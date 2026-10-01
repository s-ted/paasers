//! `run_with`: wires state, listeners, reload and shutdown together.
use super::{BoundAddrs, EntryService, Shared, http, listener, reload, shutdown, tls_accept};
use crate::config::Config;
use crate::prelude::Scheme;
use crate::routing;
use crate::storage::Db;
use crate::tls::{self, CertManager};
use arc_swap::ArcSwap;
use hyper_util::server::graceful::GracefulShutdown;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio_util::sync::CancellationToken;

pub async fn run_with(
    cfg: Config,
    cfg_path: Option<PathBuf>,
    ready: oneshot::Sender<BoundAddrs>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    run_shared(cfg, cfg_path, ready, shutdown, None).await
}

/// Same as `run_with`, additionally handing the shared state to `shared_out` (tests and MCP wiring).
pub async fn run_shared(
    cfg: Config,
    cfg_path: Option<PathBuf>,
    ready: oneshot::Sender<BoundAddrs>,
    shutdown: CancellationToken,
    shared_out: Option<oneshot::Sender<Arc<Shared>>>,
) -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cfg = Arc::new(cfg);
    let db = Db::open(&cfg.gateway.storage_path).await?;
    let shared = Arc::new(Shared::with_recorder_capacity(
        cfg.gateway.flight_recorder_capacity,
    ));
    let key: [u8; 32] = db
        .get_or_create_secret("session-hmac", 32)
        .await?
        .try_into()
        .map_err(|_| anyhow::anyhow!("stored session key has an unexpected length"))?;
    let _ = shared.gate.set(Arc::new(crate::gatekeeper::GateShared::new(
        key,
        Some(db.clone()),
    )));
    let current = Arc::new(ArcSwap::from_pointee(routing::build(&cfg, &shared)?));
    let certs = CertManager::start(
        &cfg,
        db.clone(),
        shared.certs.clone(),
        shared.challenges.clone(),
        shared.recorder.clone(),
        shutdown.clone(),
    )
    .await?;
    if let Some(out) = shared_out {
        let _ = out.send(shared.clone());
    }
    shared.health.retain(&routing::active_upstreams(&cfg));
    let conns = Arc::new(Semaphore::new(cfg.gateway.limits.max_connections));
    let graceful = Arc::new(GracefulShutdown::new());
    let limits = cfg.gateway.limits.clone();
    let mut accepts = Vec::new();

    let spawn_conn = {
        let (current, shared, graceful) = (current.clone(), shared.clone(), graceful.clone());
        let limits = limits.clone();
        move |scheme: Scheme, acceptor: Option<tokio_rustls::TlsAcceptor>| {
            let (current, shared, graceful, limits) =
                (current.clone(), shared.clone(), graceful.clone(), limits.clone());
            move |tcp: TcpStream, peer: SocketAddr, permit: OwnedSemaphorePermit| {
                let svc = EntryService {
                    peer,
                    scheme,
                    current: current.clone(),
                    shared: shared.clone(),
                };
                let (watcher, limits, acceptor) = (graceful.watcher(), limits.clone(), acceptor.clone());
                tokio::spawn(async move {
                    let (timeout, max) = (limits.header_read_timeout, limits.max_headers_size);
                    match acceptor {
                        None => http::serve_conn(tcp, svc, true, timeout, max, watcher).await,
                        Some(a) => {
                            if let Some(tls) = tls_accept::handshake(&a, tcp).await {
                                http::serve_conn(tls, svc, false, timeout, max, watcher).await;
                            }
                        }
                    }
                    drop(permit);
                });
            }
        }
    };

    let http_listener = listener::bind(cfg.gateway.listen_http)?;
    let http_addr = http_listener.local_addr()?;
    accepts.push(tokio::spawn(listener::accept_loop(
        http_listener,
        conns.clone(),
        shutdown.clone(),
        spawn_conn(Scheme("http"), None),
    )));
    let mut https_addr = None;
    if let Some(addr) = cfg.gateway.listen_https {
        let l = listener::bind(addr)?;
        let bound = l.local_addr()?;
        shared
            .https_port
            .store(bound.port(), std::sync::atomic::Ordering::Relaxed);
        https_addr = Some(bound);
        let acceptor = tls_accept::acceptor(tls::server_config(shared.certs.clone())?);
        accepts.push(tokio::spawn(listener::accept_loop(
            l,
            conns.clone(),
            shutdown.clone(),
            spawn_conn(Scheme("https"), Some(acceptor)),
        )));
    }
    if let Some(path) = cfg_path {
        tokio::spawn(reload::watch(
            path,
            current.clone(),
            shared.clone(),
            certs,
            shutdown.clone(),
        ));
    }
    tokio::spawn(maintenance(shared.clone(), shutdown.clone()));
    tokio::spawn(shutdown::wait_for_signal(shutdown.clone()));
    let mut mcp_addr = None;
    let mut mcp_task = None;
    if let Some(m) = &cfg.mcp {
        let state = Arc::new(crate::mcp::McpState {
            current: current.clone(),
            recorder: shared.recorder.clone(),
            db: db.clone(),
            started_at: shared.started_at,
            tunnels: shared.tunnels.clone(),
        });
        let (addr, task) = crate::mcp::serve(m, state, shutdown.clone()).await?;
        mcp_addr = Some(addr);
        mcp_task = Some(task);
    }
    let _ = ready.send(BoundAddrs {
        http: http_addr,
        https: https_addr,
        mcp: mcp_addr,
    });
    tracing::info!(http = %http_addr, https = ?https_addr, routes = cfg.routes.len(), "gateway started");

    shutdown.cancelled().await;
    for a in accepts.into_iter().chain(mcp_task) {
        let _ = a.await;
    }
    drop(spawn_conn);
    match Arc::try_unwrap(graceful) {
        Ok(g) => shutdown::drain(g, cfg.gateway.shutdown_grace).await,
        Err(_) => tracing::warn!("graceful handle still shared, skipping drain"),
    }
    shared.health.shutdown();
    tracing::info!("gateway stopped");
    Ok(())
}

/// Periodic memory maintenance for per-IP limiters (R9).
async fn maintenance(shared: Arc<Shared>, shutdown: CancellationToken) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            _ = tick.tick() => {}
        }
        shared.limiters.purge();
        if let Some(g) = shared.gate.get() {
            g.purge();
        }
    }
}
