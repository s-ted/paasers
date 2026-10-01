//! Server orchestration: listeners, entry service, reload and graceful shutdown.
mod entry;
mod http;
mod listener;
mod reload;
mod shutdown;

pub use entry::EntryService;

use crate::config::Config;
use crate::prelude::Scheme;
use crate::routing;
use arc_swap::ArcSwap;
use hyper_util::server::graceful::GracefulShutdown;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::sync::{Semaphore, oneshot};
use tokio_util::sync::CancellationToken;

/// Long-lived state that survives reloads (extended by later phases).
pub struct Shared {
    pub generation: AtomicU64,
    pub started_at: std::time::SystemTime,
}

impl Shared {
    pub fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            started_at: std::time::SystemTime::now(),
        }
    }
}

impl Default for Shared {
    fn default() -> Self {
        Self::new()
    }
}

/// Addresses actually bound (port 0 resolves to the real port).
#[derive(Debug, Clone)]
pub struct BoundAddrs {
    pub http: SocketAddr,
    pub https: Option<SocketAddr>,
    pub mcp: Option<SocketAddr>,
}

pub async fn run_with(
    cfg: Config,
    cfg_path: Option<PathBuf>,
    ready: oneshot::Sender<BoundAddrs>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cfg = Arc::new(cfg);
    let shared = Arc::new(Shared::new());
    let current = Arc::new(ArcSwap::from_pointee(routing::build(&cfg, &shared)?));
    let conns = Arc::new(Semaphore::new(cfg.gateway.limits.max_connections));
    let graceful = Arc::new(GracefulShutdown::new());
    let limits = cfg.gateway.limits.clone();

    let http_listener = listener::bind(cfg.gateway.listen_http)?;
    let http_addr = http_listener.local_addr()?;
    let make_conn = {
        let (current, shared, graceful) = (current.clone(), shared.clone(), graceful.clone());
        move |tcp: tokio::net::TcpStream, peer: SocketAddr, permit: tokio::sync::OwnedSemaphorePermit| {
            let svc = EntryService {
                peer,
                scheme: Scheme("http"),
                current: current.clone(),
                shared: shared.clone(),
            };
            let (watcher, limits) = (graceful.watcher(), limits.clone());
            tokio::spawn(async move {
                http::serve_conn(
                    tcp,
                    svc,
                    true,
                    limits.header_read_timeout,
                    limits.max_headers_size,
                    watcher,
                )
                .await;
                drop(permit);
            });
        }
    };
    let accept = tokio::spawn(listener::accept_loop(
        http_listener,
        conns,
        shutdown.clone(),
        make_conn,
    ));
    if let Some(path) = cfg_path {
        tokio::spawn(reload::watch(
            path,
            current.clone(),
            shared.clone(),
            shutdown.clone(),
        ));
    }
    tokio::spawn(shutdown::wait_for_signal(shutdown.clone()));
    let _ = ready.send(BoundAddrs {
        http: http_addr,
        https: None,
        mcp: None,
    });
    tracing::info!(http = %http_addr, routes = cfg.routes.len(), "gateway started");

    shutdown.cancelled().await;
    let _ = accept.await;
    match Arc::try_unwrap(graceful) {
        Ok(g) => shutdown::drain(g, cfg.gateway.shutdown_grace).await,
        Err(_) => tracing::warn!("graceful handle still shared, skipping drain"),
    }
    tracing::info!("gateway stopped");
    Ok(())
}
