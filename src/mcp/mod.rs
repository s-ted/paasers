//! MCP server (Streamable HTTP) exposing route status, flight recorder, incident lookup and cache purge.
mod auth;
mod server;
pub mod tools;

use crate::config::McpCfg;
use crate::routing::Runtime;
use crate::storage::Db;
use arc_swap::ArcSwap;
use auth::McpHttp;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;

/// What the MCP tools may read.
pub struct McpState {
    pub current: Arc<ArcSwap<Runtime>>,
    pub recorder: Arc<crate::observe::FlightRecorder>,
    pub db: Db,
    pub started_at: SystemTime,
    pub tunnels: Arc<AtomicUsize>,
}

/// Binds the listener and returns the bound address plus the serving task.
pub async fn serve(
    cfg: &McpCfg,
    state: Arc<McpState>,
    shutdown: CancellationToken,
) -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = crate::server::bind_listener(cfg.listen)?;
    let addr = listener.local_addr()?;
    let svc = McpHttp {
        service: server::service(state, cfg.token.is_some()),
        token_digest: cfg
            .token
            .as_deref()
            .map(|t| Arc::new(auth::digest(&McpHttp::expected_header(t)))),
    };
    let task = tokio::spawn(async move {
        let graceful = GracefulShutdown::new();
        loop {
            let (tcp, _) = tokio::select! {
                () = shutdown.cancelled() => break,
                r = listener.accept() => match r {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!(error = %e, "mcp accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
            };
            let mut b = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            b.http1()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(30));
            let conn = b
                .http1_only()
                .serve_connection(
                    TokioIo::new(tcp),
                    hyper_util::service::TowerToHyperService::new(svc.clone()),
                )
                .into_owned();
            let watched = graceful.watch(conn);
            tokio::spawn(async move {
                if let Err(e) = watched.await {
                    tracing::debug!(error = %e, "mcp connection closed with error");
                }
            });
        }
        if tokio::time::timeout(Duration::from_secs(5), graceful.shutdown())
            .await
            .is_err()
        {
            tracing::warn!("mcp: forced shutdown");
        }
    });
    Ok((addr, task))
}
