//! Graceful shutdown helpers.
use hyper_util::server::graceful::GracefulShutdown;
use std::time::Duration;

/// Waits for in-flight connections, up to `grace`.
pub async fn drain(graceful: GracefulShutdown, grace: Duration) {
    if tokio::time::timeout(grace, graceful.shutdown()).await.is_err() {
        tracing::warn!("forced shutdown: connections still open after grace period");
    }
}

/// Cancels `token` on SIGINT or SIGTERM.
pub async fn wait_for_signal(token: tokio_util::sync::CancellationToken) {
    use tokio::signal::unix::{SignalKind, signal};
    let term = signal(SignalKind::terminate());
    let Ok(mut term) = term else {
        let _ = tokio::signal::ctrl_c().await;
        token.cancel();
        return;
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
        () = token.cancelled() => return,
    }
    tracing::info!("shutdown signal received");
    token.cancel();
}
