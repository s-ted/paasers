//! Graceful shutdown helpers.
use hyper_util::server::graceful::GracefulShutdown;
use std::time::Duration;

/// Waits for in-flight connections, up to `grace`.
pub async fn drain(graceful: GracefulShutdown, grace: Duration) {
    if tokio::time::timeout(grace, graceful.shutdown()).await.is_err() {
        tracing::warn!("forced shutdown: connections still open after grace period");
    }
}

/// Resolves when the process is asked to terminate (SIGTERM on Unix, nothing extra elsewhere).
#[cfg(unix)]
async fn terminate() -> bool {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut s) => {
            s.recv().await;
            true
        }
        Err(_) => false,
    }
}

#[cfg(not(unix))]
async fn terminate() -> bool {
    false
}

/// Cancels `token` on Ctrl-C or SIGTERM.
pub async fn wait_for_signal(token: tokio_util::sync::CancellationToken) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        true = terminate() => {}
        () = token.cancelled() => return,
    }
    tracing::info!("shutdown signal received");
    token.cancel();
}
