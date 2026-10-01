//! Bidirectional tunnel for `Upgrade` (WebSocket) connections.
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub async fn tunnel(
    client: hyper::upgrade::OnUpgrade,
    upstream: hyper::upgrade::OnUpgrade,
    active: Arc<AtomicUsize>,
) {
    let (c, u) = tokio::join!(client, upstream);
    let (Ok(c), Ok(u)) = (c, u) else {
        tracing::debug!("upgrade failed");
        return;
    };
    active.fetch_add(1, Ordering::Relaxed);
    let (mut c, mut u) = (TokioIo::new(c), TokioIo::new(u));
    if let Err(e) = tokio::io::copy_bidirectional(&mut c, &mut u).await {
        tracing::debug!(error = %e, "tunnel closed");
    }
    active.fetch_sub(1, Ordering::Relaxed);
}
