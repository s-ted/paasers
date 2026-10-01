//! Per-connection hyper service setup.
use crate::prelude::Resp;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::graceful::Watcher;
use std::convert::Infallible;
use std::time::Duration;

pub async fn serve_conn<I, S>(
    io: I,
    svc: S,
    http1_only: bool,
    header_read_timeout: Duration,
    max_headers: u64,
    watcher: Watcher,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: tower::Service<http::Request<hyper::body::Incoming>, Response = Resp, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    let mut b = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    b.http1()
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout)
        .keep_alive(true)
        .max_buf_size(usize::try_from(max_headers).unwrap_or(65_536).max(8192));
    b.http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(250)
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(20))
        .max_header_list_size(u32::try_from(max_headers).unwrap_or(65_536));
    let b = if http1_only { b.http1_only() } else { b };
    let conn = b
        .serve_connection_with_upgrades(
            TokioIo::new(io),
            hyper_util::service::TowerToHyperService::new(svc),
        )
        .into_owned();
    if let Err(e) = watcher.watch(conn).await {
        tracing::debug!(error = %e, "connection closed with error");
    }
}
