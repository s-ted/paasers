//! Shared helpers for integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]
use paasers::config::parse_str;
use paasers::server::{BoundAddrs, run_with};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

pub struct GatewayHandle {
    pub addrs: BoundAddrs,
    pub shutdown: CancellationToken,
    pub task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl GatewayHandle {
    pub fn http_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.addrs.http.port()))
    }

    pub async fn stop(self) {
        self.shutdown.cancel();
        let _ = self.task.await;
    }
}

/// Starts a gateway on ephemeral ports from KDL source.
pub async fn spawn_gateway(kdl: &str) -> GatewayHandle {
    let cfg = parse_str(kdl, &|_| None).unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run_with(cfg, None, tx, shutdown.clone()));
    let addrs = rx.await.unwrap();
    GatewayHandle {
        addrs,
        shutdown,
        task,
    }
}

/// Sends a raw HTTP/1.1 request and returns the full response text.
pub async fn raw_request(addr: SocketAddr, req: &str) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out).into_owned()
}

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::future::Future;

/// Starts an HTTP/1.1 backend on an ephemeral port. `handler` maps a request to a response.
pub async fn spawn_backend<F, Fut>(handler: F) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    F: Fn(http::Request<hyper::body::Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = http::Response<Full<Bytes>>> + Send + 'static,
{
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    (addr, serve_backend(l, handler))
}

pub fn serve_backend<F, Fut>(l: tokio::net::TcpListener, handler: F) -> tokio::task::JoinHandle<()>
where
    F: Fn(http::Request<hyper::body::Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = http::Response<Full<Bytes>>> + Send + 'static,
{
    tokio::spawn(async move {
        // Dropping the set (when this task is aborted) also kills open connections, like a crashed backend.
        let mut conns = tokio::task::JoinSet::new();
        loop {
            let Ok((tcp, _)) = l.accept().await else { return };
            let h = handler.clone();
            conns.spawn(async move {
                let svc = service_fn(move |r| {
                    let h = h.clone();
                    async move { Ok::<_, Infallible>(h(r).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .timer(TokioTimer::new())
                    .serve_connection(TokioIo::new(tcp), svc)
                    .with_upgrades()
                    .await;
            });
        }
    })
}

/// Backend that echoes the request body and reports a few request headers in response headers.
pub async fn spawn_echo_backend() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_backend(|req| async move {
        let mut b = http::Response::builder().status(200);
        for h in [
            "host",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-real-ip",
            "via",
            "x-request-id",
            "traceparent",
        ] {
            if let Some(v) = req.headers().get(h) {
                b = b.header(format!("x-seen-{h}"), v.clone());
            }
        }
        let body = req
            .into_body()
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        b.body(Full::new(body)).unwrap()
    })
    .await
}

/// Splits a raw HTTP response into (status line + headers lowercased, body bytes).
pub fn split_response(raw: &[u8]) -> (String, Vec<u8>) {
    let pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |p| p + 4);
    (
        String::from_utf8_lossy(&raw[..pos]).to_ascii_lowercase(),
        raw[pos..].to_vec(),
    )
}

/// Like `raw_request` but returns raw bytes and accepts a body.
pub async fn raw_bytes(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(req).await.unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    out
}

/// A TCP port that is currently closed.
pub async fn closed_port() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}
