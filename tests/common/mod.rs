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
