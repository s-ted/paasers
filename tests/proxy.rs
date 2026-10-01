//! Integration tests for the reverse proxy (P5).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod common;
use bytes::Bytes;
use common::*;
use http_body_util::Full;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn kdl(upstreams: &[SocketAddr], extra: &str) -> String {
    let ups: String = upstreams
        .iter()
        .map(|a| format!("    upstream \"{a}\"\n"))
        .collect();
    format!("gateway {{\n listen \"127.0.0.1:0\"\n}}\nroute \"app.test\" {{\n{ups}{extra}\n}}\n")
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
}

#[tokio::test]
async fn proxies_get_and_post_body() {
    let (b, _h) = spawn_echo_backend().await;
    let g = spawn_gateway(&kdl(&[b], "")).await;
    let r = raw_request(g.http_addr(), &get("/x?y=1"))
        .await
        .to_ascii_lowercase();
    assert!(r.starts_with("http/1.1 200"), "{r}");
    assert!(r.contains("x-seen-host: app.test"), "{r}");
    assert!(r.contains("x-seen-x-forwarded-for: 127.0.0.1"), "{r}");
    assert!(r.contains("x-seen-x-forwarded-proto: http"), "{r}");
    assert!(r.contains("x-seen-via: 1.1 paasers"), "{r}");
    assert!(r.contains("x-request-id: "), "{r}");
    let payload = vec![b'a'; 1024 * 1024];
    let mut req = format!(
        "POST /up HTTP/1.1\r\nHost: app.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    req.extend_from_slice(&payload);
    let (head, body) = split_response(&raw_bytes(g.http_addr(), &req).await);
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert_eq!(body.len(), payload.len());
    g.stop().await;
}

#[tokio::test]
async fn spoofed_forwarding_headers_are_replaced() {
    let (b, _h) = spawn_echo_backend().await;
    let g = spawn_gateway(&kdl(&[b], "")).await;
    let r = raw_request(
        g.http_addr(),
        "GET / HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: 6.6.6.6\r\nX-Request-Id: evil\r\nConnection: close\r\n\r\n",
    )
    .await
    .to_ascii_lowercase();
    assert!(r.contains("x-seen-x-forwarded-for: 127.0.0.1\r\n"), "{r}");
    assert!(!r.contains("evil"), "{r}");
    g.stop().await;
}

#[tokio::test]
async fn websocket_echo() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let mut n = 0;
        loop {
            n += s.read(&mut buf[n..]).await.unwrap();
            if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            .await
            .unwrap();
        loop {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 {
                return;
            }
            s.write_all(&buf[..n]).await.unwrap();
        }
    });
    let g = spawn_gateway(&kdl(&[ws], "")).await;
    let mut c = TcpStream::connect(g.http_addr()).await.unwrap();
    c.write_all(
        b"GET /ws HTTP/1.1\r\nHost: app.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 4096];
    let mut n = 0;
    while !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
        n += c.read(&mut buf[n..]).await.unwrap();
    }
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 101"));
    c.write_all(b"hello tunnel").await.unwrap();
    let mut echo = [0u8; 12];
    tokio::time::timeout(Duration::from_secs(3), c.read_exact(&mut echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echo, b"hello tunnel");
    g.stop().await;
}

#[tokio::test]
async fn backend_down_gives_502_then_503_after_unhealthy() {
    let dead = closed_port().await;
    let g = spawn_gateway(&kdl(
        &[dead],
        "health-check enabled=#true interval=\"1s\" timeout=\"500ms\"",
    ))
    .await;
    // A POST is not retried: the connect error is reported as 502 and marks the upstream unhealthy.
    let post = "POST / HTTP/1.1\r\nHost: app.test\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx";
    let r = raw_request(g.http_addr(), post).await;
    assert!(r.starts_with("HTTP/1.1 502"), "{r}");
    let r = raw_request(g.http_addr(), &get("/")).await;
    assert!(r.starts_with("HTTP/1.1 503"), "{r}");
    g.stop().await;
}

#[tokio::test]
async fn backend_timeout_504() {
    let (b, _h) = spawn_backend(|_| async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        http::Response::new(Full::new(Bytes::from_static(b"late")))
    })
    .await;
    let g = spawn_gateway(&kdl(&[b], "timeouts request=\"500ms\"")).await;
    let started = std::time::Instant::now();
    let r = raw_request(g.http_addr(), &get("/")).await;
    assert!(r.starts_with("HTTP/1.1 504"), "{r}");
    assert!(started.elapsed() < Duration::from_millis(1800));
    g.stop().await;
}

#[tokio::test]
async fn retry_idempotent_on_connect_error() {
    let (good, _h) = spawn_echo_backend().await;
    let dead = closed_port().await;
    let g = spawn_gateway(&kdl(&[dead, good], "health-check enabled=#true interval=\"30s\"")).await;
    for _ in 0..100 {
        let r = raw_request(g.http_addr(), &get("/")).await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    }
    g.stop().await;
}

#[tokio::test]
async fn body_over_limit_413() {
    let (b, _h) = spawn_echo_backend().await;
    let src = kdl(&[b], "").replacen("gateway {", "gateway {\n limits max-body=\"2KiB\"", 1);
    let g = spawn_gateway(&src).await;
    // Chunked upload: no Content-Length, so the limit is enforced while streaming.
    let mut req =
        b"POST / HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            .to_vec();
    for _ in 0..8 {
        req.extend_from_slice(b"400\r\n");
        req.extend_from_slice(&[b'z'; 0x400]);
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"0\r\n\r\n");
    let (head, _) = split_response(&raw_bytes(g.http_addr(), &req).await);
    assert!(head.starts_with("http/1.1 413"), "{head}");
    g.stop().await;
}

#[tokio::test]
async fn health_recovery() {
    let (b, h) = spawn_echo_backend().await;
    let g = spawn_gateway(&kdl(
        &[b],
        "health-check interval=\"1s\" timeout=\"500ms\" unhealthy-after=1 healthy-after=1",
    ))
    .await;
    assert!(
        raw_request(g.http_addr(), &get("/"))
            .await
            .starts_with("HTTP/1.1 200")
    );
    h.abort();
    let _ = h.await;
    // Wait for the probe to notice that the backend is gone.
    let mut down = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if !raw_request(g.http_addr(), &get("/"))
            .await
            .starts_with("HTTP/1.1 200")
        {
            down = true;
            break;
        }
    }
    assert!(down, "upstream never left rotation");
    // Restart a backend on the same port.
    let l = loop {
        match tokio::net::TcpListener::bind(b).await {
            Ok(l) => break l,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    };
    let _h2 = serve_backend(l, |_| async {
        http::Response::new(Full::new(Bytes::from_static(b"ok")))
    });
    let mut up = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if raw_request(g.http_addr(), &get("/"))
            .await
            .starts_with("HTTP/1.1 200")
        {
            up = true;
            break;
        }
    }
    assert!(up, "upstream never came back");
    g.stop().await;
}
