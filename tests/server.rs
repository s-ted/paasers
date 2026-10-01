//! Integration tests for the server core (P2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod common;
use common::{raw_request, spawn_gateway};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const BASIC: &str = r#"
gateway {
    listen "127.0.0.1:0"
}
route "a.example.com" {
    upstream "10.0.0.1:80"
}
route "secure.example.com" {
    tls email="a@b.c"
    upstream "10.0.0.1:80"
}
"#;

fn basic() -> String {
    BASIC.replace(
        "listen \"127.0.0.1:0\"",
        "listen \"127.0.0.1:0\" \"127.0.0.1:8443\"",
    )
}

#[tokio::test]
async fn unknown_host_404_has_request_id() {
    let g = spawn_gateway(&basic()).await;
    let r = raw_request(
        g.http_addr(),
        "GET / HTTP/1.1\r\nHost: nope.example.com\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 404"), "{r}");
    let lower = r.to_ascii_lowercase();
    assert!(lower.contains("x-request-id: "), "{r}");
    assert!(lower.contains("traceparent: 00-"), "{r}");
    assert!(lower.contains("content-type: application/json"), "{r}");
    assert!(r.contains("\"incident_id\""), "{r}");
    g.stop().await;
}

#[tokio::test]
async fn missing_host_is_400() {
    let g = spawn_gateway(&basic()).await;
    let r = raw_request(g.http_addr(), "GET / HTTP/1.0\r\n\r\n").await;
    assert!(
        r.starts_with("HTTP/1.0 400") || r.starts_with("HTTP/1.1 400"),
        "{r}"
    );
    g.stop().await;
}

#[tokio::test]
async fn tls_route_redirects_to_https() {
    let g = spawn_gateway(&basic()).await;
    let r = raw_request(
        g.http_addr(),
        "GET /p?q=1 HTTP/1.1\r\nHost: secure.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 301"), "{r}");
    assert!(
        r.to_ascii_lowercase()
            .contains("location: https://secure.example.com:8443/p?q=1"),
        "{r}"
    );
    assert!(r.contains("/p?q=1"), "{r}");
    g.stop().await;
}

#[tokio::test]
async fn loop_detected_via_header() {
    let g = spawn_gateway(&basic()).await;
    let r = raw_request(
        g.http_addr(),
        "GET / HTTP/1.1\r\nHost: a.example.com\r\nVia: 1.1 paasers\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 508"), "{r}");
    g.stop().await;
}

#[tokio::test]
async fn oversized_content_length_is_413() {
    let src = basic().replacen("gateway {", "gateway {\n limits max-body=\"1KiB\"", 1);
    let g = spawn_gateway(&src).await;
    let r = raw_request(
        g.http_addr(),
        "POST / HTTP/1.1\r\nHost: a.example.com\r\nContent-Length: 999999\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 413"), "{r}");
    g.stop().await;
}

#[tokio::test]
async fn max_connections_enforced() {
    let src = basic().replacen("gateway {", "gateway {\n limits max-connections=2", 1);
    let g = spawn_gateway(&src).await;
    let (a, b) = (g.http_addr(), g.http_addr());
    let mut c1 = TcpStream::connect(a).await.unwrap();
    let mut c2 = TcpStream::connect(b).await.unwrap();
    // Make sure both slots are really held by exchanging a request on each.
    for c in [&mut c1, &mut c2] {
        c.write_all(b"GET / HTTP/1.1\r\nHost: nope.example.com\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        c.read_exact(&mut buf).await.unwrap();
    }
    let mut c3 = TcpStream::connect(a).await.unwrap();
    let _ = c3
        .write_all(b"GET / HTTP/1.1\r\nHost: nope.example.com\r\n\r\n")
        .await;
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(2), c3.read(&mut buf)).await;
    assert!(
        matches!(n, Ok(Ok(0)) | Ok(Err(_))),
        "third connection should be closed: {n:?}"
    );
    drop((c1, c2));
    g.stop().await;
}

#[tokio::test]
async fn graceful_shutdown_completes_cleanly() {
    let g = spawn_gateway(&basic()).await;
    let mut c = TcpStream::connect(g.http_addr()).await.unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: nope.example.com\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 12];
    c.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"HTTP/1.1 404");
    g.shutdown.cancel();
    let res = tokio::time::timeout(Duration::from_secs(5), g.task).await;
    assert!(matches!(res, Ok(Ok(Ok(())))), "{res:?}");
}
