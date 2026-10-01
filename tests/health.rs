//! Load balancing and health over real HTTP (P12).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod common;
use bytes::Bytes;
use common::*;
use http_body_util::Full;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

#[tokio::test]
async fn weighted_90_10_over_http() {
    let hits = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
    let mut addrs = Vec::new();
    // Active probes also reach the backends: they are disabled so that only client traffic is counted.
    for h in &hits {
        let h = h.clone();
        let (a, j) = spawn_backend(move |_| {
            let h = h.clone();
            async move {
                h.fetch_add(1, SeqCst);
                http::Response::new(Full::new(Bytes::from_static(b"ok")))
            }
        })
        .await;
        std::mem::forget(j);
        addrs.push(a);
    }
    let src = format!(
        "gateway {{\n listen \"127.0.0.1:0\"\n}}\nroute \"lb.test\" {{\n upstream \"{}\" weight=90\n upstream \"{}\" weight=10\n health-check enabled=#false\n}}\n",
        addrs[0], addrs[1]
    );
    let g = spawn_gateway(&src).await;
    for _ in 0..1000 {
        let r = raw_request(
            g.http_addr(),
            "GET / HTTP/1.1\r\nHost: lb.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    }
    let (a, b) = (hits[0].load(SeqCst), hits[1].load(SeqCst));
    assert_eq!(a + b, 1000);
    let share = a as f64 / 1000.0;
    assert!(
        (0.85..=0.95).contains(&share),
        "share of the 90% upstream was {share}"
    );
    g.stop().await;
}

#[tokio::test]
async fn drained_upstream_with_weight_zero_gets_no_traffic() {
    let hits = Arc::new(AtomicUsize::new(0));
    let h2 = hits.clone();
    let (drained, j) = spawn_backend(move |_| {
        let h = h2.clone();
        async move {
            h.fetch_add(1, SeqCst);
            http::Response::new(Full::new(Bytes::from_static(b"x")))
        }
    })
    .await;
    std::mem::forget(j);
    let (live, j2) = spawn_echo_backend().await;
    std::mem::forget(j2);
    let src = format!(
        "gateway {{\n listen \"127.0.0.1:0\"\n}}\nroute \"lb.test\" {{\n upstream \"{drained}\" weight=0\n upstream \"{live}\"\n health-check enabled=#false\n}}\n"
    );
    let g = spawn_gateway(&src).await;
    for _ in 0..50 {
        assert!(
            raw_request(
                g.http_addr(),
                "GET / HTTP/1.1\r\nHost: lb.test\r\nConnection: close\r\n\r\n"
            )
            .await
            .starts_with("HTTP/1.1 200")
        );
    }
    assert_eq!(hits.load(SeqCst), 0);
    g.stop().await;
}
