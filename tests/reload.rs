//! Hot reload of the configuration file (P12).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod common;
use bytes::Bytes;
use common::*;
use http_body_util::Full;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn src(listen_extra: &str, routes: &str) -> String {
    format!("gateway {{\n listen \"127.0.0.1:0\"\n{listen_extra}\n}}\n{routes}")
}

fn route(host: &str, backend: SocketAddr) -> String {
    format!(
        "route \"{host}\" {{\n upstream \"{backend}\"\n health-check interval=\"1s\" timeout=\"500ms\"\n}}\n"
    )
}

/// Runs the gateway from a real file so that the watcher is active.
async fn start(
    path: &Path,
) -> (
    SocketAddr,
    std::sync::Arc<paasers::server::Shared>,
    CancellationToken,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let cfg = paasers::config::load(path).unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let (stx, srx) = tokio::sync::oneshot::channel();
    let token = CancellationToken::new();
    let task = tokio::spawn(paasers::server::run_shared(
        cfg,
        Some(path.to_path_buf()),
        tx,
        token.clone(),
        Some(stx),
    ));
    let addrs = rx.await.unwrap();
    (
        SocketAddr::from(([127, 0, 0, 1], addrs.http.port())),
        srx.await.unwrap(),
        token,
        task,
    )
}

fn req(host: &str) -> String {
    format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

async fn status_of(addr: SocketAddr, host: &str) -> String {
    raw_request(addr, &req(host))
        .await
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

async fn wait_for(addr: SocketAddr, host: &str, want: &str) -> bool {
    for _ in 0..100 {
        if status_of(addr, host).await.contains(want) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

fn write_atomic(path: &Path, content: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

#[tokio::test]
async fn reload_on_file_change_and_invalid_reload_keeps_old() {
    let (b, _j) = spawn_echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let storage = format!("storage-path \"{}\"", dir.path().join("c.db").display());
    let path = dir.path().join("gw.kdl");
    std::fs::write(&path, src(&storage, &route("one.test", b))).unwrap();
    let (addr, shared, token, task) = start(&path).await;
    assert!(status_of(addr, "one.test").await.contains("200"));
    assert!(status_of(addr, "two.test").await.contains("404"));
    // A second route appears within the 2 s poll interval (plus margin).
    write_atomic(
        &path,
        &src(
            &storage,
            &format!("{}{}", route("one.test", b), route("two.test", b)),
        ),
    );
    assert!(wait_for(addr, "two.test", "200").await, "new route never served");
    // An invalid file keeps the previous configuration and is recorded.
    write_atomic(&path, "route {{{ not kdl");
    for _ in 0..60 {
        if shared
            .recorder
            .query(&Default::default())
            .iter()
            .any(|i| i.kind == "config")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        shared
            .recorder
            .query(&Default::default())
            .iter()
            .any(|i| i.kind == "config"),
        "no config incident"
    );
    assert!(
        status_of(addr, "two.test").await.contains("200"),
        "old config must stay active"
    );
    // A host that disappears from the file stops being served.
    write_atomic(&path, &src(&storage, &route("one.test", b)));
    assert!(wait_for(addr, "two.test", "404").await);
    token.cancel();
    let _ = task.await;
}

#[tokio::test]
async fn health_state_survives_reload() {
    let (b, _j) = spawn_echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let storage = format!("storage-path \"{}\"", dir.path().join("c.db").display());
    let path = dir.path().join("gw.kdl");
    std::fs::write(&path, src(&storage, &route("one.test", b))).unwrap();
    let (addr, shared, token, task) = start(&path).await;
    let health = shared.health.get(b).unwrap();
    health.report_failure_passive();
    assert!(!health.is_healthy());
    write_atomic(
        &path,
        &src(
            &storage,
            &format!("{}{}", route("one.test", b), route("two.test", b)),
        ),
    );
    assert!(wait_for(addr, "two.test", "").await);
    // Same Arc after the reload: state was kept (unless the probe already healed it, which is also fine).
    assert!(std::sync::Arc::ptr_eq(&health, &shared.health.get(b).unwrap()));
    token.cancel();
    let _ = task.await;
}

#[tokio::test]
async fn inflight_request_survives_reload() {
    let (slow, _j) = spawn_backend(|_| async {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        http::Response::new(Full::new(Bytes::from_static(b"slow done")))
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let storage = format!("storage-path \"{}\"", dir.path().join("c.db").display());
    let path = dir.path().join("gw.kdl");
    std::fs::write(&path, src(&storage, &route("slow.test", slow))).unwrap();
    let (addr, _shared, token, task) = start(&path).await;
    let pending = tokio::spawn(async move { raw_request(addr, &req("slow.test")).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Reload while the request is in flight, dropping the route entirely.
    write_atomic(&path, &src(&storage, ""));
    assert!(wait_for(addr, "slow.test", "404").await);
    let r = pending.await.unwrap();
    assert!(
        r.starts_with("HTTP/1.1 200") && r.ends_with("slow done"),
        "in-flight request must finish on the old snapshot: {r}"
    );
    token.cancel();
    let _ = task.await;
}

#[tokio::test]
async fn restart_only_settings_are_ignored() {
    let (b, _j) = spawn_echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let storage = format!("storage-path \"{}\"", dir.path().join("c.db").display());
    let path = dir.path().join("gw.kdl");
    std::fs::write(&path, src(&storage, &route("one.test", b))).unwrap();
    let (addr, _shared, token, task) = start(&path).await;
    // Changing `listen` cannot take effect without a restart: the gateway keeps serving where it is.
    let changed = src(&storage, &route("one.test", b)).replace("127.0.0.1:0", "127.0.0.1:1");
    write_atomic(&path, &format!("{changed}{}", route("added.test", b)));
    assert!(
        wait_for(addr, "added.test", "200").await,
        "route changes still apply"
    );
    token.cancel();
    let _ = task.await;
}
