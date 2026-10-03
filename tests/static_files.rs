//! Integration tests for static file routes (P14).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod common;
use common::*;
use std::path::Path;

const HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$ftC9LdPXCcZ6MiQpvWUwXA$haZvTFqngv2fUrBLJTBmAw2Ltxdy9HonzbKTkg4bXhI";

/// Layout: <tmp>/secret.txt (outside) and <tmp>/www (the served root).
struct Site {
    _tmp: tempfile::TempDir,
    root: std::path::PathBuf,
    #[cfg_attr(not(unix), allow(dead_code))]
    outside: std::path::PathBuf,
}

fn write(p: &Path, content: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

fn site() -> Site {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("www");
    let outside = tmp.path().join("secret.txt");
    write(&outside, "TOP-SECRET");
    write(&root.join("hello.txt"), "hello world");
    write(&root.join("app.js"), "console.log(1)");
    write(&root.join("docs/index.html"), "<h1>docs index</h1>");
    write(&root.join("docs/guide.md"), "# guide");
    write(&root.join("files/b.txt"), "b");
    write(&root.join("files/A.txt"), "a");
    write(&root.join("files/.hidden"), "h");
    write(&root.join("files/<script>alert(1)<script>.txt"), "x");
    write(&root.join("files/sp ace#1.txt"), "x");
    write(&root.join(".env"), "DB_PASSWORD=1");
    write(&root.join("big.txt"), &"lorem ipsum dolor sit amet ".repeat(400));
    std::fs::create_dir_all(root.join("empty")).unwrap();
    Site {
        _tmp: tmp,
        root,
        outside,
    }
}

fn kdl(s: &Site, props: &str, extra: &str) -> String {
    format!(
        "gateway {{\n listen \"127.0.0.1:0\"\n}}\nroute \"s.test\" {{\n static \"{}\" {props}\n{extra}\n}}\n",
        kp(&s.root)
    )
}

fn req(method: &str, path: &str, headers: &str) -> String {
    format!("{method} {path} HTTP/1.1\r\nHost: s.test\r\n{headers}Connection: close\r\n\r\n")
}

async fn fetch(g: &GatewayHandle, method: &str, path: &str, headers: &str) -> (String, String) {
    let raw = raw_bytes(g.http_addr(), req(method, path, headers).as_bytes()).await;
    let (head, body) = split_response(&raw);
    (head, String::from_utf8_lossy(&body).into_owned())
}

fn status(head: &str) -> u16 {
    head.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[tokio::test]
async fn serves_file_with_headers() {
    let s = site();
    let g = spawn_gateway(&kdl(&s, "", "")).await;
    let (h, b) = fetch(&g, "GET", "/hello.txt", "").await;
    assert_eq!(status(&h), 200, "{h}");
    assert_eq!(b, "hello world");
    assert!(h.contains("content-type: text/plain"), "{h}");
    assert!(h.contains("content-length: 11"), "{h}");
    assert!(h.contains("last-modified: "), "{h}");
    assert!(h.contains("x-content-type-options: nosniff"), "{h}");
    let (h, _) = fetch(&g, "GET", "/app.js", "").await;
    assert!(h.contains("javascript"), "{h}");
    g.stop().await;
}

#[tokio::test]
async fn head_and_method_not_allowed() {
    let s = site();
    let g = spawn_gateway(&kdl(&s, "", "")).await;
    let (h, b) = fetch(&g, "HEAD", "/hello.txt", "").await;
    assert_eq!(status(&h), 200, "{h}");
    assert!(h.contains("content-length: 11") && b.is_empty(), "{h}");
    let (h, _) = fetch(&g, "POST", "/hello.txt", "Content-Length: 0\r\n").await;
    assert_eq!(status(&h), 405, "{h}");
    assert!(h.contains("allow: get, head"), "{h}");
    g.stop().await;
}

#[tokio::test]
async fn range_and_conditional_requests() {
    let s = site();
    let g = spawn_gateway(&kdl(&s, "", "")).await;
    let (h, b) = fetch(&g, "GET", "/hello.txt", "Range: bytes=0-4\r\n").await;
    assert_eq!(status(&h), 206, "{h}");
    assert!(h.contains("content-range: bytes 0-4/11"), "{h}");
    assert_eq!(b, "hello");
    let (h, _) = fetch(&g, "GET", "/hello.txt", "").await;
    let etag = h
        .lines()
        .find_map(|l| l.strip_prefix("etag: "))
        .unwrap()
        .trim()
        .to_string();
    // Header values are lowercased by `split_response`: use a fixed future date for If-Modified-Since.
    let (h, b) = fetch(
        &g,
        "GET",
        "/hello.txt",
        "If-Modified-Since: Fri, 01 Jan 2100 00:00:00 GMT\r\n",
    )
    .await;
    assert_eq!(status(&h), 304, "{h}");
    assert!(b.is_empty());
    let (h, _) = fetch(
        &g,
        "GET",
        "/hello.txt",
        "If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n",
    )
    .await;
    assert_eq!(status(&h), 200, "{h}");
    let (h, _) = fetch(&g, "GET", "/hello.txt", &format!("If-None-Match: {etag}\r\n")).await;
    assert_eq!(status(&h), 304, "{h}");
    g.stop().await;
}

#[tokio::test]
async fn directory_index_and_trailing_slash_redirect() {
    let s = site();
    let g = spawn_gateway(&kdl(&s, "", "")).await;
    let (h, b) = fetch(&g, "GET", "/docs/", "").await;
    assert_eq!(status(&h), 200, "{h}");
    assert_eq!(b, "<h1>docs index</h1>");
    let (h, _) = fetch(&g, "GET", "/docs?x=1", "").await;
    assert_eq!(status(&h), 301, "{h}");
    assert!(h.contains("location: /docs/?x=1"), "{h}");
    g.stop().await;
}

#[tokio::test]
async fn listing_is_on_by_default() {
    let s = site();
    let g = spawn_gateway(&kdl(&s, "", "")).await;
    let (h, b) = fetch(&g, "GET", "/files/", "").await;
    assert_eq!(status(&h), 200, "{h}");
    assert!(h.contains("content-type: text/html"), "{h}");
    assert!(h.contains("content-security-policy: "), "{h}");
    assert!(b.contains("A.txt") && b.contains("b.txt"), "{b}");
    assert!(
        b.find("A.txt").unwrap() < b.find("b.txt").unwrap(),
        "case-insensitive order"
    );
    assert!(!b.contains(".hidden"), "dotfiles are not listed: {b}");
    assert!(!b.contains("<script>"), "names must be escaped: {b}");
    assert!(b.contains("&lt;script&gt;"), "{b}");
    assert!(
        b.contains("sp%20ace%231.txt"),
        "href must be percent-encoded: {b}"
    );
    assert!(b.contains("../"), "parent link below the root: {b}");
    let (h, b) = fetch(&g, "GET", "/", "").await;
    assert_eq!(status(&h), 200, "{h}");
    assert!(
        b.contains("hello.txt") && b.contains("docs/") && !b.contains(".env"),
        "{b}"
    );
    assert!(!b.contains("../"), "no parent link at the root: {b}");
    let (h, b) = fetch(&g, "GET", "/empty/", "").await;
    assert_eq!(status(&h), 200, "{h}");
    assert!(b.contains("<html"), "{b}");
    let (h, b) = fetch(&g, "HEAD", "/files/", "").await;
    assert!(status(&h) == 200 && b.is_empty(), "{h}");
    g.stop().await;
}

#[tokio::test]
async fn listing_can_be_disabled() {
    let s = site();
    let g = spawn_gateway(&kdl(&s, "listing=#false", "")).await;
    let (h, _) = fetch(&g, "GET", "/files/", "").await;
    assert_eq!(status(&h), 404, "{h}");
    let (h, _) = fetch(&g, "GET", "/docs/", "").await;
    assert_eq!(status(&h), 200, "index files still work: {h}");
    let (h, _) = fetch(&g, "GET", "/files/b.txt", "").await;
    assert_eq!(status(&h), 200, "{h}");
    g.stop().await;
}

#[tokio::test]
async fn path_traversal_never_leaks() {
    let s = site();
    let g = spawn_gateway(&kdl(&s, "", "")).await;
    for p in [
        "/../secret.txt",
        "/%2e%2e/secret.txt",
        "/%2E%2E/secret.txt",
        "/docs/../../secret.txt",
        "/docs/..%2f..%2fsecret.txt",
        "/docs/%2e%2e/%2e%2e/secret.txt",
        "/..%5csecret.txt",
        "//../secret.txt",
        "/hello.txt%00.png",
    ] {
        let (h, b) = fetch(&g, "GET", p, "").await;
        assert!(!b.contains("TOP-SECRET"), "{p} leaked: {h}");
        assert!(matches!(status(&h), 400 | 404), "{p}: {h}");
    }
    g.stop().await;
}

#[tokio::test]
async fn dotfiles_are_hidden_unless_enabled() {
    let s = site();
    let g = spawn_gateway(&kdl(&s, "", "")).await;
    let (h, b) = fetch(&g, "GET", "/.env", "").await;
    assert_eq!(status(&h), 404, "{h}");
    assert!(!b.contains("DB_PASSWORD"));
    let (h, _) = fetch(&g, "GET", "/files/.hidden", "").await;
    assert_eq!(status(&h), 404, "{h}");
    g.stop().await;
    let g = spawn_gateway(&kdl(&s, "hidden=#true", "")).await;
    let (h, b) = fetch(&g, "GET", "/.env", "").await;
    assert_eq!(status(&h), 200, "{h}");
    assert_eq!(b, "DB_PASSWORD=1");
    let (_, b) = fetch(&g, "GET", "/files/", "").await;
    assert!(b.contains(".hidden"), "{b}");
    g.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn symlinks_are_not_followed_unless_enabled() {
    let s = site();
    std::os::unix::fs::symlink(&s.outside, s.root.join("link.txt")).unwrap();
    std::os::unix::fs::symlink(s.outside.parent().unwrap(), s.root.join("linkdir")).unwrap();
    let g = spawn_gateway(&kdl(&s, "", "")).await;
    for p in ["/link.txt", "/linkdir/secret.txt"] {
        let (h, b) = fetch(&g, "GET", p, "").await;
        assert_eq!(status(&h), 404, "{p}: {h}");
        assert!(!b.contains("TOP-SECRET"));
    }
    let (_, b) = fetch(&g, "GET", "/", "").await;
    assert!(!b.contains("link.txt") && !b.contains("linkdir"), "{b}");
    g.stop().await;
    let g = spawn_gateway(&kdl(&s, "follow-symlinks=#true", "")).await;
    let (h, b) = fetch(&g, "GET", "/link.txt", "").await;
    assert_eq!(status(&h), 200, "{h}");
    assert_eq!(b, "TOP-SECRET");
    g.stop().await;
}

#[tokio::test]
async fn spa_mode_falls_back_to_index() {
    let s = site();
    write(&s.root.join("index.html"), "<app/>");
    let g = spawn_gateway(&kdl(&s, "spa=#true", "")).await;
    let (h, b) = fetch(&g, "GET", "/some/client/route", "").await;
    assert_eq!(status(&h), 200, "{h}");
    assert_eq!(b, "<app/>");
    let (h, _) = fetch(&g, "GET", "/missing.js", "").await;
    assert_eq!(status(&h), 404, "{h}");
    let (_, b) = fetch(&g, "GET", "/hello.txt", "").await;
    assert_eq!(b, "hello world", "existing files win");
    g.stop().await;
    let g = spawn_gateway(&kdl(&s, "", "")).await;
    let (h, _) = fetch(&g, "GET", "/some/client/route", "").await;
    assert_eq!(status(&h), 404, "{h}");
    g.stop().await;
}

#[tokio::test]
async fn custom_index_and_cache_control() {
    let s = site();
    write(&s.root.join("docs/home.htm"), "custom");
    let g = spawn_gateway(&kdl(
        &s,
        "index=\"home.htm\" cache-control=\"public, max-age=60\"",
        "",
    ))
    .await;
    let (h, b) = fetch(&g, "GET", "/docs/", "").await;
    assert_eq!(b, "custom", "{h}");
    assert!(h.contains("cache-control: public, max-age=60"), "{h}");
    g.stop().await;
    let g = spawn_gateway(&kdl(&s, "index=\"\"", "")).await;
    let (_, b) = fetch(&g, "GET", "/docs/", "").await;
    assert!(b.contains("guide.md"), "no index file: listing: {b}");
    g.stop().await;
}

#[tokio::test]
async fn missing_and_unusual_paths() {
    let s = site();
    let g = spawn_gateway(&kdl(&s, "", "")).await;
    let (h, _) = fetch(&g, "GET", "/nope.txt", "").await;
    assert_eq!(status(&h), 404, "{h}");
    let (h, b) = fetch(&g, "GET", "/hello.txt/", "").await;
    assert_eq!(status(&h), 404, "{h}");
    assert!(!b.contains("hello world"));
    let (h, b) = fetch(&g, "GET", "//hello.txt", "").await;
    assert!(status(&h) == 200 || status(&h) == 404, "{h}");
    let _ = b;
    g.stop().await;
}

#[tokio::test]
async fn other_layers_still_apply() {
    let s = site();
    let g = spawn_gateway(&kdl(&s, "", " rate-limit rps=1 burst=2")).await;
    for _ in 0..2 {
        let (h, _) = fetch(&g, "GET", "/hello.txt", "").await;
        assert_eq!(status(&h), 200, "{h}");
    }
    let (h, _) = fetch(&g, "GET", "/hello.txt", "").await;
    assert_eq!(status(&h), 429, "{h}");
    g.stop().await;

    let extra = format!(" gatekeeper {{\n  psk \"{HASH}\"\n }}");
    let g = spawn_gateway(&kdl(&s, "", &extra)).await;
    let (h, b) = fetch(&g, "GET", "/hello.txt", "Accept: text/html\r\n").await;
    assert_ne!(status(&h), 200, "{h}");
    assert!(!b.contains("hello world"), "{b}");
    g.stop().await;
}

#[tokio::test]
async fn compression_applies_to_static_responses() {
    let s = site();
    let g = spawn_gateway(&kdl(&s, "", "")).await;
    let (h, b) = fetch(&g, "GET", "/big.txt", "Accept-Encoding: gzip\r\n").await;
    assert_eq!(status(&h), 200, "{h}");
    assert!(h.contains("content-encoding: gzip"), "{h}");
    assert!(b.len() < 400 * 27, "compressed body expected");
    g.stop().await;
}

#[tokio::test]
async fn coexists_with_proxy_routes() {
    let s = site();
    let (backend, _h) = spawn_echo_backend().await;
    let src = format!(
        "gateway {{\n listen \"127.0.0.1:0\"\n}}\nroute \"s.test\" {{\n static \"{}\"\n}}\nroute \"app.test\" {{\n upstream \"{backend}\"\n}}\n",
        kp(&s.root)
    );
    let g = spawn_gateway(&src).await;
    let (h, b) = fetch(&g, "GET", "/hello.txt", "").await;
    assert!(status(&h) == 200 && b == "hello world", "{h}");
    let r = raw_request(
        g.http_addr(),
        "GET / HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    g.stop().await;
}

#[tokio::test]
async fn route_without_backend_serves_current_directory() {
    // The test process runs in the package root: Cargo.toml is served, .git is hidden.
    let g = spawn_gateway("gateway {\n listen \"127.0.0.1:0\"\n}\nroute \"d.test\" {}\n").await;
    let raw = raw_bytes(
        g.http_addr(),
        b"GET /Cargo.toml HTTP/1.1\r\nHost: d.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    let (h, b) = split_response(&raw);
    assert_eq!(status(&h), 200, "{h}");
    assert!(String::from_utf8_lossy(&b).contains("[package]"));
    g.stop().await;
}

#[tokio::test]
async fn empty_configuration_serves_current_directory_on_any_host() {
    let g = spawn_gateway("gateway {\n listen \"127.0.0.1:0\"\n}\n").await;
    for host in ["anything.test", "127.0.0.1"] {
        let raw = raw_bytes(
            g.http_addr(),
            format!("GET /Cargo.toml HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await;
        let (h, b) = split_response(&raw);
        assert_eq!(status(&h), 200, "{host}: {h}");
        assert!(String::from_utf8_lossy(&b).contains("[package]"));
    }
    let raw = raw_bytes(
        g.http_addr(),
        b"GET /.git/config HTTP/1.1\r\nHost: x.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status(&split_response(&raw).0), 404);
    g.stop().await;
}

#[tokio::test]
async fn configured_routes_disable_the_implicit_default() {
    let s = site();
    let g = spawn_gateway(&kdl(&s, "", "")).await;
    let raw = raw_bytes(
        g.http_addr(),
        b"GET /Cargo.toml HTTP/1.1\r\nHost: other.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        status(&split_response(&raw).0),
        404,
        "unknown hosts must not fall back"
    );
    g.stop().await;
}
