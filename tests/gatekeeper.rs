//! Full gatekeeper flow over real HTTP (P9).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod common;
use common::*;

const HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$ftC9LdPXCcZ6MiQpvWUwXA$haZvTFqngv2fUrBLJTBmAw2Ltxdy9HonzbKTkg4bXhI";
const TOTP_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn kdl(backend: std::net::SocketAddr, extra: &str) -> String {
    format!(
        "gateway {{\n listen \"127.0.0.1:0\"\n}}\nroute \"dev.test\" {{\n upstream \"{backend}\"\n gatekeeper {{\n  title \"Preview\"\n  psk \"{HASH}\"\n  totp-secret \"{TOTP_B32}\"\n  rate-limit attempts=5 window=\"15m\"\n {extra}\n }}\n}}\n"
    )
}

fn totp_now() -> String {
    let secret = totp_rs::Secret::try_from_base32(TOTP_B32).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    totp_rs::Builder::new()
        .with_secret(secret)
        .build()
        .unwrap()
        .generate(now)
        .to_string()
}

fn post_login(body: &str) -> String {
    format!(
        "POST /__gate/login HTTP/1.1\r\nHost: dev.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn header_value(resp: &str, name: &str) -> Option<String> {
    resp.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

#[tokio::test]
async fn full_psk_totp_flow() {
    let (backend, _h) = spawn_echo_backend_with_cookie().await;
    let g = spawn_gateway(&kdl(backend, "")).await;
    // 1. Anonymous HTML request is redirected to the login page.
    let r = raw_request(
        g.http_addr(),
        "GET /private?a=1 HTTP/1.1\r\nHost: dev.test\r\nAccept: text/html\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 303"), "{r}");
    assert_eq!(
        header_value(&r, "location").unwrap(),
        "/__gate/login?next=%2Fprivate%3Fa%3D1"
    );
    // The login page itself is served by the gateway.
    let page = raw_request(
        g.http_addr(),
        "GET /__gate/login HTTP/1.1\r\nHost: dev.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        page.starts_with("HTTP/1.1 200") && page.contains("Preview") && page.contains("name=\"totp\""),
        "{page}"
    );
    // 2. Wrong password, then right credentials.
    let bad = raw_request(g.http_addr(), &post_login("password=wrong&totp=000000")).await;
    assert!(
        bad.starts_with("HTTP/1.1 401") && bad.contains("Invalid credentials."),
        "{bad}"
    );
    let ok = raw_request(
        g.http_addr(),
        &post_login(&format!("password=preview&totp={}&next=%2Fprivate", totp_now())),
    )
    .await;
    assert!(ok.starts_with("HTTP/1.1 303"), "{ok}");
    assert_eq!(header_value(&ok, "location").unwrap(), "/private");
    let set_cookie = header_value(&ok, "set-cookie").unwrap();
    let cookie = set_cookie.split(';').next().unwrap().to_string();
    // 3. With the cookie, the backend answers and never sees the gate cookie.
    let r = raw_request(
        g.http_addr(),
        &format!("GET /private HTTP/1.1\r\nHost: dev.test\r\nCookie: theme=dark; {cookie}; lang=fr\r\nConnection: close\r\n\r\n"),
    )
    .await
    .to_ascii_lowercase();
    assert!(r.starts_with("http/1.1 200"), "{r}");
    assert!(r.contains("x-seen-cookie: theme=dark; lang=fr"), "{r}");
    assert!(!r.contains("gate="), "{r}");
    // 4. A tampered cookie is refused.
    let tampered = format!("{}x", cookie);
    let r = raw_request(
        g.http_addr(),
        &format!(
            "GET /private HTTP/1.1\r\nHost: dev.test\r\nCookie: {tampered}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 401"), "{r}");
    g.stop().await;
}

#[tokio::test]
async fn six_wrong_attempts_give_429() {
    let (backend, _h) = spawn_echo_backend_with_cookie().await;
    let g = spawn_gateway(&kdl(backend, "")).await;
    for i in 0..5 {
        let r = raw_request(g.http_addr(), &post_login("password=bad&totp=000000")).await;
        assert!(r.starts_with("HTTP/1.1 401"), "attempt {i}: {r}");
    }
    let r = raw_request(
        g.http_addr(),
        &post_login(&format!("password=preview&totp={}", totp_now())),
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 429"), "{r}");
    assert!(header_value(&r, "retry-after").unwrap().parse::<u64>().unwrap() > 0);
    // The flight recorder knows about it.
    assert!(
        g.shared
            .recorder
            .query(&Default::default())
            .iter()
            .any(|i| i.kind == "rate_limited")
    );
    g.stop().await;
}

#[tokio::test]
async fn session_key_survives_restart_and_psk_change_invalidates() {
    let (backend, _h) = spawn_echo_backend_with_cookie().await;
    let dir = tempfile::tempdir().unwrap();
    let storage = format!("storage-path \"{}\"", dir.path().join("c.db").display());
    let src = |hash: &str| {
        kdl(backend, "")
            .replacen(
                "listen \"127.0.0.1:0\"",
                &format!("listen \"127.0.0.1:0\"\n {storage}"),
                1,
            )
            .replace(HASH, hash)
    };
    let g = spawn_gateway(&src(HASH)).await;
    let ok = raw_request(
        g.http_addr(),
        &post_login(&format!("password=preview&totp={}", totp_now())),
    )
    .await;
    let cookie = header_value(&ok, "set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    g.stop().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let ask =
        |c: &str| format!("GET / HTTP/1.1\r\nHost: dev.test\r\nCookie: {c}\r\nConnection: close\r\n\r\n");
    let g2 = spawn_gateway(&src(HASH)).await;
    assert!(
        raw_request(g2.http_addr(), &ask(&cookie))
            .await
            .starts_with("HTTP/1.1 200"),
        "cookie must survive a restart"
    );
    g2.stop().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    // Same key, different PSK hash (a different, well formed PHC hash): every session is invalid.
    let other =
        "$argon2id$v=19$m=19456,t=2,p=1$gzjx1YF59cs1qjbiftw5DQ$9LjyGz2RGu4QVh15ofiOONIbMzo70WfTAXhILFz1a20";
    let g3 = spawn_gateway(&src(other)).await;
    assert!(
        raw_request(g3.http_addr(), &ask(&cookie))
            .await
            .starts_with("HTTP/1.1 401")
    );
    g3.stop().await;
}
