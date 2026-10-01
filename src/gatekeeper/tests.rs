//! Gatekeeper layer tests with a fake backend.
use super::session::{fingerprint, issue};
use super::{GateShared, GatekeeperLayer};
use crate::config::GatekeeperCfg;
use crate::prelude::{ClientIp, IncidentKind, Req, Resp, RouteSvc, Scheme, empty};
use crate::storage::now_unix;
use http::{HeaderValue, Method, StatusCode, header};
use http_body_util::BodyExt;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::{Layer, Service};

const HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$ftC9LdPXCcZ6MiQpvWUwXA$haZvTFqngv2fUrBLJTBmAw2Ltxdy9HonzbKTkg4bXhI";
const KEY: [u8; 32] = [9; 32];

fn cfg() -> GatekeeperCfg {
    GatekeeperCfg {
        title: "Preview".into(),
        psk_hash: HASH.into(),
        totp_secret: None,
        session_duration: Duration::from_secs(3600),
        attempts: 5,
        window: Duration::from_secs(900),
        passkey: false,
        cookie_name: "gate".into(),
    }
}

struct Rig {
    svc: super::layer::Gatekeeper,
    calls: Arc<AtomicUsize>,
    seen_cookie: Arc<Mutex<Option<String>>>,
}

fn rig(cfg: &GatekeeperCfg) -> Rig {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen: Arc<Mutex<Option<String>>> = Arc::default();
    let (c, s) = (calls.clone(), seen.clone());
    let inner = RouteSvc::new(tower::service_fn(move |r: Req| {
        c.fetch_add(1, SeqCst);
        *s.lock().unwrap() = r
            .headers()
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        async { Ok::<_, Infallible>(http::Response::new(crate::prelude::full("backend"))) }
    }));
    let shared = Arc::new(GateShared::new(KEY, None));
    let route: Arc<str> = Arc::from("a.test");
    let layer = GatekeeperLayer::new(&route, &["a.test".to_string()], cfg, false, None, &shared).unwrap();
    Rig {
        svc: layer.layer(inner),
        calls,
        seen_cookie: seen,
    }
}

fn req(method: Method, path: &str) -> Req {
    let mut r = http::Request::new(empty());
    *r.method_mut() = method;
    *r.uri_mut() = path.parse().unwrap();
    r.headers_mut()
        .insert(header::HOST, HeaderValue::from_static("a.test"));
    r.extensions_mut().insert(ClientIp("1.2.3.4".parse().unwrap()));
    r.extensions_mut().insert(Scheme("http"));
    r
}

fn form(path: &str, body: &str) -> Req {
    let mut r = http::Request::new(crate::prelude::full(body.to_string()));
    *r.method_mut() = Method::POST;
    *r.uri_mut() = path.parse().unwrap();
    r.headers_mut()
        .insert(header::HOST, HeaderValue::from_static("a.test"));
    r.extensions_mut().insert(ClientIp("1.2.3.4".parse().unwrap()));
    r.extensions_mut().insert(Scheme("http"));
    r
}

fn cookie_for(cfg: &GatekeeperCfg, exp: i64) -> String {
    let fp = fingerprint(&cfg.psk_hash, cfg.totp_secret.as_deref());
    format!("gate={}", issue(&KEY, "a.test", &fp, 'p', exp))
}

async fn run(svc: &mut super::layer::Gatekeeper, r: Req) -> (Resp, String) {
    let mut resp = svc.call(r).await.unwrap();
    let b = std::mem::replace(resp.body_mut(), empty())
        .collect()
        .await
        .unwrap()
        .to_bytes();
    (resp, String::from_utf8_lossy(&b).into_owned())
}

#[tokio::test]
async fn redirects_html_to_login_with_next() {
    let mut r = rig(&cfg());
    let mut q = req(Method::GET, "/app?x=1");
    q.headers_mut()
        .insert(header::ACCEPT, HeaderValue::from_static("text/html,*/*"));
    let (resp, _) = run(&mut r.svc, q).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers()[header::LOCATION],
        "/__gate/login?next=%2Fapp%3Fx%3D1"
    );
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(r.calls.load(SeqCst), 0);
}

#[tokio::test]
async fn json_gets_401() {
    let mut r = rig(&cfg());
    let (resp, body) = run(&mut r.svc, req(Method::GET, "/api")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(body.contains("gatekeeper_login_required"));
    assert_eq!(resp.extensions().get::<IncidentKind>().unwrap().0, "auth");
    let mut post = req(Method::POST, "/api");
    post.headers_mut()
        .insert(header::ACCEPT, HeaderValue::from_static("text/html"));
    assert_eq!(
        run(&mut r.svc, post).await.0.status(),
        StatusCode::UNAUTHORIZED,
        "only GET/HEAD get a redirect"
    );
}

#[tokio::test]
async fn valid_cookie_forwards_and_strips_cookie() {
    let c = cfg();
    let mut r = rig(&c);
    let mut q = req(Method::GET, "/app");
    q.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("a=1; {}; b=2", cookie_for(&c, now_unix() + 100))).unwrap(),
    );
    let (resp, body) = run(&mut r.svc, q).await;
    assert_eq!((resp.status(), body.as_str()), (StatusCode::OK, "backend"));
    assert_eq!(r.seen_cookie.lock().unwrap().as_deref(), Some("a=1; b=2"));
}

#[tokio::test]
async fn expired_or_forged_cookie_is_refused() {
    let c = cfg();
    let mut r = rig(&c);
    for ck in [
        cookie_for(&c, now_unix() - 5),
        "gate=v1.9999999999.p.AAAA".to_string(),
        "gate=garbage".to_string(),
    ] {
        let mut q = req(Method::GET, "/app");
        q.headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(&ck).unwrap());
        assert_eq!(
            run(&mut r.svc, q).await.0.status(),
            StatusCode::UNAUTHORIZED,
            "{ck}"
        );
    }
    assert_eq!(r.calls.load(SeqCst), 0);
}

#[tokio::test]
async fn login_success_sets_cookie_and_redirects() {
    let mut r = rig(&cfg());
    let (resp, _) = run(
        &mut r.svc,
        form("/__gate/login", "password=preview&next=%2Fdash%3Fa%3D1"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers()[header::LOCATION], "/dash?a=1");
    let sc = resp.headers()[header::SET_COOKIE].to_str().unwrap().to_string();
    assert!(
        sc.starts_with("gate=v1.")
            && sc.contains("HttpOnly")
            && sc.contains("SameSite=Lax")
            && sc.contains("Max-Age=3600")
    );
    assert!(!sc.contains("Secure"));
    // The issued cookie opens the gate.
    let mut q = req(Method::GET, "/dash");
    let value = sc.split(';').next().unwrap();
    q.headers_mut()
        .insert(header::COOKIE, HeaderValue::from_str(value).unwrap());
    assert_eq!(run(&mut r.svc, q).await.0.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_failure_401_same_message() {
    let mut c = cfg();
    c.totp_secret = Some(b"12345678901234567890".to_vec());
    let mut r = rig(&c);
    let (bad_pw, b1) = run(&mut r.svc, form("/__gate/login", "password=nope&totp=123456")).await;
    let (bad_otp, b2) = run(&mut r.svc, form("/__gate/login", "password=preview&totp=000000")).await;
    assert_eq!(
        (bad_pw.status(), bad_otp.status()),
        (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED)
    );
    assert!(b1.contains("Invalid credentials.") && b2.contains("Invalid credentials."));
    assert!(!bad_pw.headers().contains_key(header::SET_COOKIE));
    assert_eq!(bad_pw.extensions().get::<IncidentKind>().unwrap().0, "auth");
}

#[tokio::test]
async fn too_many_attempts_gives_429_with_retry_after() {
    let mut r = rig(&cfg());
    for _ in 0..5 {
        assert_eq!(
            run(&mut r.svc, form("/__gate/login", "password=x"))
                .await
                .0
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let (resp, body) = run(&mut r.svc, form("/__gate/login", "password=preview")).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().contains_key(header::RETRY_AFTER) && body.contains("Too many attempts"));
    assert_eq!(resp.extensions().get::<IncidentKind>().unwrap().0, "rate_limited");
}

#[tokio::test]
async fn totp_login_requires_valid_code_once() {
    let mut c = cfg();
    c.totp_secret = Some(b"12345678901234567890".to_vec());
    let mut r = rig(&c);
    let now = now_unix().unsigned_abs();
    let code = totp_rs::Builder::new()
        .with_secret(b"12345678901234567890".to_vec())
        .build()
        .unwrap()
        .generate(now)
        .to_string();
    let body = format!("password=preview&totp={code}");
    assert_eq!(
        run(&mut r.svc, form("/__gate/login", &body)).await.0.status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        run(&mut r.svc, form("/__gate/login", &body)).await.0.status(),
        StatusCode::UNAUTHORIZED,
        "replay"
    );
    assert_eq!(
        run(&mut r.svc, form("/__gate/login", "password=preview"))
            .await
            .0
            .status(),
        StatusCode::UNAUTHORIZED,
        "missing code"
    );
}

#[tokio::test]
async fn origin_mismatch_403() {
    let mut r = rig(&cfg());
    let mut f = form("/__gate/login", "password=preview");
    f.headers_mut()
        .insert(header::ORIGIN, HeaderValue::from_static("http://evil.test"));
    assert_eq!(run(&mut r.svc, f).await.0.status(), StatusCode::FORBIDDEN);
    let mut ok = form("/__gate/login", "password=preview");
    ok.headers_mut()
        .insert(header::ORIGIN, HeaderValue::from_static("http://a.test"));
    assert_eq!(run(&mut r.svc, ok).await.0.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn open_redirect_is_neutralized() {
    let mut r = rig(&cfg());
    let (resp, _) = run(
        &mut r.svc,
        form("/__gate/login", "password=preview&next=%2F%2Fevil.com"),
    )
    .await;
    assert_eq!(resp.headers()[header::LOCATION], "/");
}

#[tokio::test]
async fn gate_paths_never_forwarded() {
    let c = cfg();
    let mut r = rig(&c);
    let authed = |p: &str, m: Method| {
        let mut q = req(m, p);
        q.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&cookie_for(&c, now_unix() + 100)).unwrap(),
        );
        q
    };
    for (p, m) in [
        ("/__gate/login", Method::GET),
        ("/__gate/unknown", Method::GET),
        ("/__gate/passkey", Method::GET),
        ("/__gate/x/y", Method::POST),
    ] {
        let (resp, _) = run(&mut r.svc, authed(p, m)).await;
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::NOT_FOUND,
            "{p}"
        );
    }
    assert_eq!(r.calls.load(SeqCst), 0);
}

#[tokio::test]
async fn logout_clears_cookie() {
    let mut r = rig(&cfg());
    let (resp, _) = run(&mut r.svc, form("/__gate/logout", "")).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers()[header::LOCATION], "/__gate/login");
    assert!(
        resp.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
}

#[tokio::test]
async fn secure_flag_follows_tls() {
    let shared = Arc::new(GateShared::new(KEY, None));
    let route: Arc<str> = Arc::from("a.test");
    let mut c = cfg();
    c.cookie_name = "__Host-gate".into();
    let inner = RouteSvc::new(tower::service_fn(|_r: Req| async {
        Ok::<_, Infallible>(http::Response::new(empty()))
    }));
    let layer = GatekeeperLayer::new(&route, &["a.test".to_string()], &c, true, Some(443), &shared).unwrap();
    let mut svc = layer.layer(inner);
    let (resp, _) = run(&mut svc, form("/__gate/login", "password=preview")).await;
    assert!(
        resp.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .ends_with("; Secure")
    );
}

#[cfg(feature = "passkey")]
#[tokio::test]
async fn passkey_endpoints_require_session_and_known_state() {
    let mut c = cfg();
    c.passkey = true;
    let shared = Arc::new(GateShared::new(KEY, None));
    let route: Arc<str> = Arc::from("a.test");
    let inner = RouteSvc::new(tower::service_fn(|_r: Req| async {
        Ok::<_, Infallible>(http::Response::new(empty()))
    }));
    let layer = GatekeeperLayer::new(&route, &["a.test".to_string()], &c, true, Some(443), &shared).unwrap();
    let mut svc = layer.layer(inner);
    // Registration needs a PSK session.
    let (resp, _) = run(&mut svc, form("/__gate/passkey/register/start", "")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // With a session, the start endpoint returns WebAuthn options.
    let fp = fingerprint(&c.psk_hash, None);
    let cookie = format!("gate={}", issue(&KEY, "a.test", &fp, 'p', now_unix() + 100));
    let mut start = form("/__gate/passkey/register/start", "");
    start
        .headers_mut()
        .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
    let (resp, body) = run(&mut svc, start).await;
    assert_eq!(resp.status(), StatusCode::OK, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v["id"].is_string() && v["options"]["publicKey"]["challenge"].is_string());
    // Finishing with an unknown ceremony id is a 400.
    let mut fin = form(
        "/__gate/passkey/register/finish",
        "{\"id\":\"nope\",\"credential\":{}}",
    );
    fin.headers_mut()
        .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
    assert_eq!(run(&mut svc, fin).await.0.status(), StatusCode::BAD_REQUEST);
    let (resp, _) = run(
        &mut svc,
        form(
            "/__gate/passkey/login/finish",
            "{\"id\":\"nope\",\"credential\":{}}",
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // The registration page is behind a PSK session too.
    assert_eq!(
        run(&mut svc, req(Method::GET, "/__gate/passkey"))
            .await
            .0
            .status(),
        StatusCode::SEE_OTHER
    );
}

#[cfg(feature = "passkey")]
#[test]
fn pending_ceremonies_are_single_use_and_bounded() {
    use super::passkey::{Ceremony, Pending};
    let wa = super::passkey::build_webauthn(&["a.test".to_string()], "t", Some(443)).unwrap();
    let wa = wa.get("a.test").unwrap();
    let mk = || {
        let (_, st) = wa
            .start_passkey_registration(webauthn_rs::prelude::Uuid::new_v4(), "u", "U", None)
            .unwrap();
        Ceremony::Register(st, Arc::from("a.test"))
    };
    let p = Pending::default();
    let id = p.put(mk()).unwrap();
    assert!(p.take(&id).is_some());
    assert!(p.take(&id).is_none(), "single use");
    for _ in 0..1000 {
        assert!(p.put(mk()).is_some());
    }
    assert!(p.put(mk()).is_none(), "table is bounded");
}
