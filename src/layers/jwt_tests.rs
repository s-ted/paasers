//! JWT layer tests: keys are generated in the tests, RSA uses committed fixtures.
use super::jwt::{Jwt, JwtLayer};
use crate::config::{JwtCfg, JwtKey, PemKind};
use crate::prelude::{ApiKeyAuthenticated, Req, Resp, RouteSvc, empty};
use base64::Engine;
use http::{HeaderValue, header};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use std::convert::Infallible;
use std::path::PathBuf;
use std::time::Duration;
use tower::{Layer, Service};

const SECRET: &[u8] = b"test-secret-at-least-32-bytes-long!!";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn cfg(key: JwtKey, alg: Algorithm) -> JwtCfg {
    JwtCfg {
        key,
        algorithms: vec![alg],
        issuers: vec![],
        audiences: vec![],
        leeway: Duration::from_secs(60),
        inject_headers: true,
        cookie: None,
    }
}

fn hmac_cfg() -> JwtCfg {
    cfg(
        JwtKey::Hmac {
            secret: SECRET.to_vec(),
        },
        Algorithm::HS256,
    )
}

/// Backend that reports the injected headers back as response headers.
fn svc(c: &JwtCfg) -> Jwt {
    let inner = RouteSvc::new(tower::service_fn(|r: Req| async move {
        let mut resp = http::Response::new(empty());
        for h in [
            "x-user-id",
            "x-user-email",
            "x-user-roles",
            "x-jwt-claims",
            "authorization",
        ] {
            if let Some(v) = r.headers().get(h) {
                resp.headers_mut().insert(
                    http::HeaderName::from_bytes(format!("x-seen-{h}").as_bytes()).unwrap(),
                    v.clone(),
                );
            }
        }
        Ok::<_, Infallible>(resp)
    }));
    JwtLayer::new(c, "r.test").unwrap().layer(inner)
}

fn hs256(claims: serde_json::Value) -> String {
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap()
}

fn good_claims() -> serde_json::Value {
    json!({"sub": "u1", "exp": now() + 600, "iss": "https://auth", "email": "a@b.c", "roles": ["admin", "dev"], "aud": "app"})
}

async fn call(s: &mut Jwt, auth: Option<String>) -> Resp {
    let mut r = http::Request::new(empty());
    if let Some(a) = auth {
        r.headers_mut()
            .insert(header::AUTHORIZATION, HeaderValue::from_str(&a).unwrap());
    }
    s.call(r).await.unwrap()
}

#[tokio::test]
async fn hs256_valid_injects_claims() {
    let mut s = svc(&hmac_cfg());
    let t = hs256(good_claims());
    let r = call(&mut s, Some(format!("Bearer {t}"))).await;
    assert_eq!(r.status(), 200);
    let h = r.headers();
    assert_eq!(h["x-seen-x-user-id"], "u1");
    assert_eq!(h["x-seen-x-user-email"], "a@b.c");
    assert_eq!(h["x-seen-x-user-roles"], "admin,dev");
    let claims: serde_json::Value =
        serde_json::from_slice(&B64.decode(h["x-seen-x-jwt-claims"].as_bytes()).unwrap()).unwrap();
    assert_eq!(claims["sub"], "u1");
    assert_eq!(
        h["x-seen-authorization"].to_str().unwrap(),
        format!("Bearer {t}"),
        "Authorization is kept for the backend"
    );
}

#[tokio::test]
async fn missing_and_garbage_tokens_401() {
    let mut s = svc(&hmac_cfg());
    let r = call(&mut s, None).await;
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()[header::WWW_AUTHENTICATE], "Bearer realm=\"r.test\"");
    for bad in ["Bearer garbage", "Bearer ", "Basic abc", "Bearer a.b.c"] {
        let r = call(&mut s, Some(bad.into())).await;
        assert_eq!(r.status(), 401, "{bad}");
    }
}

#[tokio::test]
async fn expired_401_and_leeway_applies() {
    let mut s = svc(&hmac_cfg());
    assert_eq!(
        call(
            &mut s,
            Some(format!(
                "Bearer {}",
                hs256(json!({"sub": "u", "exp": now() - 3600}))
            ))
        )
        .await
        .status(),
        401
    );
    assert_eq!(
        call(
            &mut s,
            Some(format!(
                "Bearer {}",
                hs256(json!({"sub": "u", "exp": now() - 10}))
            ))
        )
        .await
        .status(),
        200,
        "within 60s leeway"
    );
    assert_eq!(
        call(&mut s, Some(format!("Bearer {}", hs256(json!({"sub": "u"})))))
            .await
            .status(),
        401,
        "exp is required"
    );
}

#[tokio::test]
async fn wrong_issuer_and_audience_401() {
    let mut c = hmac_cfg();
    c.issuers = vec!["https://auth".into()];
    c.audiences = vec!["app".into()];
    let mut s = svc(&c);
    assert_eq!(
        call(&mut s, Some(format!("Bearer {}", hs256(good_claims()))))
            .await
            .status(),
        200
    );
    let mut bad_iss = good_claims();
    bad_iss["iss"] = json!("https://evil");
    assert_eq!(
        call(&mut s, Some(format!("Bearer {}", hs256(bad_iss))))
            .await
            .status(),
        401
    );
    let mut bad_aud = good_claims();
    bad_aud["aud"] = json!("other");
    assert_eq!(
        call(&mut s, Some(format!("Bearer {}", hs256(bad_aud))))
            .await
            .status(),
        401
    );
}

#[tokio::test]
async fn alg_none_rejected() {
    let mut s = svc(&hmac_cfg());
    let h = B64.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let p = B64.encode(serde_json::to_vec(&good_claims()).unwrap());
    assert_eq!(call(&mut s, Some(format!("Bearer {h}.{p}."))).await.status(), 401);
    assert_eq!(
        call(&mut s, Some(format!("Bearer {h}.{p}.AAAA"))).await.status(),
        401
    );
}

#[tokio::test]
async fn other_algorithm_and_wrong_secret_rejected() {
    let mut s = svc(&hmac_cfg());
    let hs512 = jsonwebtoken::encode(
        &Header::new(Algorithm::HS512),
        &good_claims(),
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap();
    assert_eq!(
        call(&mut s, Some(format!("Bearer {hs512}"))).await.status(),
        401,
        "only configured algorithms"
    );
    let wrong = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &good_claims(),
        &EncodingKey::from_secret(b"another-secret-another-secret-xx"),
    )
    .unwrap();
    assert_eq!(call(&mut s, Some(format!("Bearer {wrong}"))).await.status(), 401);
}

fn rsa_fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

fn rsa_cfg() -> JwtCfg {
    let pem = rsa_fixture("jwt_rsa_pub.pem");
    cfg(
        JwtKey::PublicKeyPem {
            path: "pub.pem".into(),
            pem,
            kind: PemKind::Rsa,
        },
        Algorithm::RS256,
    )
}

#[tokio::test]
async fn rs256_valid_and_hs_token_on_rsa_key_rejected() {
    let mut s = svc(&rsa_cfg());
    let key = EncodingKey::from_rsa_pem(&rsa_fixture("jwt_rsa_priv.pem")).unwrap();
    let t = jsonwebtoken::encode(&Header::new(Algorithm::RS256), &good_claims(), &key).unwrap();
    assert_eq!(call(&mut s, Some(format!("Bearer {t}"))).await.status(), 200);
    // Algorithm confusion: an HS256 token signed with the public key as secret.
    let confused = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &good_claims(),
        &EncodingKey::from_secret(&rsa_fixture("jwt_rsa_pub.pem")),
    )
    .unwrap();
    assert_eq!(
        call(&mut s, Some(format!("Bearer {confused}"))).await.status(),
        401
    );
}

#[tokio::test]
async fn eddsa_valid() {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let (priv_pem, pub_pem) = (kp.serialize_pem(), kp.public_key_pem());
    let c = cfg(
        JwtKey::PublicKeyPem {
            path: "ed.pem".into(),
            pem: pub_pem.into_bytes(),
            kind: PemKind::Ed,
        },
        Algorithm::EdDSA,
    );
    let mut s = svc(&c);
    let t = jsonwebtoken::encode(
        &Header::new(Algorithm::EdDSA),
        &good_claims(),
        &EncodingKey::from_ed_pem(priv_pem.as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(call(&mut s, Some(format!("Bearer {t}"))).await.status(), 200);
    assert_eq!(
        call(&mut s, Some(format!("Bearer {}", hs256(good_claims()))))
            .await
            .status(),
        401,
        "HS256 token on an Ed key"
    );
}

#[tokio::test]
async fn cookie_source() {
    let mut c = hmac_cfg();
    c.cookie = Some("jwt".into());
    let mut s = svc(&c);
    let mut r = http::Request::new(empty());
    r.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("a=1; jwt={}", hs256(good_claims()))).unwrap(),
    );
    assert_eq!(s.call(r).await.unwrap().status(), 200);
    let mut r = http::Request::new(empty());
    r.headers_mut()
        .insert(header::COOKIE, HeaderValue::from_static("jwt=bad"));
    assert_eq!(s.call(r).await.unwrap().status(), 401);
}

#[tokio::test]
async fn api_key_bypasses_jwt() {
    let mut s = svc(&hmac_cfg());
    let mut r = http::Request::new(empty());
    r.extensions_mut().insert(ApiKeyAuthenticated);
    assert_eq!(s.call(r).await.unwrap().status(), 200);
}

#[tokio::test]
async fn spoofed_user_headers_are_always_removed() {
    for inject in [true, false] {
        let mut c = hmac_cfg();
        c.inject_headers = inject;
        let mut s = svc(&c);
        let mut r = http::Request::new(empty());
        r.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!(
                "bearer {}",
                hs256(json!({"sub": "real", "exp": now() + 60}))
            ))
            .unwrap(),
        );
        for h in ["x-user-id", "x-user-roles", "x-jwt-claims", "x-user-email"] {
            r.headers_mut().insert(h, HeaderValue::from_static("forged"));
        }
        let resp = s.call(r).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_ne!(
            resp.headers().get("x-seen-x-user-roles").map(|v| v.as_bytes()),
            Some(&b"forged"[..])
        );
        assert_ne!(
            resp.headers().get("x-seen-x-user-email").map(|v| v.as_bytes()),
            Some(&b"forged"[..])
        );
        assert_eq!(
            resp.headers().get("x-seen-x-user-id").map(|v| v.as_bytes()),
            inject.then_some(&b"real"[..])
        );
    }
}

#[tokio::test]
async fn roles_string_and_numeric_sub() {
    let mut s = svc(&hmac_cfg());
    let t = hs256(json!({"sub": 42, "exp": now() + 60, "roles": "viewer"}));
    let r = call(&mut s, Some(format!("Bearer {t}"))).await;
    assert_eq!(r.headers()["x-seen-x-user-id"], "42");
    assert_eq!(r.headers()["x-seen-x-user-roles"], "viewer");
}

#[test]
#[ignore = "timing test: run with `cargo test --release -- --ignored jwt_decode_under_50us_hs256`"]
fn jwt_decode_under_50us_hs256() {
    let c = hmac_cfg();
    let layer = JwtLayer::new(&c, "r").unwrap();
    drop(layer);
    let key = jsonwebtoken::DecodingKey::from_secret(SECRET);
    let mut v = jsonwebtoken::Validation::new(Algorithm::HS256);
    v.set_issuer(&["https://auth"]);
    v.validate_aud = false;
    let t = hs256(good_claims());
    let mut times: Vec<u128> = (0..2000)
        .map(|_| {
            let s = std::time::Instant::now();
            let _ = jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(&t, &key, &v).unwrap();
            s.elapsed().as_nanos()
        })
        .collect();
    times.sort_unstable();
    let median = times[times.len() / 2];
    assert!(median < 50_000, "median {median} ns");
}
