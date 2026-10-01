//! JWT validation (HMAC or public key) with claim injection and anti-spoofing.
use super::util::json_error;
use crate::config::{JwtCfg, JwtKey, PemKind};
use crate::prelude::{ApiKeyAuthenticated, BoxFut, Req, Resp, RouteSvc};
use base64::Engine;
use http::{HeaderValue, StatusCode, header};
use jsonwebtoken::{DecodingKey, Validation};
use serde_json::{Map, Value};
use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::Service;

const MAX_CLAIMS_HEADER: usize = 8 * 1024;
const INJECTED: &[&str] = &["x-user-id", "x-user-email", "x-user-roles", "x-jwt-claims"];

struct Rt {
    key: DecodingKey,
    validation: Validation,
    inject: bool,
    cookie: Option<String>,
    realm: Arc<str>,
}

#[derive(Clone)]
pub struct JwtLayer {
    rt: Arc<Rt>,
}

impl JwtLayer {
    pub fn new(cfg: &JwtCfg, route_id: &str) -> Result<Self, String> {
        let key = match &cfg.key {
            JwtKey::Hmac { secret } => DecodingKey::from_secret(secret),
            JwtKey::PublicKeyPem { pem, kind, .. } => match kind {
                PemKind::Rsa => DecodingKey::from_rsa_pem(pem),
                PemKind::Ec => DecodingKey::from_ec_pem(pem),
                PemKind::Ed => DecodingKey::from_ed_pem(pem),
            }
            .map_err(|e| format!("invalid public key: {e}"))?,
        };
        let first = *cfg.algorithms.first().ok_or("no JWT algorithm")?;
        let mut v = Validation::new(first);
        v.algorithms = cfg.algorithms.clone();
        v.leeway = cfg.leeway.as_secs();
        v.validate_exp = true;
        v.set_required_spec_claims(&["exp"]);
        if !cfg.issuers.is_empty() {
            v.set_issuer(&cfg.issuers);
        }
        if cfg.audiences.is_empty() {
            v.validate_aud = false;
        } else {
            v.set_audience(&cfg.audiences);
        }
        let realm = Arc::from(route_id);
        Ok(Self {
            rt: Arc::new(Rt {
                key,
                validation: v,
                inject: cfg.inject_headers,
                cookie: cfg.cookie.clone(),
                realm,
            }),
        })
    }
}

impl tower::Layer<RouteSvc> for JwtLayer {
    type Service = Jwt;
    fn layer(&self, inner: RouteSvc) -> Jwt {
        Jwt {
            inner,
            rt: self.rt.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Jwt {
    inner: RouteSvc,
    rt: Arc<Rt>,
}

/// `Authorization: Bearer <t>` (scheme case-insensitive), otherwise the configured cookie.
fn token(req: &Req, cookie: Option<&str>) -> Option<String> {
    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let (scheme, rest) = v.split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then(|| rest.trim().to_string())
        });
    bearer.filter(|t| !t.is_empty()).or_else(|| {
        let name = cookie?;
        crate::gatekeeper::session::read_cookie(req.headers(), name).map(str::to_string)
    })
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn set(req: &mut Req, name: &'static str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        req.headers_mut().insert(name, v);
    }
}

fn inject(req: &mut Req, claims: &Map<String, Value>) {
    if let Some(sub) = claims.get("sub").and_then(scalar) {
        set(req, "x-user-id", &sub);
    }
    if let Some(Value::String(e)) = claims.get("email") {
        set(req, "x-user-email", e);
    }
    let roles = match claims.get("roles") {
        Some(Value::Array(a)) => Some(a.iter().filter_map(|r| r.as_str()).collect::<Vec<_>>().join(",")),
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    };
    if let Some(r) = roles {
        set(req, "x-user-roles", &r);
    }
    if let Ok(raw) = serde_json::to_vec(claims)
        && raw.len() <= MAX_CLAIMS_HEADER
    {
        set(
            req,
            "x-jwt-claims",
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
        );
    }
}

impl Service<Req> for Jwt {
    type Response = Resp;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Req) -> BoxFut {
        let rt = self.rt.clone();
        // Incoming copies of the injected headers are never trusted, even when injection is off.
        INJECTED.iter().for_each(|h| {
            req.headers_mut().remove(*h);
        });
        if req.extensions().get::<ApiKeyAuthenticated>().is_none() {
            let Some(t) = token(&req, rt.cookie.as_deref()) else {
                let challenge = format!("Bearer realm=\"{}\"", rt.realm);
                return Box::pin(std::future::ready(Ok(json_error(
                    StatusCode::UNAUTHORIZED,
                    "token_required",
                    Some(&challenge),
                ))));
            };
            match jsonwebtoken::decode::<Map<String, Value>>(&t, &rt.key, &rt.validation) {
                Ok(data) if rt.inject => inject(&mut req, &data.claims),
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(error = %e, "jwt rejected");
                    let r = json_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_token",
                        Some("Bearer error=\"invalid_token\""),
                    );
                    return Box::pin(std::future::ready(Ok(r)));
                }
            }
        }
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move { Ok(crate::cache::layer::call_svc(&mut inner, req).await) })
    }
}
