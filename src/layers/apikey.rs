//! API key authentication (SHA-256 of the key, constant-time comparison).
use super::util::json_error;
use crate::config::ApiKeysCfg;
use crate::prelude::{ApiKeyAuthenticated, BoxFut, Req, Resp, RouteSvc};
use http::{HeaderName, HeaderValue, StatusCode};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};
use subtle::ConstantTimeEq;
use tower::Service;

#[derive(Clone)]
pub struct ApiKeyLayer {
    header: HeaderName,
    /// Header name as configured, echoed in the `WWW-Authenticate` challenge.
    header_display: Arc<str>,
    keys: Arc<Vec<([u8; 32], Arc<str>)>>,
    jwt_configured: bool,
}

impl ApiKeyLayer {
    pub fn new(cfg: &ApiKeysCfg, jwt_configured: bool) -> Option<Self> {
        let keys = cfg
            .keys
            .iter()
            .map(|k| {
                Some((
                    <[u8; 32]>::try_from(hex::decode(&k.hash_hex).ok()?).ok()?,
                    Arc::from(k.name.as_str()),
                ))
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            header: HeaderName::from_bytes(cfg.header.as_bytes()).ok()?,
            header_display: Arc::from(cfg.header.as_str()),
            keys: Arc::new(keys),
            jwt_configured,
        })
    }

    /// Walks the whole list: the time taken does not depend on which key matched.
    fn lookup(&self, value: &[u8]) -> Option<Arc<str>> {
        let h: [u8; 32] = Sha256::digest(value).into();
        self.keys.iter().fold(None, |found, (k, name)| {
            if bool::from(h.ct_eq(k)) {
                Some(name.clone())
            } else {
                found
            }
        })
    }
}

impl tower::Layer<RouteSvc> for ApiKeyLayer {
    type Service = ApiKey;
    fn layer(&self, inner: RouteSvc) -> ApiKey {
        ApiKey {
            inner,
            cfg: self.clone(),
        }
    }
}

#[derive(Clone)]
pub struct ApiKey {
    inner: RouteSvc,
    cfg: ApiKeyLayer,
}

impl Service<Req> for ApiKey {
    type Response = Resp;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Req) -> BoxFut {
        let cfg = &self.cfg;
        match req.headers().get(&cfg.header).map(|v| v.as_bytes().to_vec()) {
            None if cfg.jwt_configured => {}
            None => {
                let challenge = format!("ApiKey header=\"{}\"", cfg.header_display);
                let r = json_error(StatusCode::UNAUTHORIZED, "api_key_required", Some(&challenge));
                return Box::pin(std::future::ready(Ok(r)));
            }
            Some(v) => match cfg.lookup(&v) {
                Some(name) => {
                    req.headers_mut().remove(&cfg.header);
                    if let Ok(n) = HeaderValue::from_str(&name) {
                        req.headers_mut().insert("x-api-key-name", n);
                    }
                    req.extensions_mut().insert(ApiKeyAuthenticated);
                }
                None => {
                    let r = json_error(StatusCode::UNAUTHORIZED, "invalid_api_key", None);
                    return Box::pin(std::future::ready(Ok(r)));
                }
            },
        }
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move { Ok(crate::cache::layer::call_svc(&mut inner, req).await) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApiKeyEntry;
    use crate::prelude::empty;
    use tower::Layer;

    const KEY: &str = "test-api-key-0123456789";
    const KEY_HASH: &str = "47bd0e2f856fe258ebba4d00930ab811d0c004dafae068c9d72511ca3512cca6";

    fn svc(jwt: bool) -> ApiKey {
        let cfg = ApiKeysCfg {
            header: "X-Api-Key".into(),
            keys: vec![ApiKeyEntry {
                hash_hex: KEY_HASH.into(),
                name: "ci".into(),
            }],
        };
        let inner = RouteSvc::new(tower::service_fn(|r: Req| async move {
            let mut resp = http::Response::new(empty());
            resp.headers_mut().insert(
                "x-has-key",
                HeaderValue::from_static(if r.headers().contains_key("x-api-key") {
                    "1"
                } else {
                    "0"
                }),
            );
            if let Some(n) = r.headers().get("x-api-key-name") {
                resp.headers_mut().insert("x-name", n.clone());
            }
            resp.headers_mut().insert(
                "x-authed",
                HeaderValue::from_static(if r.extensions().get::<ApiKeyAuthenticated>().is_some() {
                    "1"
                } else {
                    "0"
                }),
            );
            Ok::<_, Infallible>(resp)
        }));
        ApiKeyLayer::new(&cfg, jwt).unwrap().layer(inner)
    }

    async fn call(s: &mut ApiKey, key: Option<&str>) -> Resp {
        let mut r = http::Request::new(empty());
        if let Some(k) = key {
            r.headers_mut()
                .insert("x-api-key", HeaderValue::from_str(k).unwrap());
        }
        s.call(r).await.unwrap()
    }

    #[tokio::test]
    async fn valid_key_forwarded_with_name_and_header_removed() {
        let r = call(&mut svc(false), Some(KEY)).await;
        assert_eq!(r.status(), 200);
        assert_eq!(
            (
                r.headers()["x-has-key"].to_str().unwrap(),
                r.headers()["x-name"].to_str().unwrap()
            ),
            ("0", "ci")
        );
        assert_eq!(r.headers()["x-authed"], "1");
    }

    #[tokio::test]
    async fn invalid_key_401() {
        for jwt in [false, true] {
            let r = call(&mut svc(jwt), Some("wrong")).await;
            assert_eq!(
                r.status(),
                401,
                "a wrong key is an error even with JWT configured"
            );
        }
    }

    #[tokio::test]
    async fn missing_key_401_without_jwt() {
        let r = call(&mut svc(false), None).await;
        assert_eq!(r.status(), 401);
        assert_eq!(r.headers()["www-authenticate"], "ApiKey header=\"X-Api-Key\"");
    }

    #[tokio::test]
    async fn missing_key_passes_to_jwt_when_configured() {
        let r = call(&mut svc(true), None).await;
        assert_eq!(
            (r.status(), r.headers()["x-authed"].to_str().unwrap()),
            (StatusCode::OK, "0")
        );
    }

    #[test]
    fn rejects_malformed_hash() {
        let cfg = ApiKeysCfg {
            header: "X-Api-Key".into(),
            keys: vec![ApiKeyEntry {
                hash_hex: "zz".into(),
                name: "a".into(),
            }],
        };
        assert!(ApiKeyLayer::new(&cfg, false).is_none());
    }
}
