//! Hyper-facing wrapper: `/healthz`, Bearer token check, then the rmcp service on `/mcp`.
use crate::prelude::{BoxFut, Resp, boxed, simple};
use http::{HeaderValue, StatusCode, header};
use http_body_util::BodyExt;
use rmcp::transport::streamable_http_server::{StreamableHttpService, session::local::LocalSessionManager};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};
use subtle::ConstantTimeEq;
use tower::Service;

use super::server::Gw;

const MAX_BODY: usize = 1024 * 1024;

#[derive(Clone)]
pub struct McpHttp {
    pub service: StreamableHttpService<Gw, LocalSessionManager>,
    /// SHA-256 of the expected `Bearer <token>` value: comparing digests equalizes lengths.
    pub token_digest: Option<Arc<[u8; 32]>>,
}

pub fn digest(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

pub fn authorized(expected: Option<&[u8; 32]>, header_value: Option<&str>) -> bool {
    match expected {
        None => true,
        Some(e) => bool::from(digest(header_value.unwrap_or_default()).ct_eq(e)),
    }
}

fn unauthorized() -> Resp {
    let mut r = simple(
        StatusCode::UNAUTHORIZED,
        "application/json",
        "{\"error\":\"unauthorized\"}",
    );
    r.headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    r
}

/// Reads at most `MAX_BODY` bytes.
async fn bounded(body: crate::prelude::Body) -> Option<bytes::Bytes> {
    let mut body = body;
    let mut buf = bytes::BytesMut::new();
    while let Some(f) = body.frame().await {
        let f = f.ok()?;
        if let Some(d) = f.data_ref() {
            if buf.len() + d.len() > MAX_BODY {
                return None;
            }
            buf.extend_from_slice(d);
        }
    }
    Some(buf.freeze())
}

impl McpHttp {
    pub fn expected_header(token: &str) -> String {
        format!("Bearer {token}")
    }
}

impl Service<http::Request<hyper::body::Incoming>> for McpHttp {
    type Response = Resp;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<hyper::body::Incoming>) -> BoxFut {
        let (mut svc, token) = (self.service.clone(), self.token_digest.clone());
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            if parts.method == http::Method::GET && parts.uri.path() == "/healthz" {
                return Ok(simple(StatusCode::OK, "text/plain", "ok"));
            }
            if parts.uri.path() != "/mcp" {
                return Ok(simple(StatusCode::NOT_FOUND, "text/plain", "not found"));
            }
            let given = parts
                .headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            if !authorized(token.as_deref(), given) {
                return Ok(unauthorized());
            }
            let Some(bytes) = bounded(boxed(body)).await else {
                return Ok(simple(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "text/plain",
                    "body too large",
                ));
            };
            let req = http::Request::from_parts(parts, http_body_util::Full::new(bytes));
            let resp = match svc.call(req).await {
                Ok(r) => r,
                Err(e) => match e {},
            };
            Ok(resp.map(boxed))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_is_exact_and_constant_shape() {
        let d = digest("Bearer secret-token-0123456789");
        assert!(authorized(Some(&d), Some("Bearer secret-token-0123456789")));
        for bad in [
            None,
            Some(""),
            Some("Bearer secret-token-012345678"),
            Some("bearer secret-token-0123456789"),
            Some("Bearer secret-token-0123456789 "),
        ] {
            assert!(!authorized(Some(&d), bad), "{bad:?}");
        }
        assert!(
            authorized(None, None),
            "no token configured: loopback listener only"
        );
    }
}
