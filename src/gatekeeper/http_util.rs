//! Small HTTP helpers for the gatekeeper endpoints.
use crate::prelude::{IncidentKind, Req, Resp, Scheme, simple};
use http::{StatusCode, header};
use http_body_util::BodyExt;

pub fn query_param(req: &Req, name: &str) -> String {
    req.uri()
        .query()
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
        })
        .unwrap_or_default()
}

pub fn json_401() -> Resp {
    let mut r = simple(
        StatusCode::UNAUTHORIZED,
        "application/json",
        "{\"error\":\"gatekeeper_login_required\",\"login\":\"/__gate/login\"}",
    );
    r.extensions_mut().insert(IncidentKind("auth"));
    r
}

/// A cross-origin `Origin` header on a POST is refused (CSRF), on top of `SameSite=Lax`.
pub fn origin_ok(req: &Req) -> bool {
    let Some(origin) = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let scheme = req.extensions().get::<Scheme>().map_or("http", |s| s.0);
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    origin.eq_ignore_ascii_case(&format!("{scheme}://{host}"))
}

pub async fn read_body(req: Req, limit: usize) -> Option<Vec<u8>> {
    let mut body = req.into_body();
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.ok()?;
        if let Some(d) = frame.data_ref() {
            if buf.len() + d.len() > limit {
                return None;
            }
            buf.extend_from_slice(d);
        }
    }
    Some(buf)
}

pub fn forbidden() -> Resp {
    let mut r = simple(
        StatusCode::FORBIDDEN,
        "text/plain",
        "cross-origin request refused",
    );
    r.extensions_mut().insert(IncidentKind("auth"));
    r
}
