//! Form handling for `POST /__gate/login` and redirect target validation.
use super::GateRt;
use super::pages::{Page, render};
use super::psk::verify_psk;
use super::session::{issue, set_cookie_header};
use crate::prelude::{ClientIp, IncidentKind, Resp, empty};
use crate::storage::now_unix;
use http::{HeaderValue, StatusCode, header};

pub const MAX_FORM_BYTES: usize = 8 * 1024;
const MAX_NEXT: usize = 2048;

/// Only same-site absolute paths are accepted as redirect targets.
pub fn safe_next(s: &str) -> String {
    let ok = s.starts_with('/')
        && !s.starts_with("//")
        && !s.starts_with("/\\")
        && s.len() <= MAX_NEXT
        && !s.chars().any(|c| c.is_control())
        && !s.starts_with("/__gate/");
    if ok { s.to_string() } else { "/".to_string() }
}

pub fn redirect(location: &str, cookie: Option<String>) -> Resp {
    let mut r = http::Response::new(empty());
    *r.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(v) = HeaderValue::from_str(location) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    if let Some(c) = cookie.and_then(|c| HeaderValue::from_str(&c).ok()) {
        r.headers_mut().append(header::SET_COOKIE, c);
    }
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

pub fn session_cookie(rt: &GateRt, method: char) -> String {
    let exp = now_unix().saturating_add(rt.session_secs);
    set_cookie_header(
        &rt.cookie_name,
        &issue(&rt.shared.hmac_key, &rt.route_id, &rt.fingerprint, method, exp),
        rt.session_secs,
        rt.secure,
    )
}

pub fn clear_cookie(rt: &GateRt) -> String {
    set_cookie_header(&rt.cookie_name, "", 0, rt.secure)
}

fn page(rt: &GateRt, status: StatusCode, msg: &str, next: &str) -> Resp {
    render(&Page {
        title: &rt.title,
        message: Some(msg),
        next,
        totp: rt.totp.is_some(),
        status,
    })
}

pub fn login_page(rt: &GateRt, next: &str) -> Resp {
    render(&Page {
        title: &rt.title,
        message: None,
        next,
        totp: rt.totp.is_some(),
        status: StatusCode::OK,
    })
}

fn flag(mut r: Resp, kind: &'static str) -> Resp {
    r.extensions_mut().insert(IncidentKind(kind));
    r
}

/// Handles the login form. Every attempt consumes limiter budget before anything is verified.
pub async fn handle_post(rt: &GateRt, ip: ClientIp, body: &[u8]) -> Resp {
    let (mut password, mut totp, mut next) = (String::new(), String::new(), String::new());
    for (k, v) in url::form_urlencoded::parse(body) {
        match k.as_ref() {
            "password" => password = v.into_owned(),
            "totp" => totp = v.into_owned(),
            "next" => next = v.into_owned(),
            _ => {}
        }
    }
    let next = safe_next(&next);
    if let Err(secs) = rt.limiter.check(ip.0) {
        let msg = format!(
            "Too many attempts. Try again in {} minutes.",
            secs.div_ceil(60).max(1)
        );
        let mut r = page(rt, StatusCode::TOO_MANY_REQUESTS, &msg, &next);
        if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
            r.headers_mut().insert(header::RETRY_AFTER, v);
        }
        return flag(r, "rate_limited");
    }
    // The PSK is verified first so that a wrong password never consumes a TOTP step.
    let psk_ok = verify_psk(&rt.shared.argon_sem, rt.phc.clone(), password).await;
    let totp_ok = psk_ok
        && rt
            .totp
            .as_ref()
            .is_none_or(|t| t.verify(&totp, now_unix().unsigned_abs()));
    if !(psk_ok && totp_ok) {
        // Same message whatever failed: no oracle for the PSK versus the second factor.
        return flag(
            page(rt, StatusCode::UNAUTHORIZED, "Invalid credentials.", &next),
            "auth",
        );
    }
    let cookie = session_cookie(rt, 'p');
    redirect(&next, Some(cookie))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_next_rejects_open_redirect() {
        for bad in [
            "//evil.com",
            "/\\evil.com",
            "https://evil.com",
            "evil.com",
            "",
            "/a\nb",
            "/__gate/login",
            "javascript:1",
        ] {
            assert_eq!(safe_next(bad), "/", "{bad:?}");
        }
        assert_eq!(safe_next("/app?x=1#y"), "/app?x=1#y");
        assert_eq!(safe_next(&format!("/{}", "a".repeat(3000))), "/");
    }
}
