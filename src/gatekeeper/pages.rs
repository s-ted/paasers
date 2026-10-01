//! Rendering of the gatekeeper page (login and passkey registration), with a per-response CSP nonce.
use crate::observe::fallback::html_escape;
use crate::prelude::{Resp, simple};
use base64::Engine;
use http::{HeaderValue, StatusCode, header};

const TEMPLATE: &str = include_str!("login.html");

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Login,
    Passkey,
}

pub struct Page<'a> {
    pub title: &'a str,
    pub mode: Mode,
    pub message: Option<&'a str>,
    pub next: &'a str,
    pub totp: bool,
    pub passkey_login: bool,
    pub status: StatusCode,
}

fn nonce() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())
}

/// Escapes for a double-quoted JavaScript string inside an inline script (also neutralizes `</script>`).
fn js_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect(),
            '<' => "\\u003c".chars().collect(),
            '>' => "\\u003e".chars().collect(),
            '&' => "\\u0026".chars().collect(),
            '\n' | '\r' | '\u{2028}' | '\u{2029}' => Vec::new(),
            c => vec![c],
        })
        .collect()
}

pub fn render(p: &Page<'_>) -> Resp {
    let n = nonce();
    let message = p.message.map_or_else(String::new, |m| {
        format!("<p class=\"err\" role=\"alert\">{}</p>", html_escape(m))
    });
    let totp = if p.totp {
        "<label for=\"otp\">6-digit code</label><input id=\"otp\" name=\"totp\" inputmode=\"numeric\" pattern=\"[0-9 ]{6,7}\" autocomplete=\"one-time-code\" required>"
    } else {
        ""
    };
    let pk = if p.passkey_login {
        "<button type=\"button\" class=\"alt\" id=\"pk-login\">Sign in with a passkey</button>"
    } else {
        ""
    };
    let body = TEMPLATE
        .replace("{{NONCE}}", &n)
        .replace(
            "{{MODE}}",
            if p.mode == Mode::Passkey {
                "passkey"
            } else {
                "login"
            },
        )
        .replace("{{MESSAGE}}", &message)
        .replace("{{TOTP_FIELD}}", totp)
        .replace("{{PASSKEY_BUTTON}}", pk)
        .replace("{{NEXT_JS}}", &js_escape(p.next))
        .replace("{{NEXT}}", &html_escape(p.next))
        .replace("{{TITLE}}", &html_escape(p.title));
    let mut r = simple(p.status, "text/html; charset=utf-8", body);
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    let csp = format!(
        "default-src 'none'; style-src 'nonce-{n}'; script-src 'nonce-{n}'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    );
    if let Ok(v) = HeaderValue::from_str(&csp) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn page<'a>(title: &'a str, msg: Option<&'a str>, next: &'a str) -> Page<'a> {
        Page {
            title,
            mode: Mode::Login,
            message: msg,
            next,
            totp: true,
            passkey_login: true,
            status: StatusCode::OK,
        }
    }

    async fn text(r: Resp) -> String {
        String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    #[tokio::test]
    async fn csp_nonce_matches_script_tag() {
        let r = render(&page("T", None, "/"));
        let csp = r.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_string();
        let body = text(r).await;
        let nonce = csp
            .split("script-src 'nonce-")
            .nth(1)
            .unwrap()
            .split('\'')
            .next()
            .unwrap()
            .to_string();
        assert!(nonce.len() >= 20);
        assert!(
            body.contains(&format!("<script nonce=\"{nonce}\">"))
                && body.contains(&format!("<style nonce=\"{nonce}\">"))
        );
        assert!(!body.contains("{{"), "unreplaced placeholder");
    }

    #[tokio::test]
    async fn title_and_values_are_escaped() {
        let body = text(render(&page(
            "<img src=x onerror=1>",
            Some("a<b>&"),
            "/x\"><script>",
        )))
        .await;
        assert!(!body.contains("<img src=x") && body.contains("&lt;img src=x"));
        assert!(body.contains("a&lt;b&gt;&amp;"));
        assert!(!body.contains("/x\"><script>"));
        assert!(body.contains("u003cscript"), "JS context is escaped too");
    }

    #[tokio::test]
    async fn optional_blocks_follow_flags() {
        let mut p = page("T", None, "/");
        p.totp = false;
        p.passkey_login = false;
        let body = text(render(&p)).await;
        assert!(
            !body.contains("name=\"totp\"")
                && !body.contains("id=\"pk-login\"")
                && !body.contains("role=\"alert\"")
        );
        let body = text(render(&page("T", None, "/"))).await;
        assert!(body.contains("name=\"totp\"") && body.contains("id=\"pk-login\""));
    }

    #[test]
    fn page_is_small_and_headers_are_set() {
        assert!(TEMPLATE.len() < 12 * 1024);
        let r = render(&page("T", None, "/"));
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(r.headers()[header::X_FRAME_OPTIONS], "DENY");
    }
}
