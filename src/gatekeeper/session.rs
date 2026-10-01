//! HMAC-SHA256 signed session cookie (pure).
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HS = Hmac<Sha256>;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn mac(key: &[u8; 32], route: &str, exp: i64, m: char, fp: &str) -> Option<HS> {
    let mut h = HS::new_from_slice(key).ok()?;
    h.update(format!("v1|{route}|{exp}|{m}|{fp}").as_bytes());
    Some(h)
}

/// Hex of the first 8 bytes of `SHA-256(psk|totp)`: changing either secret invalidates every session.
pub fn fingerprint(psk_phc: &str, totp_secret: Option<&[u8]>) -> String {
    let mut h = Sha256::new();
    h.update(psk_phc.as_bytes());
    h.update(b"|");
    h.update(totp_secret.unwrap_or_default());
    hex::encode(h.finalize().get(..8).unwrap_or_default())
}

pub fn issue(key: &[u8; 32], route: &str, fp: &str, m: char, exp: i64) -> String {
    let sig = mac(key, route, exp, m, fp)
        .map(|h| h.finalize().into_bytes().to_vec())
        .unwrap_or_default();
    format!("v1.{exp}.{m}.{}", B64.encode(sig))
}

/// Returns the login method (`'p'` PSK, `'k'` passkey) of a valid cookie.
pub fn verify(key: &[u8; 32], route: &str, fp: &str, cookie: &str, now: i64) -> Option<char> {
    let mut it = cookie.split('.');
    let (Some("v1"), Some(exp), Some(m), Some(sig), None) =
        (it.next(), it.next(), it.next(), it.next(), it.next())
    else {
        return None;
    };
    let exp = exp.parse::<i64>().ok()?;
    let mut chars = m.chars();
    let (Some(mc), None) = (chars.next(), chars.next()) else {
        return None;
    };
    if exp <= now || !matches!(mc, 'p' | 'k') {
        return None;
    }
    let sig = B64.decode(sig).ok()?;
    mac(key, route, exp, mc, fp)
        .is_some_and(|h| h.verify_slice(&sig).is_ok())
        .then_some(mc)
}

/// First value named `name` across all `Cookie` headers.
pub fn read_cookie<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .filter_map(|p| p.trim().split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v)
}

/// Rebuilds the `Cookie` headers without the cookie `name` (header removed if empty).
pub fn strip_cookie(headers: &mut http::HeaderMap, name: &str) {
    let kept: Vec<String> = headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(str::trim)
        .filter(|p| !p.is_empty() && p.split_once('=').is_none_or(|(n, _)| n != name))
        .map(str::to_string)
        .collect();
    headers.remove(http::header::COOKIE);
    if !kept.is_empty()
        && let Ok(v) = http::HeaderValue::from_str(&kept.join("; "))
    {
        headers.insert(http::header::COOKIE, v);
    }
}

pub fn set_cookie_header(name: &str, value: &str, max_age: i64, secure: bool) -> String {
    format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    #[test]
    fn roundtrip() {
        let c = issue(&KEY, "a.com", "fp", 'p', 1000);
        assert_eq!(verify(&KEY, "a.com", "fp", &c, 999), Some('p'));
        assert_eq!(
            verify(&KEY, "a.com", "fp", &issue(&KEY, "a.com", "fp", 'k', 1000), 1),
            Some('k')
        );
    }

    #[test]
    fn expired_rejected() {
        let c = issue(&KEY, "a.com", "fp", 'p', 1000);
        assert!(verify(&KEY, "a.com", "fp", &c, 1000).is_none());
        assert!(verify(&KEY, "a.com", "fp", &c, 2000).is_none());
    }

    #[test]
    fn tampered_sig_rejected() {
        let c = issue(&KEY, "a.com", "fp", 'p', 1000);
        let bad = format!("{}x", &c[..c.len() - 1]);
        assert!(verify(&KEY, "a.com", "fp", &bad, 1).is_none());
        let forged = c.replacen(".p.", ".k.", 1);
        assert!(verify(&KEY, "a.com", "fp", &forged, 1).is_none());
        let longer = c.replacen("1000", "9999", 1);
        assert!(verify(&KEY, "a.com", "fp", &longer, 1).is_none());
    }

    #[test]
    fn other_route_rejected() {
        let c = issue(&KEY, "a.com", "fp", 'p', 1000);
        assert!(verify(&KEY, "b.com", "fp", &c, 1).is_none());
        assert!(verify(&[8; 32], "a.com", "fp", &c, 1).is_none());
    }

    #[test]
    fn psk_change_invalidates() {
        let a = fingerprint("hash1", None);
        let b = fingerprint("hash2", None);
        let c = fingerprint("hash1", Some(b"totp"));
        assert!(a != b && a != c && a.len() == 16);
        let cookie = issue(&KEY, "a.com", &a, 'p', 1000);
        assert!(verify(&KEY, "a.com", &b, &cookie, 1).is_none());
    }

    #[test]
    fn malformed_never_panics() {
        for s in [
            "",
            ".",
            "v1",
            "v1.",
            "v1..",
            "v1...",
            "v1.1.p",
            "v1.1.p.",
            "v1.x.p.AAAA",
            "v1.99999999999999999999999.p.AA",
            "v2.1.p.AAAA",
            "v1.1.pp.AAAA",
            "v1.1.x.AAAA",
            "v1.1.p.!!!",
            "v1.1.p.AAAA.extra",
            "é.é.é.é",
            "v1.-5.p.AA",
            "v1.1.\u{0}.AA",
            "....",
            "v1.1.p.AAAA=",
        ] {
            assert!(verify(&KEY, "a.com", "fp", s, 0).is_none(), "{s:?}");
        }
    }

    #[test]
    fn cookie_read_and_strip() {
        let mut h = http::HeaderMap::new();
        h.append("cookie", "a=1; gate=tok; b=2".parse().unwrap());
        h.append("cookie", "gate=other; c=3".parse().unwrap());
        assert_eq!(read_cookie(&h, "gate"), Some("tok"));
        assert_eq!(read_cookie(&h, "zzz"), None);
        strip_cookie(&mut h, "gate");
        assert_eq!(h["cookie"], "a=1; b=2; c=3");
        let mut only = http::HeaderMap::new();
        only.insert("cookie", "gate=tok".parse().unwrap());
        strip_cookie(&mut only, "gate");
        assert!(!only.contains_key("cookie"));
    }

    #[test]
    fn set_cookie_attributes() {
        let c = set_cookie_header("__Host-gate", "v", 60, true);
        assert_eq!(
            c,
            "__Host-gate=v; Path=/; HttpOnly; SameSite=Lax; Max-Age=60; Secure"
        );
        assert!(!set_cookie_header("gate", "v", 0, false).contains("Secure"));
    }
}
