//! Client conditional requests answered from the cache (pure).
use http::{HeaderMap, header};

fn strip_weak(t: &str) -> &str {
    t.trim().strip_prefix("W/").unwrap_or(t.trim())
}

/// `true` when the client already holds the stored representation (answer 304).
pub fn not_modified(req: &HeaderMap, stored: &HeaderMap) -> bool {
    if let Some(inm) = req.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        let etag = stored
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(strip_weak);
        return inm.trim() == "*" || etag.is_some_and(|e| inm.split(',').any(|t| strip_weak(t) == e));
    }
    let ims = req
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| httpdate::parse_http_date(v).ok());
    let lm = stored
        .get(header::LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| httpdate::parse_http_date(v).ok());
    matches!((ims, lm), (Some(i), Some(l)) if i >= l)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderName, HeaderValue};

    fn hm(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn inm_weak_match() {
        let stored = hm(&[("etag", "\"abc\"")]);
        assert!(not_modified(&hm(&[("if-none-match", "W/\"abc\"")]), &stored));
        assert!(not_modified(&hm(&[("if-none-match", "\"x\", \"abc\"")]), &stored));
        assert!(!not_modified(&hm(&[("if-none-match", "\"x\"")]), &stored));
        assert!(!not_modified(&hm(&[("if-none-match", "\"abc\"")]), &hm(&[])));
    }

    #[test]
    fn inm_star() {
        assert!(not_modified(&hm(&[("if-none-match", "*")]), &hm(&[])));
    }

    #[test]
    fn ims_not_modified() {
        let stored = hm(&[("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")]);
        assert!(not_modified(
            &hm(&[("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT")]),
            &stored
        ));
        assert!(not_modified(
            &hm(&[("if-modified-since", "Thu, 22 Oct 2015 07:28:00 GMT")]),
            &stored
        ));
        assert!(!not_modified(
            &hm(&[("if-modified-since", "Tue, 20 Oct 2015 07:28:00 GMT")]),
            &stored
        ));
        assert!(!not_modified(&hm(&[("if-modified-since", "garbage")]), &stored));
    }

    #[test]
    fn inm_takes_precedence_over_ims() {
        let stored = hm(&[
            ("etag", "\"a\""),
            ("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ]);
        let req = hm(&[
            ("if-none-match", "\"b\""),
            ("if-modified-since", "Thu, 22 Oct 2015 07:28:00 GMT"),
        ]);
        assert!(!not_modified(&req, &stored));
    }
}
