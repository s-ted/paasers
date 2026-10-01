//! Cache key and `Vary` matching (pure).
use http::{HeaderMap, HeaderName, HeaderValue, header};

/// `host + path_and_query`, GET and HEAD share the key.
pub fn primary(host: &str, uri: &http::Uri) -> String {
    format!("{host}{}", uri.path_and_query().map_or("/", |p| p.as_str()))
}

pub type VaryList = Vec<(HeaderName, Option<HeaderValue>)>;

/// Records the request values of every header named in the response `Vary`.
pub fn vary_from(resp: &HeaderMap, req: &HeaderMap) -> VaryList {
    resp.get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().to_ascii_lowercase().as_bytes()).ok())
        .map(|n| {
            let v = req.get(&n).cloned();
            (n, v)
        })
        .collect()
}

/// An entry matches only if every recorded value equals the new request's value.
pub fn vary_matches(recorded: &VaryList, req: &HeaderMap) -> bool {
    recorded.iter().all(|(n, v)| req.get(n) == v.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn primary_key_includes_query() {
        assert_eq!(primary("a.com", &"/x?y=1".parse().unwrap()), "a.com/x?y=1");
        assert_eq!(primary("a.com", &"http://h".parse().unwrap()), "a.com/");
    }

    #[test]
    fn vary_match_and_mismatch() {
        let resp = hm(&[("vary", "Accept-Language, X-Other")]);
        let rec = vary_from(&resp, &hm(&[("accept-language", "fr")]));
        assert_eq!(rec.len(), 2);
        assert!(vary_matches(&rec, &hm(&[("accept-language", "fr")])));
        assert!(!vary_matches(&rec, &hm(&[("accept-language", "en")])));
        assert!(!vary_matches(
            &rec,
            &hm(&[("accept-language", "fr"), ("x-other", "1")])
        ));
        assert!(vary_matches(
            &vary_from(&HeaderMap::new(), &HeaderMap::new()),
            &hm(&[("a", "b")])
        ));
    }
}
