//! `Cache-Control` parsing, freshness lifetime and the "storable" decision (pure).
use crate::config::CacheCfg;
use http::{HeaderMap, StatusCode, header};
use std::time::{Duration, SystemTime};

#[derive(Default, Debug, PartialEq, Eq)]
pub struct CacheControl {
    pub no_store: bool,
    pub no_cache: bool,
    pub private: bool,
    pub public: bool,
    pub max_age: Option<u64>,
    pub s_maxage: Option<u64>,
    pub must_revalidate: bool,
    pub proxy_revalidate: bool,
    pub swr: Option<u64>,
    pub sie: Option<u64>,
}

/// Merges every `Cache-Control` header. Invalid numbers and unknown directives are ignored.
pub fn parse_cc(h: &HeaderMap) -> CacheControl {
    let mut cc = CacheControl::default();
    for d in h
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
    {
        let d = d.trim();
        let (name, val) = match d.split_once('=') {
            Some((n, v)) => (n.trim(), Some(v.trim().trim_matches('"'))),
            None => (d, None),
        };
        let num = val.and_then(|v| v.parse::<u64>().ok());
        match name.to_ascii_lowercase().as_str() {
            "no-store" => cc.no_store = true,
            "no-cache" => cc.no_cache = true,
            "private" => cc.private = true,
            "public" => cc.public = true,
            "must-revalidate" => cc.must_revalidate = true,
            "proxy-revalidate" => cc.proxy_revalidate = true,
            "max-age" => cc.max_age = num.or(cc.max_age),
            "s-maxage" => cc.s_maxage = num.or(cc.s_maxage),
            "stale-while-revalidate" => cc.swr = num.or(cc.swr),
            "stale-if-error" => cc.sie = num.or(cc.sie),
            _ => {}
        }
    }
    cc
}

/// Inputs of the storable decision that do not come from response headers.
pub struct Ctx {
    pub is_get: bool,
    /// The request carried `Authorization` or `Cookie`.
    pub sensitive: bool,
    pub has_proxy_failure: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Freshness {
    pub ttl: u64,
    pub swr: u64,
    pub sie: u64,
    pub must_revalidate: bool,
    pub auth_ok: bool,
}

fn secs_between(expires: &str, date: Option<&str>) -> Option<u64> {
    let e = httpdate::parse_http_date(expires).ok()?;
    let d = match date {
        Some(d) => httpdate::parse_http_date(d).ok()?,
        None => SystemTime::now(),
    };
    Some(e.duration_since(d).map_or(0, |x: Duration| x.as_secs()))
}

const STORABLE_STATUS: &[u16] = &[200, 203, 204, 300, 301, 308, 404, 410];

/// `Some(freshness)` when the response may be stored, `None` otherwise (RFC 9111 subset, shared cache).
pub fn storable(status: StatusCode, h: &HeaderMap, ctx: &Ctx, cfg: &CacheCfg) -> Option<Freshness> {
    let cc = parse_cc(h);
    let vary_star = h
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.split(',').any(|t| t.trim() == "*"));
    let too_big = h
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > cfg.max_object_size);
    if !ctx.is_get
        || ctx.has_proxy_failure
        || !STORABLE_STATUS.contains(&status.as_u16())
        || cc.no_store
        || cc.no_cache
        || cc.private
        || h.contains_key(header::SET_COOKIE)
        || vary_star
        || h.contains_key(header::CONTENT_RANGE)
        || too_big
    {
        return None;
    }
    if ctx.sensitive && !(cc.public || cc.s_maxage.is_some()) {
        return None;
    }
    let from_expires = h
        .get(header::EXPIRES)
        .and_then(|v| v.to_str().ok())
        .and_then(|e| secs_between(e, h.get(header::DATE).and_then(|v| v.to_str().ok())));
    let ttl = cc
        .s_maxage
        .or(cc.max_age)
        .or(from_expires)
        .unwrap_or(cfg.default_ttl.as_secs());
    if ttl == 0 {
        return None;
    }
    let must_revalidate = cc.must_revalidate || cc.proxy_revalidate;
    let pick = |own: Option<u64>, cfgv: Duration| {
        if must_revalidate {
            0
        } else {
            own.unwrap_or(cfgv.as_secs())
        }
    };
    Some(Freshness {
        ttl,
        swr: pick(cc.swr, cfg.stale_while_revalidate),
        sie: pick(cc.sie, cfg.stale_if_error),
        must_revalidate,
        auth_ok: ctx.sensitive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn cfg() -> CacheCfg {
        CacheCfg {
            max_size: 1 << 20,
            stale_while_revalidate: Duration::ZERO,
            stale_if_error: Duration::ZERO,
            default_ttl: Duration::ZERO,
            max_object_size: 1024,
        }
    }

    fn hm(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(http::HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        h
    }

    const GET: Ctx = Ctx {
        is_get: true,
        sensitive: false,
        has_proxy_failure: false,
    };

    fn ok(h: &[(&'static str, &'static str)]) -> Option<Freshness> {
        storable(StatusCode::OK, &hm(h), &GET, &cfg())
    }

    #[test]
    fn parse_multiple_headers_and_quotes() {
        let cc = parse_cc(&hm(&[
            ("cache-control", "Public, MAX-AGE=\"60\""),
            ("cache-control", "s-maxage=5, no-cache"),
        ]));
        assert!(cc.public && cc.no_cache);
        assert_eq!((cc.max_age, cc.s_maxage), (Some(60), Some(5)));
    }

    #[test]
    fn invalid_number_ignored() {
        let cc = parse_cc(&hm(&[(
            "cache-control",
            "max-age=abc, stale-while-revalidate=-1, wat, max-age",
        )]));
        assert_eq!(cc, CacheControl::default());
    }

    #[test]
    fn ttl_precedence_smaxage_maxage_expires_default() {
        assert_eq!(
            ok(&[("cache-control", "max-age=10, s-maxage=20")]).unwrap().ttl,
            20
        );
        assert_eq!(
            ok(&[
                ("cache-control", "max-age=10"),
                ("expires", "Wed, 21 Oct 2037 07:28:00 GMT")
            ])
            .unwrap()
            .ttl,
            10
        );
        let e = ok(&[
            ("expires", "Thu, 01 Jan 1970 00:01:40 GMT"),
            ("date", "Thu, 01 Jan 1970 00:00:00 GMT"),
        ])
        .unwrap();
        assert_eq!(e.ttl, 100);
        assert!(
            ok(&[
                ("expires", "Thu, 01 Jan 1970 00:00:00 GMT"),
                ("date", "Thu, 01 Jan 1970 00:01:40 GMT")
            ])
            .is_none()
        );
        assert!(ok(&[]).is_none(), "no explicit freshness and default-ttl 0");
        let c = CacheCfg {
            default_ttl: Duration::from_secs(7),
            ..cfg()
        };
        assert_eq!(storable(StatusCode::OK, &hm(&[]), &GET, &c).unwrap().ttl, 7);
    }

    #[test]
    fn not_storable_cases() {
        let fresh = ("cache-control", "max-age=60");
        assert!(ok(&[fresh]).is_some());
        assert!(
            storable(
                StatusCode::OK,
                &hm(&[fresh]),
                &Ctx { is_get: false, ..GET },
                &cfg()
            )
            .is_none()
        );
        assert!(
            storable(
                StatusCode::OK,
                &hm(&[fresh]),
                &Ctx {
                    has_proxy_failure: true,
                    ..GET
                },
                &cfg()
            )
            .is_none()
        );
        for s in [201, 206, 302, 400, 500, 502] {
            assert!(
                storable(StatusCode::from_u16(s).unwrap(), &hm(&[fresh]), &GET, &cfg()).is_none(),
                "{s}"
            );
        }
        for s in [200, 203, 204, 300, 301, 308, 404, 410] {
            assert!(
                storable(StatusCode::from_u16(s).unwrap(), &hm(&[fresh]), &GET, &cfg()).is_some(),
                "{s}"
            );
        }
        for cc in [
            "max-age=60, no-store",
            "max-age=60, no-cache",
            "max-age=60, private",
        ] {
            let h: &'static str = cc;
            assert!(ok(&[("cache-control", h)]).is_none(), "{cc}");
        }
        assert!(ok(&[fresh, ("set-cookie", "a=b")]).is_none());
        assert!(ok(&[fresh, ("vary", "Accept, *")]).is_none());
        assert!(ok(&[fresh, ("content-range", "bytes 0-1/2")]).is_none());
        assert!(ok(&[fresh, ("content-length", "1025")]).is_none());
        assert!(ok(&[fresh, ("content-length", "1024")]).is_some());
    }

    #[test]
    fn sensitive_requires_public() {
        let s = Ctx {
            sensitive: true,
            ..GET
        };
        let st = |h: &[(&'static str, &'static str)]| storable(StatusCode::OK, &hm(h), &s, &cfg());
        assert!(st(&[("cache-control", "max-age=60")]).is_none());
        assert!(st(&[("cache-control", "public, max-age=60")]).unwrap().auth_ok);
        assert!(st(&[("cache-control", "s-maxage=60")]).unwrap().auth_ok);
    }

    #[test]
    fn must_revalidate_disables_stale() {
        let c = CacheCfg {
            stale_while_revalidate: Duration::from_secs(30),
            stale_if_error: Duration::from_secs(60),
            ..cfg()
        };
        let f = storable(StatusCode::OK, &hm(&[("cache-control", "max-age=5")]), &GET, &c).unwrap();
        assert_eq!((f.swr, f.sie), (30, 60));
        let f = storable(
            StatusCode::OK,
            &hm(&[("cache-control", "max-age=5, must-revalidate")]),
            &GET,
            &c,
        )
        .unwrap();
        assert_eq!((f.swr, f.sie, f.must_revalidate), (0, 0, true));
        let f = storable(
            StatusCode::OK,
            &hm(&[("cache-control", "max-age=5, stale-while-revalidate=2")]),
            &GET,
            &c,
        )
        .unwrap();
        assert_eq!(f.swr, 2, "response directive overrides config");
    }
}
