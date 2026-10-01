//! Building responses from cache entries, and entries from responses.
use super::cond::not_modified;
use super::key::{VaryList, primary, vary_from};
use super::policy::Freshness;
use super::store::Entry;
use super::store::HttpCache;
use crate::prelude::{Resp, empty, full};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use std::time::Instant;

const MAX_TAGS: usize = 64;
const MAX_TAG_LEN: usize = 256;
const NOT_STORED: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "set-cookie",
    "surrogate-key",
    "age",
    "x-cache",
];
const NOT_MODIFIED_HEADERS: &[HeaderName] = &[
    header::ETAG,
    header::CACHE_CONTROL,
    header::EXPIRES,
    header::VARY,
    header::LAST_MODIFIED,
    header::DATE,
];

/// Surrogate-Key tags (space separated), bounded in count and size.
pub fn tags_from(h: &HeaderMap) -> Box<[String]> {
    h.get_all("surrogate-key")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(str::split_whitespace)
        .filter(|t| t.len() <= MAX_TAG_LEN)
        .take(MAX_TAGS)
        .map(str::to_string)
        .collect()
}

pub fn storable_headers(h: &HeaderMap) -> HeaderMap {
    let mut out = h.clone();
    NOT_STORED.iter().for_each(|n| {
        out.remove(*n);
    });
    out
}

pub struct Origin<'a> {
    pub host: &'a str,
    pub path: &'a str,
    pub req_headers: &'a HeaderMap,
}

/// Entry without a body yet is not representable, so the body is passed explicitly.
pub fn build_entry(
    status: StatusCode,
    resp_headers: &HeaderMap,
    body: Bytes,
    f: &Freshness,
    o: &Origin<'_>,
) -> Entry {
    let vary: VaryList = vary_from(resp_headers, o.req_headers);
    let initial_age = resp_headers
        .get(header::AGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    Entry {
        status,
        headers: storable_headers(resp_headers),
        body,
        stored_at: Instant::now(),
        initial_age,
        ttl: f.ttl,
        swr: f.swr,
        sie: f.sie,
        must_revalidate: f.must_revalidate,
        auth_ok: f.auth_ok,
        vary,
        tags: tags_from(resp_headers),
        host: o.host.to_string(),
        path: o.path.to_string(),
    }
}

fn set_cache_headers(r: &mut Resp, age: u64, label: &'static str) {
    r.headers_mut().insert(header::AGE, HeaderValue::from(age));
    r.headers_mut().insert("x-cache", HeaderValue::from_static(label));
    r.extensions_mut().insert(crate::prelude::CacheStatus(label));
}

/// Response served from an entry. Client conditionals are evaluated first (304).
pub fn from_entry(e: &Entry, req_headers: &HeaderMap, head: bool, label: &'static str) -> Resp {
    if not_modified(req_headers, &e.headers) {
        let mut r = http::Response::new(empty());
        *r.status_mut() = StatusCode::NOT_MODIFIED;
        for n in NOT_MODIFIED_HEADERS {
            if let Some(v) = e.headers.get(n) {
                r.headers_mut().insert(n.clone(), v.clone());
            }
        }
        set_cache_headers(&mut r, e.age(), label);
        return r;
    }
    let body = if head { empty() } else { full(e.body.clone()) };
    let mut r = http::Response::new(body);
    *r.status_mut() = e.status;
    *r.headers_mut() = e.headers.clone();
    set_cache_headers(&mut r, e.age(), label);
    r
}

/// Merges the headers of a 304 into the stored ones (representation headers are kept).
pub fn merge_304(old: &HeaderMap, fresh: &HeaderMap) -> HeaderMap {
    let mut out = old.clone();
    for (k, v) in storable_headers(fresh).iter() {
        if k != header::CONTENT_LENGTH && k != header::CONTENT_ENCODING {
            out.insert(k.clone(), v.clone());
        }
    }
    out
}

/// Adds `If-None-Match` / `If-Modified-Since` from the stored validators. Returns whether any was added.
pub fn add_validators(req: &mut HeaderMap, stored: &HeaderMap) -> bool {
    let mut added = false;
    for (from, to) in [
        (header::ETAG, header::IF_NONE_MATCH),
        (header::LAST_MODIFIED, header::IF_MODIFIED_SINCE),
    ] {
        if let Some(v) = stored.get(from) {
            req.insert(to, v.clone());
            added = true;
        }
    }
    added
}

fn same_host_key(host: &str, value: Option<&HeaderValue>) -> Option<String> {
    let uri: http::Uri = value?.to_str().ok()?.parse().ok()?;
    match uri.host() {
        Some(h) if !h.eq_ignore_ascii_case(host) => None,
        _ => Some(primary(host, &uri)),
    }
}

/// RFC 9111 §4.4: a successful unsafe request invalidates the target and `Location` / `Content-Location`.
pub fn invalidate(cache: &HttpCache, host: &str, key: &str, resp: &Resp) {
    if !(resp.status().is_success() || resp.status().is_redirection()) {
        return;
    }
    cache.remove(key);
    for h in [header::LOCATION, header::CONTENT_LOCATION] {
        if let Some(k) = same_host_key(host, resp.headers().get(&h)) {
            cache.remove(&k);
        }
    }
}
