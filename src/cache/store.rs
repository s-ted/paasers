//! In-memory HTTP cache (weighted in bytes), purge by tag/host/prefix and the per-route registry.
use super::key::VaryList;
use crate::config::{CacheCfg, UpstreamCfg};
use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use quick_cache::{Weighter, sync::Cache};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

pub struct Entry {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub stored_at: Instant,
    pub initial_age: u64,
    pub ttl: u64,
    pub swr: u64,
    pub sie: u64,
    pub must_revalidate: bool,
    pub auth_ok: bool,
    pub vary: VaryList,
    pub tags: Box<[String]>,
    pub host: String,
    /// Path and query.
    pub path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Fresh,
    StaleSwr,
    StaleSie,
    Expired,
}

impl Entry {
    pub fn age(&self) -> u64 {
        self.initial_age + self.stored_at.elapsed().as_secs()
    }

    pub fn state(&self) -> State {
        let age = self.age();
        if age < self.ttl {
            State::Fresh
        } else if age < self.ttl + self.swr {
            State::StaleSwr
        } else if age < self.ttl + self.sie {
            State::StaleSie
        } else {
            State::Expired
        }
    }
}

#[derive(Clone)]
pub struct Weigh;

impl Weighter<String, Arc<Entry>> for Weigh {
    fn weight(&self, k: &String, v: &Arc<Entry>) -> u64 {
        (k.len() + v.body.len() + v.headers.len() * 64 + 256) as u64
    }
}

#[derive(Debug, Default, Clone)]
pub struct Purge {
    pub tags: Vec<String>,
    pub host: Option<String>,
    pub path_prefix: Option<String>,
    pub all: bool,
}

impl Purge {
    fn has_criteria(&self) -> bool {
        self.all || !self.tags.is_empty() || self.host.is_some() || self.path_prefix.is_some()
    }

    fn matches(&self, e: &Entry) -> bool {
        (self.tags.is_empty() || e.tags.iter().any(|t| self.tags.contains(t)))
            && self.host.as_ref().is_none_or(|h| *h == e.host)
            && self.path_prefix.as_ref().is_none_or(|p| e.path.starts_with(p))
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheStats {
    pub entries: usize,
    pub weight_bytes: u64,
    pub capacity_bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub stale: u64,
    pub bypass: u64,
}

pub struct HttpCache {
    store: Cache<String, Arc<Entry>, Weigh>,
    revalidating: Mutex<HashSet<String>>,
    pub cfg: CacheCfg,
    hits: AtomicU64,
    misses: AtomicU64,
    stale: AtomicU64,
    bypass: AtomicU64,
}

impl HttpCache {
    pub fn new(cfg: &CacheCfg) -> Self {
        let items = usize::try_from(cfg.max_size / 16_384).unwrap_or(1024).max(1024);
        Self {
            store: Cache::with_weighter(items, cfg.max_size, Weigh),
            revalidating: Mutex::new(HashSet::new()),
            cfg: cfg.clone(),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            stale: AtomicU64::new(0),
            bypass: AtomicU64::new(0),
        }
    }

    pub fn get(&self, key: &str) -> Option<Arc<Entry>> {
        self.store.get(key)
    }

    pub fn insert(&self, key: String, e: Entry) {
        self.store.insert(key, Arc::new(e));
    }

    pub fn remove(&self, key: &str) {
        self.store.remove(key);
    }

    /// `true` if the caller won the right to revalidate this key (one revalidation per key).
    pub fn begin_revalidation(&self, key: &str) -> bool {
        self.revalidating
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.to_string())
    }

    pub fn end_revalidation(&self, key: &str) {
        self.revalidating
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
    }

    pub fn count(&self, status: &str) {
        let c = match status {
            "HIT" => &self.hits,
            "STALE" => &self.stale,
            "BYPASS" => &self.bypass,
            _ => &self.misses,
        };
        c.fetch_add(1, Relaxed);
    }

    /// Removes matching entries and returns how many were removed. No criterion: nothing is purged.
    pub fn purge(&self, p: &Purge) -> usize {
        if !p.has_criteria() {
            return 0;
        }
        if p.all {
            let n = self.store.len();
            self.store.clear();
            return n;
        }
        let removed = AtomicUsize::new(0);
        self.store.retain(|_, e| {
            let hit = p.matches(e);
            if hit {
                removed.fetch_add(1, Relaxed);
            }
            !hit
        });
        removed.load(Relaxed)
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entries: self.store.len(),
            weight_bytes: self.store.weight(),
            capacity_bytes: self.store.capacity(),
            hits: self.hits.load(Relaxed),
            misses: self.misses.load(Relaxed),
            stale: self.stale.load(Relaxed),
            bypass: self.bypass.load(Relaxed),
        }
    }
}

type RegistryEntry = (CacheCfg, Vec<UpstreamCfg>, Arc<HttpCache>);

/// Keeps one cache per route across reloads, unless its cache config or upstreams changed.
#[derive(Default)]
pub struct CacheRegistry {
    inner: Mutex<HashMap<Arc<str>, RegistryEntry>>,
}

impl CacheRegistry {
    pub fn get_or_create(
        &self,
        route: &Arc<str>,
        cfg: &CacheCfg,
        upstreams: &[UpstreamCfg],
    ) -> Arc<HttpCache> {
        let mut m = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((c, u, cache)) = m.get(route)
            && c == cfg
            && u == upstreams
        {
            return cache.clone();
        }
        let cache = Arc::new(HttpCache::new(cfg));
        m.insert(route.clone(), (cfg.clone(), upstreams.to_vec(), cache.clone()));
        cache
    }

    pub fn get(&self, route: &str) -> Option<Arc<HttpCache>> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(route)
            .map(|e| e.2.clone())
    }

    pub fn retain(&self, active: &HashSet<Arc<str>>) {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|k, _| active.contains(k));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    pub fn cfg(max: u64) -> CacheCfg {
        CacheCfg {
            max_size: max,
            stale_while_revalidate: Duration::ZERO,
            stale_if_error: Duration::ZERO,
            default_ttl: Duration::ZERO,
            max_object_size: max,
        }
    }

    pub fn entry(host: &str, path: &str, tags: &[&str], body: usize) -> Entry {
        Entry {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from(vec![0u8; body]),
            stored_at: Instant::now(),
            initial_age: 0,
            ttl: 60,
            swr: 0,
            sie: 0,
            must_revalidate: false,
            auth_ok: false,
            vary: Vec::new(),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            host: host.into(),
            path: path.into(),
        }
    }

    fn filled() -> HttpCache {
        let c = HttpCache::new(&cfg(1 << 20));
        c.insert("a.com/x/1".into(), entry("a.com", "/x/1", &["t1", "t2"], 10));
        c.insert("a.com/y".into(), entry("a.com", "/y", &["t2"], 10));
        c.insert("b.com/x/1".into(), entry("b.com", "/x/1", &[], 10));
        c
    }

    #[test]
    fn purge_by_tag() {
        let c = filled();
        assert_eq!(
            c.purge(&Purge {
                tags: vec!["t2".into()],
                ..Purge::default()
            }),
            2
        );
        assert!(c.get("b.com/x/1").is_some() && c.get("a.com/y").is_none());
    }

    #[test]
    fn purge_by_host_prefix() {
        let c = filled();
        let p = Purge {
            host: Some("a.com".into()),
            path_prefix: Some("/x".into()),
            ..Purge::default()
        };
        assert_eq!(c.purge(&p), 1);
        assert!(c.get("a.com/y").is_some() && c.get("a.com/x/1").is_none());
    }

    #[test]
    fn purge_all_counts() {
        let c = filled();
        assert_eq!(
            c.purge(&Purge {
                all: true,
                ..Purge::default()
            }),
            3
        );
        assert_eq!(c.stats().entries, 0);
    }

    #[test]
    fn purge_no_criteria_noop() {
        let c = filled();
        assert_eq!(c.purge(&Purge::default()), 0);
        assert_eq!(c.stats().entries, 3);
    }

    #[test]
    fn weight_limits_capacity() {
        let c = HttpCache::new(&cfg(10_000));
        for i in 0..200 {
            c.insert(format!("h/{i}"), entry("h", "/", &[], 500));
        }
        let s = c.stats();
        assert!(s.weight_bytes <= s.capacity_bytes, "{s:?}");
        assert!(s.entries < 200);
    }

    #[test]
    fn revalidation_is_exclusive_per_key() {
        let c = HttpCache::new(&cfg(1000));
        assert!(c.begin_revalidation("k"));
        assert!(!c.begin_revalidation("k"));
        c.end_revalidation("k");
        assert!(c.begin_revalidation("k"));
    }

    #[test]
    fn entry_states() {
        let mut e = entry("h", "/", &[], 1);
        e.ttl = 10;
        e.swr = 5;
        e.sie = 20;
        assert_eq!(e.state(), State::Fresh);
        e.initial_age = 12;
        assert_eq!(e.state(), State::StaleSwr);
        e.initial_age = 17;
        assert_eq!(e.state(), State::StaleSie);
        e.initial_age = 40;
        assert_eq!(e.state(), State::Expired);
    }

    #[test]
    fn cache_reset_when_upstreams_change() {
        let r = CacheRegistry::default();
        let route: Arc<str> = Arc::from("a.com");
        let up = |p: u16| {
            vec![UpstreamCfg {
                addr: format!("10.0.0.1:{p}").parse().unwrap(),
                weight: 1,
            }]
        };
        let c1 = r.get_or_create(&route, &cfg(1000), &up(80));
        assert!(Arc::ptr_eq(&c1, &r.get_or_create(&route, &cfg(1000), &up(80))));
        assert!(!Arc::ptr_eq(&c1, &r.get_or_create(&route, &cfg(1000), &up(81))));
        let c3 = r.get_or_create(&route, &cfg(1000), &up(81));
        assert!(!Arc::ptr_eq(&c3, &r.get_or_create(&route, &cfg(2000), &up(81))));
        r.retain(&HashSet::new());
        assert!(r.get("a.com").is_none());
    }
}

/// Test helper: `Entry` is intentionally not `Clone` (it lives behind an `Arc`).
#[cfg(test)]
pub mod tests_support {
    use super::*;

    pub fn clone_entry(e: &Entry) -> Entry {
        Entry {
            status: e.status,
            headers: e.headers.clone(),
            body: e.body.clone(),
            stored_at: e.stored_at,
            initial_age: e.initial_age,
            ttl: e.ttl,
            swr: e.swr,
            sie: e.sie,
            must_revalidate: e.must_revalidate,
            auth_ok: e.auth_ok,
            vary: e.vary.clone(),
            tags: e.tags.clone(),
            host: e.host.clone(),
            path: e.path.clone(),
        }
    }
}
