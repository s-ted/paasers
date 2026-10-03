//! Flight recorder: bounded ring buffer of incidents, queried by trace id (Incident ID) or filters.
use rmcp::schemars;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

const DETAIL_MAX: usize = 512;
const UA_MAX: usize = 256;
const QUERY_LIMIT_DEFAULT: usize = 50;
const QUERY_LIMIT_MAX: usize = 500;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Incident {
    /// 32 hex characters, equal to the Incident ID shown to users.
    pub trace_id: String,
    pub ts: String,
    pub ts_unix_ms: u64,
    pub kind: &'static str,
    pub status: Option<u16>,
    pub method: Option<String>,
    pub host: Option<String>,
    /// Path without the query string, so that secrets in queries never reach the recorder.
    pub path: Option<String>,
    pub route_id: Option<String>,
    pub client_ip: Option<String>,
    pub upstream: Option<String>,
    pub duration_ms: Option<u64>,
    pub detail: Option<String>,
    pub user_agent: Option<String>,
}

/// Truncates on a char boundary.
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let end = (0..=max).rev().find(|i| s.is_char_boundary(*i)).unwrap_or(0);
    s.get(..end).unwrap_or("").to_string()
}

impl Incident {
    /// New incident stamped with the current time.
    pub fn new(trace_id: String, kind: &'static str) -> Self {
        let now = std::time::SystemTime::now();
        let ms = now
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
        Self {
            trace_id,
            ts: humantime::format_rfc3339_millis(now).to_string(),
            ts_unix_ms: ms,
            kind,
            ..Self::default()
        }
    }

    pub fn with_detail(mut self, d: &str) -> Self {
        self.detail = Some(truncate(d, DETAIL_MAX));
        self
    }

    pub fn with_user_agent(mut self, ua: &str) -> Self {
        self.user_agent = Some(truncate(ua, UA_MAX));
        self
    }
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct Query {
    pub limit: Option<usize>,
    pub status_min: Option<u16>,
    pub status_max: Option<u16>,
    pub host: Option<String>,
    pub route_id: Option<String>,
    pub kind: Option<String>,
    pub since_unix_ms: Option<u64>,
    pub path_prefix: Option<String>,
}

impl Query {
    fn matches(&self, i: &Incident) -> bool {
        let eq = |want: &Option<String>, have: &Option<String>| {
            want.as_ref().is_none_or(|w| have.as_deref() == Some(w))
        };
        self.status_min.is_none_or(|m| i.status.is_some_and(|s| s >= m))
            && self.status_max.is_none_or(|m| i.status.is_some_and(|s| s <= m))
            && eq(&self.host, &i.host)
            && eq(&self.route_id, &i.route_id)
            && self.kind.as_deref().is_none_or(|k| i.kind == k)
            && self.since_unix_ms.is_none_or(|t| i.ts_unix_ms >= t)
            && self
                .path_prefix
                .as_deref()
                .is_none_or(|p| i.path.as_deref().is_some_and(|x| x.starts_with(p)))
    }
}

pub struct FlightRecorder {
    inner: Mutex<VecDeque<Arc<Incident>>>,
    capacity: usize,
    total: AtomicU64,
}

impl FlightRecorder {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            capacity,
            total: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<Arc<Incident>>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn record(&self, i: Incident) {
        // Capacity 0 is `flight-recorder off`.
        if self.capacity == 0 {
            return;
        }
        let mut q = self.lock();
        q.push_back(Arc::new(i));
        while q.len() > self.capacity {
            q.pop_front();
        }
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    /// All entries of one trace, in chronological order.
    pub fn get(&self, trace_id: &str) -> Vec<Arc<Incident>> {
        self.lock()
            .iter()
            .filter(|i| i.trace_id == trace_id)
            .cloned()
            .collect()
    }

    /// Most recent first, at most `limit` entries (default 50, max 500).
    pub fn query(&self, q: &Query) -> Vec<Arc<Incident>> {
        let limit = q.limit.unwrap_or(QUERY_LIMIT_DEFAULT).min(QUERY_LIMIT_MAX);
        self.lock()
            .iter()
            .rev()
            .filter(|i| q.matches(i))
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inc(id: &str, status: u16, host: &str, path: &str) -> Incident {
        let mut i = Incident::new(id.into(), "http");
        i.status = Some(status);
        i.host = Some(host.into());
        i.path = Some(path.into());
        i
    }

    #[test]
    fn capacity_evicts_oldest() {
        let r = FlightRecorder::new(3);
        (0..5).for_each(|n| r.record(inc(&format!("t{n}"), 500, "a", "/")));
        let ids: Vec<_> = r
            .query(&Query::default())
            .iter()
            .map(|i| i.trace_id.clone())
            .collect();
        assert_eq!(ids, vec!["t4", "t3", "t2"]);
        assert_eq!((r.len(), r.total()), (3, 5));
    }

    #[test]
    fn query_filters_combined() {
        let r = FlightRecorder::new(10);
        r.record(inc("a", 404, "x.com", "/api/1"));
        r.record(inc("b", 502, "x.com", "/api/2"));
        r.record(inc("c", 502, "y.com", "/api/3"));
        let q = Query {
            status_min: Some(500),
            host: Some("x.com".into()),
            path_prefix: Some("/api".into()),
            ..Query::default()
        };
        let got = r.query(&q);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].trace_id, "b");
        let q = Query {
            kind: Some("other".into()),
            ..Query::default()
        };
        assert!(r.query(&q).is_empty());
        let q = Query {
            limit: Some(1),
            ..Query::default()
        };
        assert_eq!(r.query(&q)[0].trace_id, "c");
    }

    #[test]
    fn get_by_trace_id_multiple_entries() {
        let r = FlightRecorder::new(10);
        r.record(inc("t", 502, "a", "/1"));
        r.record(inc("o", 500, "a", "/"));
        r.record(inc("t", 503, "a", "/2"));
        let got = r.get("t");
        assert_eq!(
            got.iter().map(|i| i.path.clone().unwrap()).collect::<Vec<_>>(),
            vec!["/1", "/2"]
        );
        assert!(r.get("missing").is_empty());
    }

    #[test]
    fn limit_capped_500() {
        let r = FlightRecorder::new(1000);
        (0..700).for_each(|n| r.record(inc(&format!("{n}"), 500, "a", "/")));
        assert_eq!(
            r.query(&Query {
                limit: Some(10_000),
                ..Query::default()
            })
            .len(),
            500
        );
        assert_eq!(r.query(&Query::default()).len(), 50);
    }

    #[test]
    fn detail_truncated_on_char_boundary() {
        let i = Incident::new("t".into(), "http").with_detail(&"é".repeat(600));
        let d = i.detail.unwrap();
        assert!(d.len() <= 512 && d.chars().all(|c| c == 'é'));
        assert_eq!(truncate("abc", 10), "abc");
    }
}
