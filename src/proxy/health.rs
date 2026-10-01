//! Upstream health state, probes and the registry that keeps state across reloads.
use super::client::UpstreamClient;
use crate::config::{HealthCfg, HealthMode};
use crate::prelude::empty;
use crate::storage::now_unix;
use http_body_util::{BodyExt, Limited};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering::Relaxed};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub struct UpstreamHealth {
    pub addr: SocketAddr,
    healthy: AtomicBool,
    /// When no active probe runs, passive failures are ignored (nothing could make the upstream healthy again).
    active: AtomicBool,
    consecutive_fail: AtomicU32,
    consecutive_ok: AtomicU32,
    last_change_unix: AtomicI64,
    last_error: Mutex<Option<String>>,
}

impl UpstreamHealth {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            healthy: AtomicBool::new(true),
            active: AtomicBool::new(true),
            consecutive_fail: AtomicU32::new(0),
            consecutive_ok: AtomicU32::new(0),
            last_change_unix: AtomicI64::new(now_unix()),
            last_error: Mutex::new(None),
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Relaxed)
    }

    pub fn last_change_unix(&self) -> i64 {
        self.last_change_unix.load(Relaxed)
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set_active(&self, active: bool) {
        self.active.store(active, Relaxed);
    }

    fn switch(&self, healthy: bool) -> bool {
        let changed = self.healthy.swap(healthy, Relaxed) != healthy;
        if changed {
            self.last_change_unix.store(now_unix(), Relaxed);
        }
        changed
    }

    /// Connection error seen by the proxy: instant removal from rotation.
    pub fn report_failure_passive(&self) {
        if !self.active.load(Relaxed) {
            return;
        }
        self.consecutive_ok.store(0, Relaxed);
        if self.switch(false) {
            tracing::warn!(upstream = %self.addr, "upstream unhealthy (passive)");
        }
    }

    pub fn report_success_passive(&self) {
        if self.is_healthy() {
            self.consecutive_fail.store(0, Relaxed);
        }
    }

    /// Records one active probe result and applies the thresholds.
    pub fn record_probe(&self, result: Result<(), String>, cfg: &HealthCfg) {
        match result {
            Ok(()) => {
                self.consecutive_fail.store(0, Relaxed);
                let ok = self.consecutive_ok.fetch_add(1, Relaxed) + 1;
                if !self.is_healthy() && ok >= cfg.healthy_after && self.switch(true) {
                    tracing::info!(upstream = %self.addr, "upstream healthy");
                }
            }
            Err(msg) => {
                self.consecutive_ok.store(0, Relaxed);
                let fails = self.consecutive_fail.fetch_add(1, Relaxed) + 1;
                *self.last_error.lock().unwrap_or_else(PoisonError::into_inner) = Some(msg.clone());
                if self.is_healthy() && fails >= cfg.unhealthy_after && self.switch(false) {
                    tracing::warn!(upstream = %self.addr, error = %msg, "upstream unhealthy");
                }
            }
        }
    }
}

/// One probe. HTTP: any status below 500 is healthy. TCP: the connection must open.
pub async fn probe(client: &UpstreamClient, addr: SocketAddr, cfg: &HealthCfg) -> Result<(), String> {
    let work = async {
        match cfg.mode {
            HealthMode::Tcp => tokio::net::TcpStream::connect(addr)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            HealthMode::Http => {
                let req = http::Request::builder()
                    .uri(format!("http://{addr}{}", cfg.path))
                    .header(http::header::HOST, addr.to_string())
                    .header(http::header::USER_AGENT, "paasers-health/1")
                    .body(empty())
                    .map_err(|e| e.to_string())?;
                let resp = client.request(req).await.map_err(|e| e.to_string())?;
                let status = resp.status();
                let _ = Limited::new(resp.into_body(), 64 * 1024).collect().await;
                if status.as_u16() < 500 {
                    Ok(())
                } else {
                    Err(format!("status {status}"))
                }
            }
        }
    };
    tokio::time::timeout(cfg.timeout, work)
        .await
        .unwrap_or_else(|_| Err("probe timed out".into()))
}

async fn checker(
    health: Arc<UpstreamHealth>,
    client: UpstreamClient,
    cfg: HealthCfg,
    cancel: CancellationToken,
) {
    let jitter = rand::random_range(0..u64::try_from(cfg.interval.as_millis()).unwrap_or(1000).max(1));
    tokio::select! {
        () = cancel.cancelled() => return,
        () = tokio::time::sleep(Duration::from_millis(jitter)) => {}
    }
    let mut tick = tokio::time::interval(cfg.interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            _ = tick.tick() => {}
        }
        let r = probe(&client, health.addr, &cfg).await;
        health.record_probe(r, &cfg);
    }
}

struct Entry {
    health: Arc<UpstreamHealth>,
    checker: Option<(HealthCfg, CancellationToken)>,
}

/// Shared by all routes and kept across reloads, so health state survives a rebuild.
pub struct HealthRegistry {
    inner: Mutex<HashMap<SocketAddr, Entry>>,
    root: CancellationToken,
}

impl Default for HealthRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthRegistry {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            root: CancellationToken::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SocketAddr, Entry>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn get_or_create(&self, addr: SocketAddr) -> Arc<UpstreamHealth> {
        let mut m = self.lock();
        m.entry(addr)
            .or_insert_with(|| Entry {
                health: Arc::new(UpstreamHealth::new(addr)),
                checker: None,
            })
            .health
            .clone()
    }

    pub fn get(&self, addr: SocketAddr) -> Option<Arc<UpstreamHealth>> {
        self.lock().get(&addr).map(|e| e.health.clone())
    }

    /// Starts (or restarts, if the config changed) the active checker of `addr`.
    /// The first route declaring an address decides its probe configuration.
    pub fn ensure_checker(&self, addr: SocketAddr, cfg: &HealthCfg, client: &UpstreamClient) {
        let health = self.get_or_create(addr);
        health.set_active(cfg.enabled);
        let mut m = self.lock();
        let Some(entry) = m.get_mut(&addr) else { return };
        if entry.checker.as_ref().is_some_and(|(c, _)| c == cfg) {
            return;
        }
        if let Some((_, old)) = entry.checker.take() {
            old.cancel();
        }
        if !cfg.enabled {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let token = self.root.child_token();
        handle.spawn(checker(health, client.clone(), cfg.clone(), token.clone()));
        entry.checker = Some((cfg.clone(), token));
    }

    /// Drops state and stops checkers of upstreams that are no longer configured.
    pub fn retain(&self, active: &HashSet<SocketAddr>) {
        self.lock().retain(|addr, e| {
            let keep = active.contains(addr);
            if !keep && let Some((_, t)) = &e.checker {
                t.cancel();
            }
            keep
        });
    }

    pub fn shutdown(&self) {
        self.root.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HealthCfg {
        HealthCfg {
            unhealthy_after: 2,
            healthy_after: 2,
            ..HealthCfg::default()
        }
    }

    fn up() -> UpstreamHealth {
        UpstreamHealth::new("127.0.0.1:1".parse().unwrap())
    }

    #[test]
    fn passive_failure_marks_unhealthy_immediately() {
        let h = up();
        assert!(h.is_healthy());
        h.report_failure_passive();
        assert!(!h.is_healthy());
    }

    #[test]
    fn recovers_after_healthy_after_successes() {
        let h = up();
        h.report_failure_passive();
        h.report_success_passive();
        assert!(!h.is_healthy(), "passive success must not rehabilitate");
        h.record_probe(Ok(()), &cfg());
        assert!(!h.is_healthy());
        h.record_probe(Ok(()), &cfg());
        assert!(h.is_healthy());
    }

    #[test]
    fn active_failures_need_threshold_and_record_error() {
        let h = up();
        h.record_probe(Err("boom".into()), &cfg());
        assert!(h.is_healthy());
        h.record_probe(Err("boom".into()), &cfg());
        assert!(!h.is_healthy());
        assert_eq!(h.last_error().as_deref(), Some("boom"));
        h.record_probe(Ok(()), &cfg());
        h.record_probe(Err("x".into()), &cfg());
        assert!(!h.is_healthy(), "a failure resets the success streak");
    }

    #[test]
    fn passive_ignored_when_active_disabled() {
        let h = up();
        h.set_active(false);
        h.report_failure_passive();
        assert!(h.is_healthy());
    }

    #[test]
    fn registry_reuses_state_and_retains() {
        let r = HealthRegistry::new();
        let a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let h1 = r.get_or_create(a);
        h1.report_failure_passive();
        r.get_or_create(b);
        assert!(Arc::ptr_eq(&h1, &r.get_or_create(a)));
        r.retain(&HashSet::from([a]));
        assert!(r.get(b).is_none() && r.get(a).is_some());
    }

    #[tokio::test]
    async fn tcp_probe_detects_open_and_closed_port() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let c = HealthCfg {
            mode: HealthMode::Tcp,
            ..HealthCfg::default()
        };
        let client = super::super::client::new_client();
        assert!(probe(&client, addr, &c).await.is_ok());
        drop(l);
        assert!(probe(&client, addr, &c).await.is_err());
    }
}
