//! TLS: SNI certificate resolver, self-signed bootstrap certificates and ACME (HTTP-01) issuance.
pub mod acme;
pub mod challenge;
pub mod local;
pub mod pem;
mod refresh;
pub mod resolver;
pub mod select;
pub mod selfsigned;
mod state;
mod worker;

pub use challenge::ChallengeStore;
pub use resolver::CertResolver;

use crate::config::{Config, TlsCfg, TlsMode};
use crate::observe::{FlightRecorder, Incident, trace};
use crate::storage::{Db, StorageError};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;

pub use state::HostCert;
use state::{HostState, State, TlsRoute};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("pem: {0}")]
    Pem(String),
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("pem file: {0}")]
    PemFile(#[from] rustls_pki_types::pem::Error),
    #[error("acme: {0}")]
    Acme(#[from] instant_acme::Error),
    #[error("certificate generation: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("storage: {0}")]
    Storage(#[from] StorageError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("order: {0}")]
    Order(String),
}

pub struct CertManagerInner {
    pub(crate) db: Db,
    pub(crate) resolver: Arc<CertResolver>,
    pub(crate) challenges: Arc<ChallengeStore>,
    pub(crate) recorder: Arc<FlightRecorder>,
    pub(crate) state: Mutex<State>,
    pub(crate) wake: Notify,
    pub(crate) report: ArcSwap<HashMap<String, HostCert>>,
}

impl CertManagerInner {
    pub(crate) fn incident(&self, kind: &'static str, route: &str, detail: &str) {
        let mut i = Incident::new(trace::trace_hex(trace::nz128()), kind).with_detail(detail);
        i.route_id = Some(route.to_string());
        self.recorder.record(i);
    }
}

#[derive(Clone)]
pub struct CertManager {
    inner: Arc<CertManagerInner>,
}

pub fn server_config(resolver: Arc<CertResolver>) -> Result<rustls::ServerConfig, rustls::Error> {
    let mut c =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
    c.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(c)
}

/// ACME directory URL for a route: `staging` forces Let's Encrypt staging, else the global directory.
pub fn directory_for_route(cfg: &Config, staging: bool) -> String {
    if staging {
        acme::directory_url(&crate::config::AcmeDirectory::Staging)
    } else {
        acme::directory_url(&cfg.gateway.acme_directory)
    }
}

fn tls_routes(cfg: &Config) -> Vec<TlsRoute> {
    cfg.routes
        .iter()
        .filter_map(|r| {
            let TlsCfg { mode } = r.tls.as_ref()?;
            let directory = match mode {
                TlsMode::Auto { acme: Some(a) } => Some(directory_for_route(cfg, a.staging)),
                _ => None,
            };
            Some(TlsRoute {
                id: r.id.clone(),
                hosts: r.hosts.clone(),
                mode: mode.clone(),
                directory,
            })
        })
        .collect()
}

impl CertManager {
    /// Selects the initial certificates and starts the renewal worker.
    pub async fn start(
        cfg: &Config,
        db: Db,
        resolver: Arc<CertResolver>,
        challenges: Arc<ChallengeStore>,
        recorder: Arc<FlightRecorder>,
        shutdown: CancellationToken,
    ) -> Result<Self, TlsError> {
        let inner = Arc::new(CertManagerInner {
            db,
            resolver,
            challenges,
            recorder,
            state: Mutex::new(State {
                gw: cfg.gateway.clone(),
                routes: Vec::new(),
                index: local::LocalIndex::default(),
                hosts: HashMap::new(),
                selfsigned: HashMap::new(),
                temp: HashMap::new(),
            }),
            wake: Notify::new(),
            report: ArcSwap::from_pointee(HashMap::new()),
        });
        let m = Self { inner };
        m.reconcile(cfg).await;
        tokio::spawn(worker::run(m.inner.clone(), shutdown.clone()));
        tokio::spawn(m.clone().watch_certs_dir(shutdown));
        Ok(m)
    }

    /// Applies a (new) configuration and reloads the local certificate directory.
    pub async fn reconcile(&self, cfg: &Config) {
        let mut st = self.inner.state.lock().await;
        st.gw = cfg.gateway.clone();
        st.routes = tls_routes(cfg);
        st.index = cfg
            .gateway
            .certs_dir
            .as_deref()
            .map(local::LocalIndex::load)
            .unwrap_or_default();
        refresh::refresh(&self.inner, &mut st).await;
        drop(st);
        self.inner.wake.notify_one();
    }

    async fn certs_stamp(&self) -> Option<Vec<(String, Option<std::time::SystemTime>, u64)>> {
        let dir = self.inner.state.lock().await.gw.certs_dir.clone();
        dir.map(|d| local::dir_stamp(&d))
    }

    /// Polls `certs-dir` every 2 s: certbot renewals are picked up without a reload.
    async fn watch_certs_dir(self, shutdown: CancellationToken) {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last = self.certs_stamp().await;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => return,
                _ = tick.tick() => {}
            }
            let now = self.certs_stamp().await;
            if now != last {
                last = now;
                self.reload_local().await;
            }
        }
    }

    /// Re-reads `certs-dir` only (its content changed on disk).
    pub async fn reload_local(&self) {
        let mut st = self.inner.state.lock().await;
        let Some(dir) = st.gw.certs_dir.clone() else {
            return;
        };
        st.index = local::LocalIndex::load(&dir);
        refresh::refresh(&self.inner, &mut st).await;
        drop(st);
        self.inner.wake.notify_one();
    }

    /// Certificate source per host, for observability.
    pub fn report(&self) -> Arc<HashMap<String, HostCert>> {
        self.inner.report.load_full()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(src: &str) -> Config {
        crate::config::parse_str(src, &|_| None).unwrap()
    }

    #[test]
    fn staging_overrides_global_directory() {
        const STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
        let prod = cfg("gateway { default-email \"a@b.c\" }");
        let custom = cfg("gateway { default-email \"a@b.c\"\n acme-directory \"https://ca.example/dir\" }");
        assert_eq!(directory_for_route(&prod, true), STAGING);
        assert_eq!(directory_for_route(&custom, true), STAGING);
        assert_eq!(directory_for_route(&custom, false), "https://ca.example/dir");
        assert!(directory_for_route(&prod, false).contains("acme-v02"));
    }

    #[test]
    fn routes_carry_their_directory() {
        let c = cfg(
            "gateway { default-email \"a@b.c\" }\nroute \"a.com\" { upstream \"10.0.0.1:80\"\n tls { staging } }\nroute \"b.com\" { upstream \"10.0.0.1:80\"\n tls self-signed=#true }\nroute \"c.com\" { upstream \"10.0.0.1:80\"\n tls }",
        );
        let r = tls_routes(&c);
        assert!(r[0].directory.as_deref().is_some_and(|d| d.contains("staging")));
        assert!(r[1].directory.is_none());
        assert!(r[2].directory.as_deref().is_some_and(|d| d.contains("acme-v02")));
    }
}
