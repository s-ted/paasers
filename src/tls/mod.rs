//! TLS: SNI certificate resolver, self-signed bootstrap certificates and ACME (HTTP-01) issuance.
pub mod acme;
pub mod challenge;
pub mod pem;
pub mod resolver;
pub mod selfsigned;
mod worker;

pub use challenge::ChallengeStore;
pub use resolver::CertResolver;

use crate::config::{Config, GatewayCfg, RouteCfg, TlsCfg};
use crate::observe::{FlightRecorder, Incident, trace};
use crate::storage::{Db, StorageError};
use arc_swap::ArcSwapOption;
use rustls::sign::CertifiedKey;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

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

/// One ACME order: all hosts of a route share a single certificate.
#[derive(Debug, Clone)]
pub struct TlsJob {
    pub route_id: Arc<str>,
    pub hosts: Vec<String>,
    pub email: String,
}

pub struct CertManagerInner {
    pub(crate) db: Db,
    pub(crate) resolver: Arc<CertResolver>,
    pub(crate) challenges: Arc<ChallengeStore>,
    pub(crate) recorder: Arc<FlightRecorder>,
    pub(crate) gw: GatewayCfg,
    pub(crate) default_cert: ArcSwapOption<String>,
    pub(crate) wanted: watch::Sender<Arc<Vec<TlsJob>>>,
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

fn read_files(cert: &std::path::Path, key: &std::path::Path) -> Result<Arc<CertifiedKey>, TlsError> {
    Ok(Arc::new(pem::certified(
        &std::fs::read_to_string(cert)?,
        &std::fs::read_to_string(key)?,
    )?))
}

impl CertManager {
    /// Loads certificates, installs bootstrap certificates and starts the renewal worker.
    pub async fn start(
        cfg: &Config,
        db: Db,
        resolver: Arc<CertResolver>,
        challenges: Arc<ChallengeStore>,
        recorder: Arc<FlightRecorder>,
        shutdown: CancellationToken,
    ) -> Result<Self, TlsError> {
        let (wanted, _) = watch::channel(Arc::new(Vec::new()));
        let inner = Arc::new(CertManagerInner {
            db,
            resolver,
            challenges,
            recorder,
            gw: cfg.gateway.clone(),
            default_cert: ArcSwapOption::empty(),
            wanted,
        });
        let m = Self { inner };
        m.reconcile(cfg, true).await?;
        tokio::spawn(worker::run(m.inner.clone(), shutdown));
        Ok(m)
    }

    fn record(&self, route: &RouteCfg, msg: &str) {
        let mut i = Incident::new(trace::trace_hex(trace::nz128()), "acme").with_detail(msg);
        i.route_id = Some(route.id.to_string());
        self.inner.recorder.record(i);
    }

    /// Applies a (new) configuration. At startup a bad certificate file is fatal, on reload it is logged.
    pub async fn reconcile(&self, cfg: &Config, startup: bool) -> Result<(), TlsError> {
        let inner = &self.inner;
        let mut active: HashSet<String> = HashSet::new();
        let mut jobs = Vec::new();
        for route in cfg.routes.iter().filter(|r| r.tls.is_some()) {
            active.extend(route.hosts.iter().cloned());
            match route.tls.as_ref() {
                Some(TlsCfg::Files { cert, key }) => match read_files(cert, key) {
                    Ok(k) => route.hosts.iter().for_each(|h| match h.strip_prefix("*.") {
                        Some(parent) => inner.resolver.set_wildcard(parent, k.clone()),
                        None => inner.resolver.set(h, k.clone()),
                    }),
                    Err(e) if startup => return Err(e),
                    Err(e) => {
                        tracing::error!(route = %route.id, error = %e, "cannot reload certificate files, keeping the previous ones");
                        self.record(route, &e.to_string());
                    }
                },
                Some(TlsCfg::Acme { email }) => {
                    let mut missing = Vec::new();
                    for h in &route.hosts {
                        let loaded = match inner.db.get_cert(h).await? {
                            Some(r) => pem::certified(&r.cert_pem, &r.key_pem).ok().map(Arc::new),
                            None => None,
                        };
                        match loaded {
                            Some(k) => inner.resolver.set(h, k),
                            None if inner.resolver.get(h).is_none() => missing.push(h.clone()),
                            None => {}
                        }
                    }
                    if !missing.is_empty() {
                        // One self-signed certificate (SAN = all missing hosts) avoids handshake failures meanwhile.
                        let k = Arc::new(selfsigned::self_signed(&missing)?);
                        missing.iter().for_each(|h| inner.resolver.set(h, k.clone()));
                    }
                    jobs.push(TlsJob {
                        route_id: route.id.clone(),
                        hosts: route.hosts.clone(),
                        email: email.clone(),
                    });
                }
                None => {}
            }
        }
        inner
            .default_cert
            .store(cfg.gateway.default_cert.clone().map(Arc::new));
        if let Some(dc) = &cfg.gateway.default_cert {
            inner.resolver.set_default(inner.resolver.get(dc));
        }
        inner.resolver.remove_not_in(&active);
        inner.wanted.send_replace(Arc::new(jobs));
        Ok(())
    }
}
