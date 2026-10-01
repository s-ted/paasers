//! Server orchestration: listeners, entry service, reload and graceful shutdown.
mod entry;
mod http;
mod listener;
mod reload;
pub(crate) mod request;
mod run;
mod shutdown;
mod tls_accept;

pub use entry::EntryService;
pub use listener::bind as bind_listener;
pub use run::{run_shared, run_with};

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize};

/// Long-lived state that survives reloads (extended by later phases).
pub struct Shared {
    pub generation: AtomicU64,
    pub started_at: std::time::SystemTime,
    pub recorder: Arc<crate::observe::FlightRecorder>,
    pub client: crate::proxy::UpstreamClient,
    pub health: Arc<crate::proxy::HealthRegistry>,
    /// Active WebSocket tunnels.
    pub tunnels: Arc<AtomicUsize>,
    /// Actually bound HTTPS port (0 until bound), used for redirects when the configured port is 0.
    pub https_port: std::sync::atomic::AtomicU16,
    pub caches: Arc<crate::cache::CacheRegistry>,
    pub limiters: Arc<crate::layers::ratelimit::LimiterRegistry>,
    pub geoip: Arc<crate::layers::geoip::GeoRegistry>,
    /// Gatekeeper state (needs the database for its signing key, so it is set once after startup).
    pub gate: std::sync::OnceLock<Arc<crate::gatekeeper::GateShared>>,
    pub certs: Arc<crate::tls::CertResolver>,
    /// HTTP-01 key authorizations served on the plain HTTP listener.
    pub challenges: Arc<crate::tls::ChallengeStore>,
}

impl Shared {
    pub fn new() -> Self {
        Self::with_recorder_capacity(500)
    }

    pub fn with_recorder_capacity(capacity: usize) -> Self {
        Self {
            recorder: Arc::new(crate::observe::FlightRecorder::new(capacity)),
            generation: AtomicU64::new(0),
            started_at: std::time::SystemTime::now(),
            client: crate::proxy::new_client(),
            health: Arc::new(crate::proxy::HealthRegistry::new()),
            tunnels: Arc::new(AtomicUsize::new(0)),
            https_port: std::sync::atomic::AtomicU16::new(0),
            caches: Arc::new(crate::cache::CacheRegistry::default()),
            limiters: Arc::new(crate::layers::ratelimit::LimiterRegistry::default()),
            geoip: Arc::new(crate::layers::geoip::GeoRegistry::default()),
            gate: std::sync::OnceLock::new(),
            certs: Arc::new(crate::tls::CertResolver::default()),
            challenges: Arc::new(crate::tls::ChallengeStore::default()),
        }
    }
}

impl Default for Shared {
    fn default() -> Self {
        Self::new()
    }
}

/// Addresses actually bound (port 0 resolves to the real port).
#[derive(Debug, Clone)]
pub struct BoundAddrs {
    pub http: SocketAddr,
    pub https: Option<SocketAddr>,
    pub mcp: Option<SocketAddr>,
}
