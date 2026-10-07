//! Validated configuration data model (pure data).
use super::model_auth::*;
use ipnet::IpNet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub gateway: GatewayCfg,
    pub mcp: Option<McpCfg>,
    pub routes: Vec<RouteCfg>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeDirectory {
    Production,
    Staging,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogCfg {
    pub json: bool,
    pub level: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_connections: usize,
    pub max_body: u64,
    pub header_read_timeout: Duration,
    pub max_headers_size: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GatewayCfg {
    pub listen_http: SocketAddr,
    pub listen_https: Option<SocketAddr>,
    pub storage_path: PathBuf,
    pub acme_directory: AcmeDirectory,
    pub acme_ca_root: Option<PathBuf>,
    pub default_email: Option<String>,
    pub certs_dir: Option<PathBuf>,
    pub trusted_proxies: Vec<IpNet>,
    /// 0 with `flight-recorder off`.
    pub flight_recorder_capacity: usize,
    pub log: LogCfg,
    pub limits: Limits,
    pub worker_threads: Option<usize>,
    pub default_cert: Option<String>,
    pub shutdown_grace: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpCfg {
    pub listen: SocketAddr,
    pub token: Option<String>,
    /// Built-in default (no `mcp-server` node): a bind failure is only a warning.
    pub implicit: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RouteCfg {
    pub id: Arc<str>,
    pub hosts: Vec<String>,
    pub tls: Option<TlsCfg>,
    pub redirect_https: bool,
    /// Empty for a static route.
    pub upstreams: Vec<UpstreamCfg>,
    /// Serves a directory instead of proxying (`static`).
    pub static_files: Option<StaticCfg>,
    pub health: HealthCfg,
    pub request_timeout: Duration,
    pub cache: Option<CacheCfg>,
    pub compression: Option<CompressionCfg>,
    pub geoip: Option<GeoIpCfg>,
    /// Resolved and aggregated `allow-ips`; `None` = every client is allowed.
    pub allow_ips: Option<Vec<IpNet>>,
    pub rate_limits: Vec<RateLimitCfg>,
    pub gatekeeper: Option<GatekeeperCfg>,
    pub jwt: Option<JwtCfg>,
    pub api_keys: Option<ApiKeysCfg>,
    pub transform: Option<TransformCfg>,
    /// None with `fallback off`: backend responses and failures are left untouched.
    pub fallback: Option<FallbackCfg>,
    /// Retry an idempotent request once on another backend after a connection failure.
    pub retry: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCfg {
    pub mode: TlsMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsMode {
    /// Local certificate from `certs-dir`, else ACME, else a temporary self-signed certificate.
    Auto { acme: Option<AcmeTarget> },
    /// In-memory generated certificate, never ACME.
    SelfSigned,
}

/// Present only when ACME is possible for the route (email known, no wildcard host).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeTarget {
    pub email: String,
    pub staging: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticCfg {
    pub root: PathBuf,
    /// Index file name, empty when disabled.
    pub index: String,
    pub listing: bool,
    pub spa: bool,
    pub hidden: bool,
    pub follow_symlinks: bool,
    pub cache_control: Option<String>,
}

impl Default for StaticCfg {
    /// Serves the current working directory (resolved when the routes are built).
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            index: "index.html".into(),
            listing: true,
            spa: false,
            hidden: false,
            follow_symlinks: false,
            cache_control: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamCfg {
    pub addr: SocketAddr,
    pub weight: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthMode {
    Http,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCfg {
    pub path: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub unhealthy_after: u32,
    pub healthy_after: u32,
    pub mode: HealthMode,
    pub enabled: bool,
}

impl Default for HealthCfg {
    fn default() -> Self {
        Self {
            path: "/".into(),
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(2),
            unhealthy_after: 2,
            healthy_after: 2,
            mode: HealthMode::Http,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackCfg {
    pub status: u16,
    pub show_incident_id: bool,
    pub title: String,
    pub message: String,
    pub on: Vec<u16>,
}

impl Default for FallbackCfg {
    fn default() -> Self {
        Self {
            status: 503,
            show_incident_id: true,
            title: "Service temporarily unavailable".into(),
            message: "We are working on restoring the service. Please try again in a few moments.".into(),
            on: vec![502, 503, 504],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheCfg {
    pub max_size: u64,
    pub stale_while_revalidate: Duration,
    pub stale_if_error: Duration,
    pub default_ttl: Duration,
    pub max_object_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionCfg {
    pub zstd: bool,
    pub brotli: bool,
    pub gzip: bool,
    pub min_size: u64,
}

impl Default for CompressionCfg {
    fn default() -> Self {
        Self {
            zstd: true,
            brotli: true,
            gzip: true,
            min_size: 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoIpCfg {
    pub database: PathBuf,
    pub block: Vec<String>,
    pub allow: Vec<String>,
    pub inject_header: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitCfg {
    pub rps: u32,
    pub burst: u32,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatekeeperCfg {
    pub title: String,
    pub psk_hash: String,
    pub totp_secret: Option<Vec<u8>>,
    pub session_duration: Duration,
    pub attempts: u32,
    pub window: Duration,
    pub cookie_name: String,
}
