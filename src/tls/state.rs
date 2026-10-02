//! Shared state of the certificate manager.
use super::local::LocalIndex;
use super::select::Source;
use crate::config::{GatewayCfg, TlsMode};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// A TLS route reduced to what certificate management needs.
#[derive(Debug, Clone)]
pub struct TlsRoute {
    pub id: Arc<str>,
    pub hosts: Vec<String>,
    pub mode: TlsMode,
    /// ACME directory URL (auto mode with ACME only).
    pub directory: Option<String>,
}

/// Certificate currently installed for a host.
#[derive(Debug, Clone)]
pub struct HostState {
    pub source: Source,
    pub key: Arc<CertifiedKey>,
    pub not_after: i64,
    pub path: Option<PathBuf>,
    pub directory: Option<String>,
}

impl HostState {
    pub fn new(source: Source, key: Arc<CertifiedKey>, not_after: i64) -> Self {
        Self {
            source,
            key,
            not_after,
            path: None,
            directory: None,
        }
    }
}

/// Read-only view for observability (MCP).
#[derive(Debug, Clone)]
pub struct HostCert {
    pub source: &'static str,
    pub not_after: i64,
    pub path: Option<String>,
    pub acme_directory: Option<String>,
}

impl From<&HostState> for HostCert {
    fn from(s: &HostState) -> Self {
        Self {
            source: s.source.label(),
            not_after: s.not_after,
            path: s.path.as_ref().map(|p| p.display().to_string()),
            acme_directory: s.directory.clone(),
        }
    }
}

pub type SelfSignedEntry = (Vec<String>, Arc<CertifiedKey>, i64);

pub struct State {
    pub gw: GatewayCfg,
    pub routes: Vec<TlsRoute>,
    pub index: LocalIndex,
    pub hosts: HashMap<String, HostState>,
    pub selfsigned: HashMap<Arc<str>, SelfSignedEntry>,
    /// Temporary self-signed certificates of auto-mode hosts that have nothing better yet.
    pub temp: HashMap<String, (Arc<CertifiedKey>, i64)>,
}
