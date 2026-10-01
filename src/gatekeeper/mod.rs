//! Gatekeeper: environment barrier with an Argon2id PSK, optional TOTP and passkeys.
mod http_util;
mod layer;
mod limiter;
mod login;
mod pages;
#[cfg(feature = "passkey")]
pub mod passkey;
mod psk;
pub mod session;
mod totp;

pub use layer::GatekeeperLayer;

use crate::config::GatekeeperCfg;
use crate::storage::Db;
use limiter::LoginLimiter;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::Semaphore;
use totp::TotpChecker;

#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("gatekeeper {0}")]
    Build(String),
}

/// State shared by every gatekeeper route and kept across reloads.
pub struct GateShared {
    pub hmac_key: [u8; 32],
    pub argon_sem: Semaphore,
    pub db: Option<Db>,
    limiters: Mutex<HashMap<Arc<str>, Arc<LoginLimiter>>>,
    #[cfg(feature = "passkey")]
    pub pending: passkey::Pending,
}

impl GateShared {
    pub fn new(hmac_key: [u8; 32], db: Option<Db>) -> Self {
        Self {
            hmac_key,
            argon_sem: Semaphore::new(2),
            db,
            limiters: Mutex::new(HashMap::new()),
            #[cfg(feature = "passkey")]
            pending: passkey::Pending::default(),
        }
    }

    /// Keeps the limiter of a route while its `attempts`/`window` are unchanged.
    fn limiter(
        &self,
        route: &Arc<str>,
        attempts: u32,
        window: Duration,
    ) -> Result<Arc<LoginLimiter>, GateError> {
        let mut m = self.limiters.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(l) = m.get(route)
            && l.attempts == attempts
            && l.window == window
        {
            return Ok(l.clone());
        }
        let l = Arc::new(
            LoginLimiter::new(attempts, window)
                .ok_or_else(|| GateError::Build("invalid rate-limit parameters".into()))?,
        );
        m.insert(route.clone(), l.clone());
        Ok(l)
    }

    /// Periodic cleanup of per-IP state.
    pub fn purge(&self) {
        self.limiters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .for_each(|l| l.purge());
    }
}

/// Gatekeeper configuration compiled for one route.
pub struct GateRt {
    pub route_id: Arc<str>,
    pub title: String,
    pub cookie_name: String,
    pub session_secs: i64,
    pub phc: Arc<str>,
    pub fingerprint: String,
    pub totp: Option<TotpChecker>,
    pub passkey: bool,
    pub secure: bool,
    pub limiter: Arc<LoginLimiter>,
    pub shared: Arc<GateShared>,
    #[cfg(feature = "passkey")]
    pub webauthn: HashMap<String, Arc<webauthn_rs::Webauthn>>,
}

impl GateRt {
    pub fn build(
        route_id: &Arc<str>,
        hosts: &[String],
        cfg: &GatekeeperCfg,
        secure: bool,
        https_port: Option<u16>,
        shared: &Arc<GateShared>,
    ) -> Result<Self, GateError> {
        let totp = match &cfg.totp_secret {
            Some(s) => {
                Some(TotpChecker::new(s).ok_or_else(|| GateError::Build("invalid totp secret".into()))?)
            }
            None => None,
        };
        #[cfg(not(feature = "passkey"))]
        let _ = (hosts, https_port);
        Ok(Self {
            route_id: route_id.clone(),
            title: cfg.title.clone(),
            cookie_name: cfg.cookie_name.clone(),
            session_secs: i64::try_from(cfg.session_duration.as_secs()).unwrap_or(i64::MAX / 4),
            phc: Arc::from(cfg.psk_hash.as_str()),
            fingerprint: session::fingerprint(&cfg.psk_hash, cfg.totp_secret.as_deref()),
            totp,
            passkey: cfg.passkey,
            secure,
            limiter: shared.limiter(route_id, cfg.attempts, cfg.window)?,
            shared: shared.clone(),
            #[cfg(feature = "passkey")]
            webauthn: if cfg.passkey {
                passkey::build_webauthn(hosts, &cfg.title, https_port)?
            } else {
                HashMap::new()
            },
        })
    }
}

#[cfg(test)]
mod tests;
