//! SQLite storage on a dedicated thread: certificates, secrets, ACME account and passkeys.
pub mod acme;
pub mod certs;
mod db;
pub mod passkeys;
pub mod secrets;

pub use db::Db;

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage thread stopped")]
    Closed,
    #[error("corrupt record: {0}")]
    Corrupt(String),
    #[error("limit reached: {0}")]
    LimitReached(&'static str),
}

/// Unix seconds, `0` if the clock is before the epoch.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}
