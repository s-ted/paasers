//! Shared in-memory HTTP cache (RFC 9111 subset), stale-while-revalidate and tag purge.
pub mod cond;
pub mod key;
pub mod layer;
pub mod policy;
pub mod respond;
pub mod revalidate;
pub mod store;
pub mod tee;

pub use layer::CacheLayer;
pub use store::{CacheRegistry, CacheStats, HttpCache, Purge};

#[cfg(test)]
mod tests;
