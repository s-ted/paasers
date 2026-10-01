//! Shared upstream HTTP client (connection pool).
use crate::prelude::Body;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use std::time::Duration;

pub type UpstreamClient = Client<HttpConnector, Body>;

/// The connect timeout is global and fixed at 5 s: only the request timeout is configurable per route.
pub fn new_client() -> UpstreamClient {
    let mut conn = HttpConnector::new();
    conn.set_nodelay(true);
    conn.set_connect_timeout(Some(Duration::from_secs(5)));
    conn.set_keepalive(Some(Duration::from_secs(60)));
    conn.enforce_http(true);
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(32)
        .pool_timer(TokioTimer::new())
        .timer(TokioTimer::new())
        .http1_preserve_header_case(false)
        .build(conn)
}
