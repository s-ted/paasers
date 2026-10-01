# P0: Conventions, skeleton, shared types

> Mandatory before any line of code. Everything below has been **compiled and tested** (rustc 1.95.0).

## 1. Initialization

```bash
cd /workspaces/paasers
git init && cargo init --name paasers   # then replace Cargo.toml with §2
rustup target add x86_64-unknown-linux-musl
mkdir -p src/{config,server,routing,proxy,observe,tls,storage,layers,cache,gatekeeper,mcp} tests/{common,fixtures} examples deploy scripts
```

`.gitignore`: `/target`. `Cargo.lock` **is committed**.

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "1.95.0"
components = ["clippy", "rustfmt"]
targets = ["x86_64-unknown-linux-musl"]
```

`clippy.toml`:
```toml
allow-unwrap-in-tests = true
allow-expect-in-tests = true
allow-panic-in-tests = true
allow-indexing-slicing-in-tests = true
```

`rustfmt.toml`: `max_width = 110`.

## 2. Exact `Cargo.toml` (validated: resolution, gnu + static musl build, feature on/off)

```toml
[package]
name = "paasers"
version = "0.1.0"
edition = "2024"
rust-version = "1.95"
license = "MIT OR Apache-2.0"
description = "PaaS edge gateway & ingress proxy"

[lib]
path = "src/lib.rs"

[[bin]]
name = "paasers"
path = "src/main.rs"

[dependencies]
# runtime / http
tokio = { version = "1.53", features = ["rt-multi-thread", "macros", "net", "time", "sync", "signal", "fs", "io-util"] }
hyper = { version = "1.11", features = ["http1", "http2", "server", "client"] }
hyper-util = { version = "0.1.21", features = ["tokio", "service", "server-auto", "server-graceful", "client-legacy", "http1", "http2"] }
http = "1.5"
http-body = "1"
http-body-util = "0.1.5"
bytes = "1.12"
tower = { version = "0.5.3", features = ["util"] }
tower-http = { version = "0.7.1", default-features = false, features = ["compression-gzip", "compression-br", "compression-zstd"] }
async-compression = { version = "0.4.49", features = ["tokio", "gzip", "zstd", "brotli"] }
tokio-util = { version = "0.7.19", features = ["io", "rt"] }
futures-util = "0.3.34"
pin-project-lite = "0.2.17"
socket2 = { version = "0.6.5", features = ["all"] }
# tls / acme
rustls = { version = "0.23.45", default-features = false, features = ["aws_lc_rs", "std", "tls12", "logging"] }
tokio-rustls = { version = "0.26.6", default-features = false, features = ["aws_lc_rs", "tls12"] }
rustls-pki-types = "1.15"
instant-acme = { version = "0.8.5", default-features = false, features = ["aws-lc-rs", "hyper-rustls", "rcgen"] }
rcgen = { version = "0.14.10", default-features = false, features = ["aws_lc_rs", "pem"] }
x509-parser = "0.18.1"
# storage / routing / config
rusqlite = { version = "0.40.2", features = ["bundled"] }
matchit = "0.9.2"
arc-swap = "1.9.2"
kdl = { version = "6.7.1", default-features = false, features = ["span", "v1-fallback"] }
humantime = "2.4"
bytesize = "2.7"
ipnet = "2.12"
regex = "1.13"
# features
governor = { version = "0.10.4", default-features = false, features = ["std", "quanta", "dashmap"] }
jsonwebtoken = { version = "11.1", default-features = false, features = ["aws_lc_rs", "use_pem"] }
argon2 = "0.6"
totp-rs = "6"
webauthn-rs = { version = "0.5.5", optional = true }
maxminddb = { version = "0.32", features = ["mmap"] }
quick_cache = "0.7"
httpdate = "1.0.3"
# observability / mcp
tracing = "0.1.44"
tracing-subscriber = { version = "0.3.23", features = ["env-filter", "fmt", "json"] }
fastrace = "0.7.19"
rmcp = { version = "=3.5.0", features = ["server", "macros", "transport-streamable-http-server"] }
# misc
thiserror = "2.0.21"
anyhow = "1.0.104"
serde = { version = "1.0.228", features = ["derive"] }
serde_json = "1.0.151"
sha2 = "0.11"
hmac = "0.13"
subtle = "2.6"
hex = "0.4.3"
base64 = "0.23"
rand = "0.10"
uuid = { version = "1.26", features = ["v4"] }
url = "2.5"
clap = { version = "4.6", features = ["derive"] }
mimalloc = { version = "0.1.52", default-features = false }

[target.'cfg(target_env = "musl")'.dependencies]
openssl = { version = "0.10", features = ["vendored"], optional = true }

[features]
default = ["passkey"]
passkey = ["dep:webauthn-rs", "dep:openssl"]

[dev-dependencies]
tempfile = "3"

[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
strip = true
panic = "unwind"

[lints.rust]
unsafe_code = "deny"

[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
indexing_slicing = "deny"
todo = "deny"
unimplemented = "deny"
dbg_macro = "deny"
```

It is **forbidden** to add an unlisted dependency. No `axum`, `reqwest`, direct `hyper-rustls`, direct `openssl` outside the feature, `lazy_static`, `once_cell` (use `std::sync::LazyLock`/`OnceLock`), `chrono` (use `std::time` + `httpdate` + `humantime`).

Verified notes:
* `rmcp` re-exports `schemars`: write `use rmcp::schemars;` **in the module** that derives, then `#[derive(schemars::JsonSchema)]` (no direct `schemars` dependency). Also applies to `observe::recorder::Query` (plans/06).
* `jsonwebtoken` feature `aws_lc_rs` **alone**: the crypto provider is selected automatically (otherwise runtime panic; never also enable `rust_crypto`).
* `rustls`: **never** rely on an implicit global provider; always build via `ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))`. In addition, `main` calls once `let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();` (for instant-acme/hyper-rustls).
* `maxminddb::Reader::open_mmap` is `unsafe`: the only allowed place, `#[allow(unsafe_code)]` on the function + comment `// SAFETY: file replaced only by atomic rename; never modified in place.`
* `rand 0.10`: `rand::random::<[u8; 32]>()`, `rand::random_range(0..n)`.

## 3. Code rules (from SPECS §5, made verifiable)

1. **Language: English only.** All code (identifiers, comments, doc comments, log messages, error messages, test names), all user-facing default texts (error pages, gatekeeper UI, MCP tool descriptions and hints, CLI output) and all documentation (README, commit messages) are written in English.
2. **No** `unwrap/expect/panic!/todo!/unimplemented!/dbg!/x[i]` outside `#[cfg(test)]` (deny lints). Use `.get(i)`, `?`, `let ... else`, `ok_or(...)`.
3. Errors: one `thiserror` `enum XxxError` per module (`config::ConfigError`, `storage::StorageError`, `tls::TlsError`, `proxy::ProxyError`, ...). `anyhow` **only** in `main.rs`/`cli.rs`/background tasks (top-level `run()`).
4. Files ≤ **250 lines** excluding the `#[cfg(test)] mod tests` block (target 200). `scripts/ci.sh` checks it.
5. No `async` lock held across a network `.await`. Allowed locks: `std::sync::Mutex` (O(1) sections, never across `.await`), `tokio::sync::{Semaphore, Notify, watch, mpsc, oneshot}`, `arc_swap::ArcSwap`, atomics.
6. Functional style: iterators (`filter_map`, `fold`, `try_fold`), pure functions for all parsing/policy (testable without I/O), I/O at the edges.
7. Zero-copy: `bytes::Bytes` for bodies, `HeaderValue::from_static` for constants, no `.to_string()` on a hot path without need.
8. `tracing`: `info!` for lifecycle events, `warn!` for degradations, `error!` for failures, `debug!` per request. Never any secret in logs (PSK, tokens, cookies, keys).
9. Each `.rs` file starts with a one-sentence `//!` doc line.
10. All unit tests in `#[cfg(test)] mod tests { use super::*; ... }` at the bottom of the file.

## 4. `src/prelude.rs` (exact, validated)

```rust
//! HTTP types shared by the whole data plane.
use std::convert::Infallible;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// Single body type used everywhere (requests AND responses).
pub type Body = BoxBody<Bytes, BoxError>;
pub type Req = http::Request<Body>;
pub type Resp = http::Response<Body>;
/// Route service: concrete, cloneable, Sync (required by hyper), infallible.
pub type RouteSvc = tower::util::BoxCloneSyncService<Req, Resp, Infallible>;
pub type BoxFut = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Resp, Infallible>> + Send>>;

pub fn full(b: impl Into<Bytes>) -> Body { Full::new(b.into()).map_err(|n| match n {}).boxed() }
pub fn empty() -> Body { Empty::<Bytes>::new().map_err(|n| match n {}).boxed() }
/// Converts any body (Incoming, compression, ...) into `Body`.
pub fn boxed<B>(b: B) -> Body
where B: http_body::Body<Data = Bytes> + Send + Sync + 'static, B::Error: Into<BoxError> {
    b.map_err(Into::into).boxed()
}
pub fn map_resp<B>(r: http::Response<B>) -> Resp
where B: http_body::Body<Data = Bytes> + Send + Sync + 'static, B::Error: Into<BoxError> {
    r.map(boxed)
}
/// Simple response (status + text), without panicking.
pub fn simple(status: http::StatusCode, ctype: &'static str, body: impl Into<Bytes>) -> Resp {
    let mut r = http::Response::new(full(body));
    *r.status_mut() = status;
    r.headers_mut().insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static(ctype));
    r
}
```

## 5. **Mandatory** Tower pattern for each middleware (validated)

**Rule R5**: Services are **concrete** over `RouteSvc`, never generic `S`. A generic Service that does an `.await` before calling `inner` triggers a rustc error "implementation of `Send` is not general enough" (observed). The pattern below compiles, passes clippy and the tests:

```rust
#[derive(Clone)]
pub struct FooLayer { cfg: Arc<FooCfg>, state: Arc<FooState> }
impl tower::Layer<RouteSvc> for FooLayer {
    type Service = Foo;
    fn layer(&self, inner: RouteSvc) -> Foo { Foo { inner, cfg: self.cfg.clone(), state: self.state.clone() } }
}
#[derive(Clone)]
pub struct Foo { inner: RouteSvc, cfg: Arc<FooCfg>, state: Arc<FooState> }
impl tower::Service<Req> for Foo {
    type Response = Resp; type Error = Infallible; type Future = BoxFut;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> { self.inner.poll_ready(cx) }
    fn call(&mut self, req: Req) -> BoxFut {
        // "Clone and swap" exchange: the ready instance moves into the future.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let (cfg, state) = (self.cfg.clone(), self.state.clone());
        Box::pin(async move {
            use tower::ServiceExt;
            // ... logic, possibly .await ...
            inner.ready().await?.call(req).await
        })
    }
}
```
* **Synchronous** decisions (e.g. 403 rejection): return `Box::pin(std::future::ready(Ok(resp)))` without calling `inner`.
* Assembly: each layer is applied by an explicit `match` that returns a `RouteSvc` (exact code: `plans/04-routing.md` §4). Do **not** use `ServiceBuilder::option_layer` (nested `Either<..>` types).
* `tower-http` `CompressionLayer` produces a `Response<CompressionBody<Body>>`, re-wrapped by `.map_response(map_resp)` (exact validated code: `plans/10-security-layers.md` §5).

## 6. Errors → responses

`src/error.rs`:
```rust
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("bad request: {0}")] BadRequest(&'static str),          // 400
    #[error("not found")] UnknownHost,                                // 404
    #[error("payload too large")] PayloadTooLarge,                    // 413
    #[error("loop detected")] Loop,                                   // 508
    #[error("no healthy upstream")] NoHealthyUpstream,                // 503
    #[error("upstream connect: {0}")] UpstreamConnect(String),        // 502
    #[error("upstream timeout")] UpstreamTimeout,                     // 504
    #[error("upstream: {0}")] Upstream(String),                       // 502
}
impl GatewayError { pub fn status(&self) -> http::StatusCode { /* mapping above */ } }
```
The proxy converts its errors into a `Resp` with this status **and** inserts the extension `ProxyFailure { kind: &'static str, detail: String, upstream: Option<SocketAddr> }` into the response. The `FallbackLayer` and the flight recorder read this extension (see `plans/06`).

## 7. Shared request extensions (types in `src/prelude.rs`)

```rust
#[derive(Clone, Copy, Debug)] pub struct ClientIp(pub std::net::IpAddr);        // set by Entry
#[derive(Clone, Copy, Debug)] pub struct Scheme(pub &'static str);               // "http" | "https"
#[derive(Clone, Debug)] pub struct TraceCtx { pub trace_id: u128, pub parent_span: Option<u64>, pub span_id: u64, pub sampled: bool }
#[derive(Clone, Debug)] pub struct RouteId(pub std::sync::Arc<str>);             // set by Entry
#[derive(Clone, Copy, Debug)] pub struct ApiKeyAuthenticated;                     // set by ApiKeyLayer
#[derive(Clone, Debug)] pub struct CountryCode(pub [u8; 2]);                      // set by GeoIpLayer
#[derive(Clone, Debug)] pub struct ProxyFailure { pub kind: &'static str, pub detail: String, pub upstream: Option<std::net::SocketAddr> }
#[derive(Clone, Debug)] pub struct UpstreamUsed(pub std::net::SocketAddr);        // set by Proxy on the response
#[derive(Clone, Copy, Debug)] pub struct RequestStart(pub std::time::Instant);    // set by Entry
#[derive(Clone, Copy, Debug)] pub struct IncidentKind(pub &'static str);          // set on the RESPONSE by a rejecting layer (429 "rate_limited", 401/403 "auth", 403 "geo_blocked")
#[derive(Clone, Copy, Debug)] pub struct CacheStatus(pub &'static str);           // set on the response by CacheLayer ("HIT"|"MISS"|"STALE"|"BYPASS")
```

## 8. `src/lib.rs` / `src/main.rs`

`lib.rs` declares `pub mod prelude; pub mod error; pub mod cli; pub mod config; pub mod server; pub mod routing; pub mod proxy; pub mod observe; pub mod tls; pub mod storage; pub mod layers; pub mod cache; pub mod gatekeeper; pub mod mcp;`. Modules not yet implemented are created empty (`//! ...`) so that it compiles from P0.

`main.rs`:
```rust
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
fn main() -> std::process::ExitCode { paasers::cli::main() }
```

## 9. `scripts/ci.sh`
```bash
#!/usr/bin/env bash
set -euo pipefail
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
# files <= 250 lines excluding tests
fail=0
for f in $(git ls-files 'src/*.rs' 'src/**/*.rs'); do
  n=$(awk '/^#\[cfg\(test\)\]/{exit} {c++} END{print c+0}' "$f")
  if [ "$n" -gt 250 ]; then echo "TOO LONG: $f ($n)"; fail=1; fi
done
exit $fail
```

## 10. DoD P0
- [ ] `cargo check --message-format=short` OK, `cargo clippy --all-targets -- -D warnings` OK.
- [ ] `scripts/ci.sh` OK.
- [ ] Unit test `prelude::tests::simple_sets_status_and_ctype`.
- [ ] Commit `P0: skeleton`.
