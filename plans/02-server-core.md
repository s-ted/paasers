# P2: Server core (`src/server/`, `src/cli.rs`)

## 1. Files

| File | Role |
|---|---|
| `cli.rs` | `pub fn main() -> ExitCode`: clap, subcommands, tokio runtime construction |
| `server/mod.rs` | `pub async fn run_with(cfg, cfg_path, ready, shutdown) -> anyhow::Result<()>` (exact signature §9): orchestrates everything |
| `server/listener.rs` | socket creation (dual-stack), `accept` loop with semaphore |
| `server/http.rs` | connection service: `hyper_util::server::conn::auto` builder, timeouts |
| `server/tls.rs` | TLS acceptor (uses `tls::resolver`) |
| `server/entry.rs` | `EntryService`: 1st service called by hyper for each request |
| `server/reload.rs` | SIGHUP + mtime poll ⇒ rebuild runtime ⇒ `ArcSwap::store` |
| `server/shutdown.rs` | `CancellationToken` + `GracefulShutdown` |

## 2. CLI (`clap` derive)

```text
paasers run   -c, --config <PATH>   (default /etc/paasers/gateway.kdl)
paasers check -c, --config <PATH>
paasers hash-password               reads the password from stdin (1st line, without trailing \n), prints the argon2id PHC m=19456,t=2,p=1
paasers hash-api-key                reads the key from stdin, prints sha256 hex
paasers gen-totp [--issuer <s>] [--account <s>]   generates 20 random bytes, prints base32 then the URL otpauth://totp/<issuer>:<account>?secret=<b32>&issuer=<issuer>&algorithm=SHA1&digits=6&period=30
paasers version
```
* `hash-password` rejects an empty input (exit 2) and < 8 characters (exit 2, message).
* The otpauth URL is built by hand (percent-encoding via `url::form_urlencoded::byte_serialize`), no `otpauth` feature of totp-rs.
* `main()`: `ExitCode::SUCCESS` / `from(1)` runtime error / `from(2)` config or usage error.
* Runtime: `tokio::runtime::Builder::new_multi_thread().worker_threads(n).enable_all().build()` where `n = cfg.gateway.worker_threads.unwrap_or(min(available_parallelism, 4))`. The config is therefore read **before** creating the runtime (sync read `std::fs`).
* Logs: `tracing_subscriber::fmt()` + `EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.log.level))`, `.json()` if `log.json`. Initialized after reading the config; if the config fails, the error is printed directly on stderr.

## 3. Startup: exact sequence

`cli::main` (`paasers run`): `config::load(&path)` (sync, before the runtime; error ⇒ stderr + exit 2) ⇒ init logs ⇒ builds the tokio runtime ⇒ `rt.block_on(server::run_with(cfg, Some(path), ready_tx /*rx ignored*/, CancellationToken::new()))` ⇒ `Ok` exit 0, `Err` exit 1.

`run_with`:
1. `rustls::crypto::aws_lc_rs::default_provider().install_default()` (ignore `Err` = already installed).
2. (config already loaded, received as parameter)
3. `let db = storage::Db::open(&cfg.gateway.storage_path).await?` (P3; creates the parent directory if absent, mode 0700).
4. Long-lived shared state: `let shared = Arc::new(Shared::new(&cfg, db.clone()))` (§6).
5. `let runtime = routing::build(&cfg, &shared)?` (P4); `let current = Arc::new(ArcSwap::from_pointee(runtime))`.
6. TLS: `tls::CertManager::start(&cfg, db.clone(), shared.clone(), shutdown.clone())` (P7) ⇒ loads the certificates from the database, installs self-signed ones for the missing ones, starts the ACME worker.
7. Background tasks: health-checkers (P5), limiter purge (60 s), reload watcher (§7, only if `cfg_path` is `Some`), MCP (P11 if configured).
8. HTTP and HTTPS listeners (§4) bound; send `BoundAddrs { http, https: Option, mcp: Option }` on `ready` (ignore the error if the receiver is dropped).
9. Signal task: `ctrl_c` or `SIGTERM` (`tokio::signal::unix::signal(SignalKind::terminate())`) ⇒ `shutdown.cancel()`.
10. `shutdown.cancelled().await` ⇒ graceful shutdown §8 (the token can also be cancelled by a test).

## 4. Listeners (`listener.rs`, `http.rs`, `tls.rs`)

### 4.1 Socket (validated)
```rust
pub fn bind(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() { s.set_only_v6(false)?; }
    s.set_reuse_address(true)?; s.set_nonblocking(true)?; s.set_tcp_nodelay(true)?;
    s.bind(&addr.into())?; s.listen(1024)?;
    tokio::net::TcpListener::from_std(s.into())
}
```
If `bind([::]:p)` fails with `EAFNOSUPPORT` (IPv6 disabled) ⇒ retry on `0.0.0.0:p` with `warn!`.

### 4.2 Accept loop
```text
loop {
  select! { _ = shutdown.cancelled() => break,
            r = listener.accept() => {
               let (tcp, peer) = match r { Ok(x) => x, Err(e) => { warn!; sleep(50ms) if EMFILE/ENFILE; continue } };
               let Ok(permit) = conn_sem.clone().try_acquire_owned() else { drop(tcp); continue };  // max-connections
               tcp.set_nodelay(true) (ignore error);
               spawn(serve_conn(tcp, peer, kind, ...permit)) } }
}
```
`kind` = `Http` | `Https`. The permit is held by the connection task until it ends.

### 4.3 Connection service (validated in the spike)
```rust
// Compiled + clippy -D warnings OK. `S` = EntryService (concrete); generic here only because there is no .await before the call.
pub async fn serve_conn<I, S>(io: I, svc: S, http1_only: bool, header_read_timeout: Duration, max_headers: u64,
                              graceful: &hyper_util::server::graceful::GracefulShutdown)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: tower::Service<http::Request<hyper::body::Incoming>, Response = Resp, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    let mut b = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    b.http1().timer(TokioTimer::new()).header_read_timeout(header_read_timeout).keep_alive(true)
        .max_buf_size(usize::try_from(max_headers).unwrap_or(65_536).max(8192));
    b.http2().timer(TokioTimer::new()).max_concurrent_streams(250)
        .keep_alive_interval(Some(Duration::from_secs(30))).keep_alive_timeout(Duration::from_secs(20))
        .max_header_list_size(u32::try_from(max_headers).unwrap_or(65_536));
    let b = if http1_only { b.http1_only() } else { b };
    let conn = b.serve_connection_with_upgrades(TokioIo::new(io), hyper_util::service::TowerToHyperService::new(svc)).into_owned();
    let conn = graceful.watch(conn);
    if let Err(e) = conn.await { tracing::debug!(error = %e, "connection closed with error"); }
}
```
Note: hyper's `max_buf_size` must be ≥ 8192 (otherwise internal hyper panic): hence the mandatory `.max(8192)`, and the config validation `max-headers-size >= 8KiB`.
* Inactivity: in HTTP/1.1, hyper 1.11 arms `header_read_timeout` as soon as it waits for the header of the **next** request (verified in `proto/h1/conn.rs::poll_read_head`): an idle keep-alive connection is therefore closed after `header-read-timeout` (default 30 s). This same timeout protects against slowloris. In HTTP/2, dead peers are detected by ping (`keep_alive_interval` 30 s + `keep_alive_timeout` 20 s). There is **no** separate `idle-timeout` option.
* HTTPS: `tokio_rustls::TlsAcceptor::from(Arc<ServerConfig>).accept(tcp)` under `tokio::time::timeout(10s)`; failure/timeout ⇒ `debug!` and end. ALPN `["h2","http/1.1"]` (server).
* HTTP (:80): **no** h2c (cleartext h2): use `.http1_only()` on the auto builder for the HTTP listener.

## 5. `EntryService` (`entry.rs`)

Concrete `tower::Service<Request<Incoming>>` service, `Clone`, created per connection with: `peer: SocketAddr`, `scheme: Scheme`, `current: Arc<ArcSwap<Runtime>>`, `shared: Arc<Shared>`.

`call(req)` algorithm (everything is inside an `async move`, no panic possible):
1. `let start = Instant::now()`.
2. `let rt = current.load_full()` (snapshot for the whole request).
3. **Client IP**: `peer.ip().to_canonical()`; if this IP ∈ `rt.trusted_proxies` and header `X-Forwarded-For` present ⇒ take the **last** IP of the XFF list that is not in `trusted_proxies` (scanning right to left); parse failed ⇒ TCP IP.
4. **Trace** (`observe::trace::from_headers`) ⇒ `TraceCtx` (see plans/06).
5. **Host**: `req.uri().host()` (h2 `:authority`) otherwise `Host` header; strip port; lowercase; trim trailing `.`. Absent/invalid ⇒ 400 response (JSON/HTML depending on Accept, via `observe::fallback::render_error`).
6. **ACME challenge** (only if `scheme == http`): path starts with `/.well-known/acme-challenge/` ⇒ `shared.challenges.get(token)` ⇒ 200 `text/plain` key-authorization, otherwise 404. **Before** route resolution (the host may be in the middle of issuance).
7. **Route**: `rt.table.lookup(host)` ⇒ `Option<Arc<RouteRuntime>>`; `None` ⇒ 404 "Unknown host".
8. **HTTPS redirect**: `scheme == http` and `route.redirect_https` ⇒ 301 `Location: https://{host}{path_and_query}` (non-standard HTTPS port added if `listen_https.port() != 443`).
9. **Loop**: `Via` contains `paasers` ⇒ 508.
10. **Body size**: `Content-Length` > `limits.max_body` ⇒ 413. Otherwise body = `http_body_util::Limited::new(incoming, max_body)` then `boxed()` (exceeding while streaming produces a body error ⇒ the proxy returns 413 if the response has not started, tested: `Limited` returns Err beyond the limit).
11. Insert extensions: `ClientIp`, `Scheme`, `TraceCtx`, `RouteId`, `RequestStart`; then `routing::strip_spoofable(&mut req)` (plans/04 §4.4).
12. Call `route.service.clone().oneshot(req).await` (infallible); if the response carries `UpstreamUsed`, wrap its body in `WatchBody` (plans/06 §4).
13. Response post-processing: insert `traceparent` (new gateway span, see 06) and `x-request-id: <trace_id hex>`; record in the flight recorder if `status >= 400` or `ProxyFailure` extension present (06); `access log` `debug!` (method, host, path, status, duration ms, upstream, trace_id).
14. Return the response.

The 400/404/301/508/413 responses generated here also go through step 13 (flight recorder for ≥ 400).

## 6. `Shared` (long-lived state, survives reloads)

```rust
pub struct Shared {
    pub db: storage::Db,
    pub recorder: Arc<observe::FlightRecorder>,
    pub challenges: Arc<tls::ChallengeStore>,        // token -> key-auth, std::sync::RwLock<HashMap>
    pub certs: Arc<tls::CertResolver>,
    pub health: Arc<proxy::HealthRegistry>,          // SocketAddr -> Arc<UpstreamHealth>
    pub caches: Arc<cache::CacheRegistry>,           // RouteId -> Arc<HttpCache>
    pub limiters: Arc<layers::ratelimit::LimiterRegistry>, // (RouteId, path) -> Arc<Limiter>
    pub gate: Arc<gatekeeper::GateShared>,           // HMAC key, login limiters, TOTP anti-replay
    pub geoip: Arc<layers::geoip::GeoRegistry>,      // PathBuf -> Arc<Reader<Mmap>>
    pub client: proxy::UpstreamClient,               // shared hyper client (pool)
    pub tunnels: Arc<AtomicUsize>,                   // active WebSocket tunnels (plans/05 §7, MCP)
    pub started_at: std::time::SystemTime,
}
```
The registries are `std::sync::Mutex<HashMap<K, Arc<V>>>` with `get_or_create(key, || ...)` and `retain(active_keys)` called after each reload to free the entries of removed routes.

## 7. Reload (`reload.rs`)

* Triggers: `SIGHUP` (`signal(SignalKind::hangup())`) **or** change of `(mtime, len)` of the config file (poll `tokio::time::interval(2s)`, `MissedTickBehavior::Skip`).
* Procedure (serialized in **one** task, never two concurrent reloads):
  1. `config::load(path)`; error ⇒ `error!(%err, "config reload failed; keeping previous config")`, flight recorder `kind="config"`, end.
  2. Compare the "restart-only" fields (`gateway.listen*`, `storage_path`, `mcp`, `worker_threads`, `log`); difference ⇒ `warn!` per field, **ignore** these fields (keep the old ones).
  3. `routing::build(&new_cfg, &shared)`; error ⇒ same as 1.
  4. `current.store(Arc::new(new_runtime))`.
  5. `shared.*.retain(...)`; health-checkers: stop those of removed upstreams (child CancellationToken per upstream), start the new ones.
  6. `tls::CertManager::reconcile(&new_cfg)` (new domains ⇒ self-signed + ACME order).
  7. `info!(routes = n, "config reloaded")`.

## 8. Graceful shutdown (`shutdown.rs`)

1. `shutdown.cancel()` ⇒ the accept loops stop (no more new connections).
2. `tokio::time::timeout(cfg.gateway.shutdown_grace, graceful.shutdown()).await` (hyper sends h2 GOAWAY / closes h1 keep-alive after the in-flight request).
3. Timeout reached ⇒ `warn!("forced shutdown")`.
4. DB close (drop of the SQLite thread, WAL flush: `PRAGMA wal_checkpoint(TRUNCATE)`).
5. Return `Ok(())` ⇒ exit 0.

## 9. Tests

Unit:
- `entry::tests::client_ip_ignores_xff_from_untrusted`, `client_ip_uses_rightmost_untrusted_xff`, `client_ip_ipv4_mapped_canonical`.
- `entry::tests::host_from_authority_strip_port_lower_trailing_dot`, `missing_host_400`.
- `entry::tests::redirect_https_preserves_path_query_and_port`.
- `cli::tests::otpauth_url_encoding`.
- `listener::tests::dual_stack_accepts_ipv4` (bind `[::]:0`, connect `127.0.0.1`, validated in the spike).

Integration (`tests/proxy.rs`, via `tests/common::spawn_gateway(kdl) -> GatewayHandle { http_addr, https_addr, mcp_addr, shutdown }` which calls a public function `paasers::server::run_with(cfg: Config, ready: oneshot::Sender<BoundAddrs>)`):
- `unknown_host_404_has_request_id`.
- `graceful_shutdown_finishes_inflight`: slow backend 500 ms, shutdown during the request ⇒ 200 response received.
- `max_connections_enforced` (max=2, 3rd connection closed).

**API requirement for the tests**: a single public startup function, exact signature `pub async fn run_with(cfg: Config, cfg_path: Option<PathBuf>, ready: oneshot::Sender<BoundAddrs>, shutdown: CancellationToken) -> anyhow::Result<()>`. It receives an already parsed `Config`, returns via `ready` the actually bound addresses (port 0 ⇒ real port), and enables file reload only if `cfg_path` is `Some` (tested with `tempfile`). There is **no** separate `server::run(path)`: `cli` does `load` then `run_with` (§3).
`pub struct BoundAddrs { pub http: SocketAddr, pub https: Option<SocketAddr>, pub mcp: Option<SocketAddr> }` (actually bound addresses, via `listener.local_addr()`).

## 10. DoD P2
- [ ] `paasers check -c examples/gateway.kdl` ⇒ exit 0 (with `JWT_SECRET_KEY` set and an existing geoip: the example in `examples/` points to `tests/fixtures/GeoIP2-Country-Test.mmdb`).
- [ ] Gateway starts, responds 404 JSON on unknown host, shuts down cleanly on SIGTERM.
- [ ] §9 tests green. Commit `P2: server core`.
