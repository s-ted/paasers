# P5: Proxy, load-balancing, health-checks, WebSocket (`src/proxy/`)

## 1. Files

| File | Role |
|---|---|
| `proxy/mod.rs` | `ProxyService` (concrete Service), `ProxyError` |
| `proxy/client.rs` | `UpstreamClient`: shared legacy hyper-util client |
| `proxy/headers.rs` | request/response header rewriting (pure functions) |
| `proxy/balancer.rs` | `Balancer`, weighted selection among healthy ones |
| `proxy/health.rs` | `UpstreamHealth`, `HealthRegistry`, probe task |
| `proxy/upgrade.rs` | WebSocket / `Upgrade` tunnel |

## 2. Upstream client (`client.rs`, validated in the spike)

```rust
pub type UpstreamClient = hyper_util::client::legacy::Client<HttpConnector, Body>;
pub fn new_client() -> UpstreamClient {
    let mut conn = HttpConnector::new();
    conn.set_nodelay(true);
    conn.set_connect_timeout(Some(Duration::from_secs(5)));   // global and fixed (§8)
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
```
A single client for the whole gateway (in `Shared`), reused across reloads (pool preserved).

**Connect timeout**: `HttpConnector::set_connect_timeout` is global to the client, which is itself shared and built only once. DECISION: connect timeout **fixed at 5 s**, not configurable; only `timeouts request=` is configurable per route (§8). Exceeding the connect timeout is an `is_connect()` error (⇒ 502 + passive marking), exceeding the request timeout ⇒ 504.

## 3. Balancer (`balancer.rs`)

```rust
pub struct Upstream { pub addr: SocketAddr, pub weight: u32, pub health: Arc<UpstreamHealth> }
pub struct Balancer { pub upstreams: Vec<Upstream> }
impl Balancer {
    /// Weighted random choice among healthy upstreams with weight > 0.
    pub fn pick(&self) -> Option<&Upstream> {
        let total: u64 = self.healthy().map(|u| u64::from(u.weight)).sum();
        if total == 0 { return None; }
        let mut r = rand::random_range(0..total);
        self.healthy().find(|u| { let w = u64::from(u.weight); if r < w { true } else { r -= w; false } })
    }
    fn healthy(&self) -> impl Iterator<Item = &Upstream> {
        self.upstreams.iter().filter(|u| u.weight > 0 && u.health.is_healthy())
    }
}
```
* Weighted random (not round-robin): no shared mutable state, compatible with Blue/Green 90/10.
* `pick_excluding(addr)`: same algorithm excluding one address (for the retry in §4 step 8).

## 4. `ProxyService::call`: exact algorithm

Input: `Req` (extensions set by Entry). Output: `Resp` (never an error).

1. `let Some(up) = balancer.pick() else { return failure(503, "no_healthy_upstream", None) }`.
2. Detect upgrade: `is_upgrade = req.headers().get(CONNECTION)` contains the token `upgrade` (case-insensitive, comma-separated list) **and** `Upgrade` header present. If so: `let client_upgrade = hyper::upgrade::on(&mut req);` (**before** destructuring the request).
3. `let (mut parts, body) = req.into_parts()`.
4. URI: `http://{up.addr}{path_and_query}` (`path_and_query` absent ⇒ `/`). Build via `http::Uri::builder().scheme("http").authority(addr.to_string()).path_and_query(pq).build()`; error ⇒ 400.
5. `headers::prepare_request(&mut parts, ctx)` (§5). **`parts.version = http::Version::HTTP_11`** (R6: the client rejects `HTTP_2`, observed).
6. `let fut = client.request(Request::from_parts(parts, body))`.
7. `match tokio::time::timeout(route.request_timeout, fut).await`:
   * `Err(_elapsed)` ⇒ `failure(504, "upstream_timeout", Some(up.addr))`, **no** unhealthy marking (slowness ≠ outage).
   * `Ok(Err(e)) if e.is_connect()` ⇒ `up.health.report_failure_passive()` (§6) then **a single retry** if `retryable`; otherwise `failure(502, "upstream_connect", Some(up.addr))`.
     `retryable` is computed **before** step 6: method ∈ {`GET`,`HEAD`,`OPTIONS`,`TRACE`} **and** `body.size_hint().exact() == Some(0)` **and** no upgrade. In this case only, before step 6, we keep `retry_parts = (method, uri_path_and_query, headers, version)` cloned (`http::request::Parts` is not `Clone`: clone field by field, extensions **not** copied). Retry: `balancer.pick_excluding(up.addr)`; `None` ⇒ `failure(502, ...)`; otherwise rebuild the URI with the new address, body `empty()`, and redo steps 6-7 **without** another retry.
   * Other `Ok(Err(e))` ⇒ if the `std::error::Error::source()` chain of `e` contains an `http_body_util::LengthLimitError` (`err.downcast_ref::<LengthLimitError>().is_some()` at each level, loop bounded to 10 levels) ⇒ `failure(413, "payload_too_large", None)`; otherwise `failure(502, "upstream_error", Some(up.addr))`.
   * `Ok(Ok(resp))` ⇒ continue.
8. `up.health.report_success_passive()`.
9. If `resp.status() == 101` and `is_upgrade`: `let upstream_upgrade = hyper::upgrade::on(&mut resp);` then `tokio::spawn(upgrade::tunnel(client_upgrade, upstream_upgrade))` (§7).
10. `headers::prepare_response(&mut resp)` (§5); insert extension `UpstreamUsed(up.addr)`.
11. Return `resp.map(boxed)`.

`failure(status, kind, upstream)` builds `Resp` (empty body, status) with the extension `ProxyFailure { kind, detail, upstream }`; the HTML/JSON rendering is done by the `FallbackLayer` (plans/06).

## 5. Headers (`headers.rs`, tested pure functions)

`prepare_request(parts, ctx)` where `ctx = { client_ip, scheme, host, trace: &TraceCtx }`:
1. Remove hop-by-hop: `connection`, `keep-alive`, `proxy-connection`, `te`, `trailer`, `transfer-encoding`, `upgrade`, `proxy-authorization`, `proxy-authenticate` **and** any header named in the value of `Connection`. **Upgrade exception**: if `is_upgrade`, put back `Connection: upgrade` and the original `Upgrade`.
2. Remove `expect`.
3. `Host`: keep the original host (`ctx.host`, with the original port if there was one); for an h2 request (no Host header), **insert** `Host: <authority>`.
4. `X-Forwarded-For`: if the TCP IP of the **peer** ∈ `trusted-proxies`, keep the incoming value and append `, {peer_ip}`; otherwise replace entirely with `{peer_ip}`. (`ctx` therefore also carries `peer_ip` and `peer_trusted: bool`.) `X-Real-IP: client_ip` (resolved client IP, plans/02 §5.3). `X-Forwarded-Proto: ctx.scheme`. `X-Forwarded-Host: ctx.host`.
5. `Via`: add `1.1 paasers` (append).
6. `traceparent`: `00-{trace_id:032x}-{new_span:016x}-{flags}` (gateway span, see plans/06); `tracestate` kept as is. `X-Request-Id: {trace_id:032x}` (overwrites any incoming value).

`prepare_response(resp)`: remove hop-by-hop (except for 101: keep `Connection`/`Upgrade`).

## 6. Health-checks (`health.rs`)

```rust
pub struct UpstreamHealth {
    healthy: AtomicBool,                 // initial = true (optimistic: no 503 at startup)
    consecutive_fail: AtomicU32,
    consecutive_ok: AtomicU32,
    last_change_unix: AtomicI64,
    last_error: std::sync::Mutex<Option<String>>,
    pub addr: SocketAddr,
}
```
* `is_healthy()`: `healthy.load(Relaxed)`.
* **Active**: one `tokio` task per unique address (even if shared between routes, config of the **first** route declaring it), started by `HealthRegistry::ensure_checker(addr, cfg, cancel)`.
  * Loop: `interval(cfg.interval)` with `MissedTickBehavior::Delay` + initial jitter `rand::random_range(0..interval_ms)`.
  * `http` mode: `GET http://{addr}{path}` with headers `Host: {addr}`, `User-Agent: paasers-health/1`, via the shared client, under `timeout(cfg.timeout)`. Success = response received with status `< 500`; the body is drained (`collect` limited to 64 KiB, ignored).
  * `tcp` mode: `timeout(cfg.timeout, TcpStream::connect(addr))`; success = connection established.
  * Success: `consecutive_fail = 0`, `consecutive_ok += 1`; if unhealthy and `consecutive_ok >= healthy_after` ⇒ switch to healthy, `info!(upstream, "upstream healthy")`.
  * Failure: `consecutive_ok = 0`, `consecutive_fail += 1`, `last_error = Some(msg)`; if healthy and `consecutive_fail >= unhealthy_after` ⇒ switch to unhealthy, `warn!`, flight recorder `kind="health"`.
* **Passive**: `report_failure_passive()` ⇒ switches **immediately** to unhealthy (D3 "instant removal") and `consecutive_ok = 0`; the active probe will make it healthy again after `healthy_after` successes. `report_success_passive()` ⇒ does nothing if unhealthy (only the probe rehabilitates), resets `consecutive_fail` if healthy.
* `enabled=#false` ⇒ no active task; passive still applies, **but** an upstream turned unhealthy without an active probe would stay unhealthy forever ⇒ in this case, `report_failure_passive` is **ignored** (upstream always healthy).
* "All unhealthy" case ⇒ 503 `no_healthy_upstream` (fallback).

## 7. Tunnel (`upgrade.rs`, validated in the spike)

```rust
pub async fn tunnel(client: hyper::upgrade::OnUpgrade, upstream: hyper::upgrade::OnUpgrade) {
    let (c, u) = tokio::join!(client, upstream);
    let (Ok(c), Ok(u)) = (c, u) else { debug!("upgrade failed"); return };
    let (mut c, mut u) = (TokioIo::new(c), TokioIo::new(u));
    if let Err(e) = tokio::io::copy_bidirectional(&mut c, &mut u).await { debug!(error = %e, "tunnel closed"); }
}
```
`AtomicUsize` counter of active tunnels in `Shared` (exposed by MCP `get_route_status`).

## 8. Grammar change (DECISION, carried over into `plans/01-config.md` §3.7)

`timeouts connect=` is **not** supported (the hyper-util connector has a global timeout): `timeouts request="60s"` only. Connect timeout fixed at 5 s.

## 9. Tests

Unit:
- `balancer::tests::weighted_distribution_90_10` (100 000 draws, share of the 1st ∈ [0.88, 0.92]).
- `balancer::tests::skips_unhealthy_and_zero_weight`, `none_when_all_unhealthy`.
- `headers::tests::strips_hop_by_hop_and_connection_listed`, `xff_appends_trusted_resets_untrusted`, `h2_request_gets_host_header`, `upgrade_keeps_connection_upgrade`, `via_appended`, `request_id_overwritten`.
- `health::tests::passive_failure_marks_unhealthy_immediately`, `recovers_after_healthy_after_successes`, `passive_ignored_when_active_disabled`.

Integration (`tests/proxy.rs`, `tests/health.rs`) with local hyper backends:
- `proxies_get_and_post_body` (echo of a 1 MiB body).
- `h2_client_to_h1_backend` (h2 TLS client via `hyper::client::conn::http2`, backend receives HTTP/1.1 + Host).
- `websocket_echo` (raw HTTP/1.1 handshake, validated in the spike).
- `backend_down_gives_502_then_503_after_unhealthy`.
- `backend_timeout_504` (backend sleeps 2 s, `timeouts request="500ms"`).
- `retry_idempotent_on_connect_error` (2 upstreams, one closed port: 100 GET ⇒ 100 × 200).
- `body_over_limit_413`.
- `health_recovery` (backend stopped then restarted on the same port ⇒ becomes healthy again in ≤ interval × (healthy_after + 1)).

## 10. DoD P5
- [ ] Tests §9 green. Commit `P5: proxy`.
