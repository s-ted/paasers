# P4: Routing and runtime snapshot (`src/routing/`)

## 1. Files

| File | Role |
|---|---|
| `routing/mod.rs` | `Runtime`, `RouteRuntime`, `pub fn build(cfg, shared) -> Result<Runtime, BuildError>` |
| `routing/host.rs` | `host_key(host) -> String` (reversed labels) |
| `routing/table.rs` | `HostTable` (matchit) |
| `routing/stack.rs` | assembly of a route's Tower stack (order §1.3 of PLAN.md) |

## 2. Host table (D30, validated in the spike)

`matchit` is a **path** router; we use it as a radix tree over reversed DNS labels:

```rust
/// "www.client.com" -> "/com/client/www" ; "*.client.com" -> "/com/client/{w}"
pub fn host_key(host: &str) -> String {
    host.rsplit('.').fold(String::with_capacity(host.len() + 2), |mut acc, label| {
        acc.push('/');
        if label == "*" { acc.push_str("{w}") } else { acc.push_str(label) }
        acc
    })
}
```
* Hosts are already normalized and validated by the config (characters `[a-z0-9-]` only ⇒ no `{`/`}` can reach matchit).
* **Lookup key**: the request normalizes its host (plans/02 §5 step 5) then `host_key`; a request host containing a character outside `[a-z0-9.-]` ⇒ 400 **before** the lookup (avoids matchit special characters).
* Verified semantics: `/com/client/{w}` matches `dev.client.com` but **not** `a.b.client.com` (a single label, consistent with TLS wildcards) nor `client.com`. An exact host takes precedence over the wildcard (exact `www` vs `{w}`).
* Insertion: `router.insert(host_key(h), idx)` where `idx: usize` indexes `Vec<Arc<RouteRuntime>>`. Conflict (`InsertError`) ⇒ `BuildError` (should not happen after config validation).

```rust
pub struct HostTable { router: matchit::Router<usize>, routes: Vec<Arc<RouteRuntime>> }
impl HostTable {
    pub fn lookup(&self, host: &str) -> Option<&Arc<RouteRuntime>> {
        let key = host_key(host);
        self.router.at(&key).ok().and_then(|m| self.routes.get(*m.value))
    }
}
```

## 3. Runtime (immutable snapshot)

```rust
pub struct Runtime {
    pub table: HostTable,
    pub trusted_proxies: Vec<ipnet::IpNet>,
    pub https_port: Option<u16>,
    pub limits: Limits,
    pub generation: u64,              // incremented on each build (logs/MCP)
    pub config: Arc<Config>,          // for MCP get_route_status
}
pub struct RouteRuntime {
    pub id: Arc<str>,
    pub hosts: Vec<String>,
    pub cfg: Arc<RouteCfg>,
    pub service: RouteSvc,            // full Tower stack
    pub redirect_https: bool,
    pub balancer: Arc<proxy::Balancer>, // also used by MCP (health state)
    pub cache: Option<Arc<cache::HttpCache>>, // for MCP purge
}
```
`Runtime` is placed in `Arc<ArcSwap<Runtime>>` (`ArcSwap::from_pointee`, `load_full()` per request, `store(Arc::new(..))` on reload).

## 4. `build(cfg, shared)`: construction

For each route (config order):
1. `balancer = proxy::Balancer::new(&route.upstreams, &shared.health)`: fetches/creates the `Arc<UpstreamHealth>` of each address in `shared.health` (reused across reloads ⇒ health state preserved).
2. Base service: `proxy::ProxyService::new(balancer.clone(), shared.client.clone(), route.timeouts, route.id.clone())`.
3. Layers (from inside to outside, i.e. in the reverse order of the table in PLAN §1.3):
   ```rust
   let svc = RouteSvc::new(proxy);
   let svc = RouteSvc::new(FallbackLayer::new(route.fallback.clone()).layer(svc));
   // `cache: Option<Arc<HttpCache>>` obtained in step 5; `HttpCache` already contains its `CacheCfg`.
   let svc = match &cache { Some(c) => RouteSvc::new(CacheLayer::new(c.clone()).layer(svc)), None => svc };
   let svc = match &route.compression { Some(c) => layers::compression::wrap(svc, c), None => svc };
   let svc = match &route.transform   { Some(t) => RouteSvc::new(TransformLayer::new(t).layer(svc)), None => svc };
   let svc = match &route.jwt         { Some(j) => RouteSvc::new(JwtLayer::new(j)?.layer(svc)), None => svc };
   let svc = match &route.api_keys    { Some(k) => RouteSvc::new(ApiKeyLayer::new(k, route.jwt.is_some()).layer(svc)), None => svc };
   let svc = match &route.gatekeeper  { Some(g) => RouteSvc::new(GatekeeperLayer::new(g, &route, shared)?.layer(svc)), None => svc };
   let svc = if route.rate_limits.is_empty() { svc } else { RouteSvc::new(RateLimitLayer::new(&route, shared).layer(svc)) };
   let svc = match &route.geoip       { Some(g) => RouteSvc::new(GeoIpLayer::new(g, shared)?.layer(svc)), None => svc };
   ```
   (Explicit `match` form rather than `option_layer`: each step returns `RouteSvc`, which avoids the explosion of nested types and guarantees rule R5.)
4. **Systematic anti-spoofing** (D14), without a Layer: `EntryService` calls `routing::strip_spoofable(&mut req)` just before `oneshot`, for all routes. This function removes the incoming headers `x-user-id`, `x-user-email`, `x-user-roles`, `x-jwt-claims`, `x-api-key-name`, `x-country-code`.
5. Cache (computed **before** step 3): `let cache = route.cache.as_ref().map(|c| shared.caches.get_or_create(&route.id, c, &route.upstreams));` (`CacheRegistry`, plans/08 §6.0: fresh cache if the cache config or the upstreams have changed).

`BuildError`: `thiserror`, variants `Jwt(String)`, `GeoIp(String)`, `Gatekeeper(String)`, `Router(String)`. A build error at startup ⇒ exit 2; on reload ⇒ old config kept.

## 5. Tests

- `host::tests::host_key_exact_and_wildcard`.
- `table::tests::exact_beats_wildcard`, `wildcard_single_label_only` (`a.b.client.com` does not match `*.client.com`), `apex_not_matched_by_wildcard`, `unknown_none`.
- `mod::tests::build_two_routes_lookup` (test config with 2 routes, lookup of each host).
- `mod::tests::health_state_survives_rebuild`: build, mark an upstream unhealthy, rebuild ⇒ still unhealthy (same `Arc`).
- `mod::tests::cache_reset_when_upstreams_change`.

## 6. DoD P4
- [ ] `cargo test routing::` green. Commit `P4: routing`.
