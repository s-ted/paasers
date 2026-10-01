# P8: HTTP Cache RFC 9111 (subset) (`src/cache/`)

> DECISION D9/D10: shared **in-memory** cache, per route, weighted in bytes. Anything not explicitly cacheable according to this document => `BYPASS` (safe by default).

## 1. Files

| File | Role | Pure? |
|---|---|---|
| `cache/policy.rs` | parse `Cache-Control`, freshness computation, "storable" decision | yes |
| `cache/key.rs` | primary key, `Vary` check | yes |
| `cache/store.rs` | `HttpCache` (quick_cache), `Entry`, purge | no |
| `cache/tee.rs` | `TeeBody` (copies the body while streaming, validated in the spike) | no |
| `cache/cond.rs` | client conditional requests (304) | yes |
| `cache/layer.rs` | `CacheLayer` / `CacheService` | no |

## 2. Model

```rust
pub struct Entry {
    pub status: StatusCode,
    pub headers: HeaderMap,           // stored response headers (§5.4)
    pub body: Bytes,
    pub stored_at: Instant,           // for the age
    pub stored_at_unix: i64,
    pub initial_age: u64,             // value of the backend Age header at storage time (0 if absent)
    pub ttl: u64,                     // freshness lifetime in seconds
    pub swr: u64,                     // effective stale-while-revalidate (s)
    pub sie: u64,                     // effective stale-if-error (s)
    pub must_revalidate: bool,        // must-revalidate / proxy-revalidate => swr = sie = 0
    pub auth_ok: bool,                // stored for a request with Authorization/Cookie (public/s-maxage)
    pub vary: Vec<(HeaderName, Option<HeaderValue>)>, // Vary headers and values from the original request
    pub tags: Box<[String]>,          // Surrogate-Key
    pub host: String,
    pub path: String,                 // path + query
}
pub struct HttpCache {
    store: quick_cache::sync::Cache<String, Arc<Entry>, Weigh>,
    revalidating: std::sync::Mutex<HashSet<String>>,
    cfg: CacheCfg,
    hits: AtomicU64, misses: AtomicU64, stale: AtomicU64, bypass: AtomicU64,
}
#[derive(Clone)] pub struct Weigh;
impl quick_cache::Weighter<String, Arc<Entry>> for Weigh {
    fn weight(&self, k: &String, v: &Arc<Entry>) -> u64 {
        (k.len() + v.body.len() + v.headers.len() * 64 + 256) as u64
    }
}
// Construction (validated in the spike):
// Cache::with_weighter(estimated_items, cfg.max_size, Weigh), estimated_items = max(1024, max_size / 16384)
```
`age(e) = e.initial_age + e.stored_at.elapsed().as_secs()`. States:
* `fresh`: `age < ttl`
* `stale_swr`: `ttl <= age < ttl + swr`
* `stale_sie`: `ttl <= age < ttl + sie`
* `expired`: otherwise (removed on read).

## 3. `Cache-Control` (`policy.rs`)

`parse_cc(&HeaderMap) -> CacheControl`: merges all `cache-control` values; directives separated by `,`, trimmed, case-insensitive name, optional value after `=` (quotes removed); invalid numeric values => directive ignored; unknown directives ignored.
```rust
#[derive(Default, Debug, PartialEq)]
pub struct CacheControl { pub no_store: bool, pub no_cache: bool, pub private: bool, pub public: bool,
    pub max_age: Option<u64>, pub s_maxage: Option<u64>, pub must_revalidate: bool, pub proxy_revalidate: bool,
    pub swr: Option<u64>, pub sie: Option<u64> }
```
**Request** directives (client `Cache-Control`, `Pragma`) are **ignored** (usual CDN behavior, documented).

### 3.1 "Cacheable" request (lookup allowed)
Method `GET` or `HEAD`, **and** no `Range` header, **and** no upgrade. Otherwise => `BYPASS` (and §5.5 for invalidation).
`sensitive = Authorization present || Cookie present` (after the GatekeeperLayer has removed its own cookie).

### 3.2 "Storable" response
All conditions:
1. `GET` request (not HEAD: no body).
2. Status in {200, 203, 204, 300, 301, 308, 404, 410}.
3. `!no_store && !no_cache && !private`.
4. No `Set-Cookie` header.
5. `Vary` does not contain `*`.
6. If `sensitive`: `public || s_maxage.is_some()` required; then `auth_ok = true`.
7. `ttl > 0` with `ttl = s_maxage.or(max_age).or(expires - date).unwrap_or(cfg.default_ttl)` where `expires - date` is only used if both headers parse (`httpdate::parse_http_date`); negative => 0. (`Date` absent => use the current time.)
8. No `Content-Range`, status != 206.
9. `Content-Length` absent or <= `max_object_size`.
10. No `ProxyFailure` extension on the response.

`swr = if must_revalidate||proxy_revalidate {0} else { cc.swr.unwrap_or(cfg.stale_while_revalidate) }`; same for `sie`.

## 4. Key (`key.rs`)

`primary = format!("{host}{path_and_query}")` (normalized host, without port; `path_and_query` as received, `/` if absent). GET and HEAD share the key.
`Vary`: on save, for each name listed in the response `Vary` (separated by `,`, lowercase), record `(name, req.headers().get(name).cloned())`. On read, the entry only matches if **all** recorded values are equal (byte for byte) to those of the new request; otherwise => MISS (and the new response will replace the entry: one variant per key, KISS).

## 5. `CacheService::call`: exact algorithm

Preamble: if the request is not cacheable (§3.1) => call `inner`, apply §5.5, add `X-Cache: BYPASS`.

1. `key = primary(req)`. `lookup = cache.get(&key)` filtered by Vary and `(!sensitive || e.auth_ok)`.
2. **Fresh HIT**: respond from the entry (§5.3) with `X-Cache: HIT`.
3. **Stale SWR** (`stale_swr` and `swr > 0`): respond from the entry with `X-Cache: STALE`; if `cache.revalidating.insert(key)` succeeds => `tokio::spawn(revalidate(...))` (§5.2).
4. Otherwise (MISS, or expired, or stale beyond SWR):
   * If the entry exists and has `ETag`/`Last-Modified`: add `If-None-Match`/`If-Modified-Since` to the backend request **only if** the client did not send its own conditionals.
   * `resp = inner.call(req)`.
   * If `resp.status() == 304` **and** the gateway added the conditionals: refresh the entry (§5.2 step 3) and respond from it (`X-Cache: HIT`).
   * If (`resp.status() >= 500` **or** `ProxyFailure`) and entry in `stale_sie`: respond from the entry with `X-Cache: STALE` (no `Warning` header, obsolete since RFC 9111).
   * If storable (§3.2): wrap the body in `TeeBody::new(body, max_object_size, on_done)` where `on_done(bytes)` builds the `Entry` and `cache.insert(key, Arc::new(entry))`; `X-Cache: MISS`.
   * Otherwise: `X-Cache: MISS` (response not stored); remove any existing entry if the status is storable-but-not-cacheable (e.g. `no-store`): `cache.remove(&key)`.
5. Remove `Surrogate-Key` from every response returned to the client.
6. `CacheStatus` extension set with the same value as `X-Cache`.

### 5.1 `TeeBody`
Exact code (compiled, strict clippy OK, **tested behind a real hyper server**). Observed pitfall: hyper **stops polling** the body as soon as `is_end_stream()` becomes true (`Full` body) and therefore never observes `Ready(None)`. A first version that only finalized on `Ready(None)` never stored anything. Finalization therefore also happens after a frame if `inner.is_end_stream()`:
```rust
pin_project_lite::pin_project! {
    pub struct TeeBody { #[pin] inner: Body, buf: Option<BytesMut>, limit: usize, on_done: Option<Box<dyn FnOnce(Bytes) + Send + Sync>> }
}
impl TeeBody {
    pub fn new(inner: Body, limit: usize, on_done: Box<dyn FnOnce(Bytes) + Send + Sync>) -> Self {
        Self { inner, buf: Some(BytesMut::new()), limit, on_done: Some(on_done) }
    }
}
impl http_body::Body for TeeBody {
    type Data = Bytes; type Error = BoxError;
    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let mut this = self.project();
        let res = this.inner.as_mut().poll_frame(cx);
        match &res {
            Poll::Ready(Some(Ok(f))) => if let Some(d) = f.data_ref() {
                let over = this.buf.as_ref().is_some_and(|b| b.len() + d.len() > *this.limit);
                if over { *this.buf = None } else if let Some(b) = this.buf.as_mut() { b.extend_from_slice(d) }
            },
            Poll::Ready(Some(Err(_))) => { *this.buf = None; }
            Poll::Ready(None) | Poll::Pending => {}
        }
        // hyper stops polling as soon as is_end_stream() is true: finalize here too.
        let done = matches!(res, Poll::Ready(None))
            || (matches!(res, Poll::Ready(Some(Ok(_)))) && this.inner.is_end_stream());
        if done && let (Some(b), Some(f)) = (this.buf.take(), this.on_done.take()) { f(b.freeze()) }
        res
    }
    fn is_end_stream(&self) -> bool { self.inner.is_end_stream() }
    fn size_hint(&self) -> http_body::SizeHint { self.inner.size_hint() }
}
```
Overflow or error => buffer dropped; end of stream => `on_done` exactly once. Trailers ignored. Client that aborts => nothing stored. An empty body whose `is_end_stream()` is true **before** any poll is never polled => if `body.is_end_stream()` at the time of the storage decision (e.g. 204, `Content-Length: 0`), build the `Entry` directly with `Bytes::new()` without `TeeBody`.
Mandatory test: `tee::tests::stores_under_real_hyper_server` (local `hyper::server::conn::http1` server, `full(..)` body, raw TCP client => `on_done` receives the complete body).

### 5.2 Background revalidation
Before step 3, clone: `inner` (RouteSvc), `uri`, request `headers` **without** `If-*`, extensions `ClientIp`, `Scheme`, `TraceCtx` (new span), `RouteId`. The task:
1. Builds `GET uri` with these headers + `If-None-Match: <etag>` and/or `If-Modified-Since: <last-modified>` from the entry, body `empty()`.
2. `inner.oneshot(req)` under `timeout(30s)`.
3. `304` => new `Entry` = old one with `stored_at = now`, `initial_age = 0`, headers updated with those of the 304 (except `Content-Length`, `Content-Encoding`, `Transfer-Encoding`), `ttl` recomputed from the merged headers; `insert`.
4. Storable `2xx` => collect the body (`Limited` to `max_object_size`, via `http_body_util::BodyExt::collect`) and `insert`.
5. Other => change nothing.
6. **Always** `revalidating.remove(&key)` at the end (RAII guard `struct Guard` whose `Drop` removes the key, to cover panic/cancellation).

### 5.3 Response from an entry
`Response` with `status`, cloned `headers`, `Age: age(e)`, body `full(e.body.clone())` (zero-copy `Bytes`) except `HEAD` => `empty()` with `Content-Length` kept.
Client conditionals (`cond.rs`) evaluated **first**: `If-None-Match` (weak comparison: `W/` ignored, `*` matches) against the entry `ETag` => 304; otherwise `If-Modified-Since` (if no `If-None-Match`) >= `Last-Modified` => 304. The 304 carries `ETag`, `Cache-Control`, `Expires`, `Vary`, `Last-Modified`, `Date`, `Age`, empty body.

### 5.4 Stored headers
All response headers **except**: hop-by-hop, `Set-Cookie` (already excluded), `Surrogate-Key` (-> `tags`, space-separated, max 64 tags of 256 bytes), `Age`, `X-Cache`.

### 5.5 Invalidation by unsafe method (RFC 9111 §4.4)
`POST|PUT|PATCH|DELETE` request: after the response, if status 2xx/3xx => `cache.remove(primary(req))` + keys from the `Location`/`Content-Location` headers if same host.

## 6. Purge (`store.rs`), used by MCP

### 6.0 `CacheRegistry` (in `Shared`, plans/02 §6)
```rust
pub struct CacheRegistry { inner: std::sync::Mutex<HashMap<Arc<str>, (CacheCfg, Vec<UpstreamCfg>, Arc<HttpCache>)>> }
impl CacheRegistry {
    /// Reuses the cache if `cfg` AND `upstreams` are equal (PartialEq) to the stored ones, otherwise creates a new one.
    pub fn get_or_create(&self, route: &Arc<str>, cfg: &CacheCfg, upstreams: &[UpstreamCfg]) -> Arc<HttpCache>;
    /// Removes routes absent from `active` (called after each reload).
    pub fn retain(&self, active: &HashSet<Arc<str>>);
}
```
`CacheCfg` and `UpstreamCfg` derive `PartialEq` (plans/01 `model.rs`).

```rust
pub struct Purge { pub tags: Vec<String>, pub host: Option<String>, pub path_prefix: Option<String>, pub all: bool }
impl HttpCache { pub fn purge(&self, p: &Purge) -> usize }   // returns the number of removed entries
```
Implementation: `all` => `store.clear()` (count = `len()` before); otherwise `store.retain(|_k, e| !matches(e, p))` with counting via `AtomicUsize` in the closure. `matches` = (tags empty **or** non-empty intersection) **and** (host absent **or** equal) **and** (prefix absent **or** `e.path.starts_with`). At least one criterion required (otherwise 0, nothing purged). Validated in the spike: `retain` on quick_cache works.
Statistics: `stats() -> CacheStats { entries, weight_bytes, capacity_bytes, hits, misses, stale, bypass }` (`store.len()`, `store.weight()`, `store.capacity()`).

## 7. Tests

`policy.rs`: `parse_multiple_headers_and_quotes`, `invalid_number_ignored`, `ttl_precedence_smaxage_maxage_expires_default`, `not_storable_cases` (one test per §3.2 condition), `sensitive_requires_public`, `must_revalidate_disables_stale`.
`key.rs`: `vary_match_and_mismatch`, `vary_star_not_storable`.
`cond.rs`: `inm_weak_match`, `inm_star`, `ims_not_modified`, `inm_takes_precedence_over_ims`.
`store.rs`: `purge_by_tag`, `purge_by_host_prefix`, `purge_all_counts`, `purge_no_criteria_noop`, `weight_limits_capacity` (insert beyond `max_size`, check `weight() <= capacity`).
`layer.rs` (fake service counting calls):
- `miss_then_hit` (2 GETs => 1 backend call, 2nd response `X-Cache: HIT` + `Age`).
- `head_served_from_get_entry_without_body`.
- `swr_serves_stale_and_revalidates_once` (ttl 1 s, swr 30; `tokio::time::pause()` + `advance(2s)`; 3 concurrent requests => 3 x STALE, exactly 1 revalidation).
- `revalidation_304_refreshes`.
- `stale_if_error_on_502`.
- `set_cookie_not_stored`, `authorization_bypass_unless_public`, `range_bypass`.
- `surrogate_key_stripped_and_purgeable`.
- `post_invalidates`.
- `oversized_body_not_stored` (9 MiB streamed body without Content-Length).
- `client_304_from_cache`.
Integration `tests/cache.rs`: route with `cache` + `compression`, backend `Cache-Control: max-age=60`; 2nd request `Accept-Encoding: zstd` => HIT **and** `content-encoding: zstd` (compression above the cache).

## 8. DoD P8
- [ ] §7 tests green. Commit `P8: cache`.
