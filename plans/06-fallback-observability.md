# P6: Trace context, Flight Recorder, Fallback (`src/observe/`, `src/layers/fallback.rs`)

## 1. Files

| File | Role |
|---|---|
| `observe/trace.rs` | W3C `traceparent` parsing/generation (via `fastrace::collector::SpanContext`) |
| `observe/recorder.rs` | `FlightRecorder` (ring buffer), `Incident`, queries/filters |
| `observe/fallback.rs` | HTML/JSON rendering of error pages (pure functions) |
| `observe/fallback.html` | inline HTML template |
| `observe/body_watch.rs` | `WatchBody`: records errors occurring while streaming the response body |
| `layers/fallback.rs` | `FallbackLayer` |

## 2. Trace context (`trace.rs`)

```rust
use fastrace::collector::{SpanContext, SpanId, TraceId};

// fastrace `TraceId::random()`/`SpanId::random()` = `rand::random()`: CAN be 0 (invalid per W3C).
pub fn nz128() -> u128 { rand::random::<u128>().max(1) }
pub fn nz64() -> u64 { rand::random::<u64>().max(1) }

/// Reads `traceparent`; valid ⇒ reuses trace_id (D4), parent = incoming span; otherwise generates.
pub fn from_headers(h: &http::HeaderMap) -> TraceCtx {
    let incoming = h.get("traceparent").and_then(|v| v.to_str().ok())
        .and_then(SpanContext::decode_w3c_traceparent);
    let span_id = nz64();
    match incoming {
        Some(sc) => TraceCtx { trace_id: sc.trace_id.0, parent_span: Some(sc.span_id.0), span_id, sampled: sc.sampled },
        None => TraceCtx { trace_id: nz128(), parent_span: None, span_id, sampled: true },
    }
}
pub fn traceparent(t: &TraceCtx) -> String {
    SpanContext::new(TraceId(t.trace_id), SpanId(t.span_id)).sampled(t.sampled).encode_w3c_traceparent()
}
pub fn trace_hex(id: u128) -> String { format!("{id:032x}") }
```
* Code compiled + tested (reuse of an incoming trace_id, zero trace_id rejected then regenerated). `decode_w3c_traceparent` rejects version ≠ `00`, zero ids, invalid format; `encode_w3c_traceparent` produces `00-{:032x}-{:016x}-{:02x}`.
* Do **not** use `TraceId::random()`/`SpanId::random()` (no non-zero guarantee).
* Non-request events (health, acme, config) use `nz128()` as trace_id.
* **The same** `span_id` (the gateway's) is sent to the backend (`plans/05` §5.6) and returned to the client (`plans/02` §5.13). The **Incident ID** = `trace_hex(trace_id)` (32 lowercase hex).
* No fastrace reporter is installed (no span collection): only the `SpanContext` type is used.

## 3. Flight Recorder (`recorder.rs`)

```rust
#[derive(Clone, Debug, serde::Serialize)]
pub struct Incident {
    pub trace_id: String,            // 32 hex, = Incident ID
    pub ts: String,                  // RFC 3339 ms UTC: humantime::format_rfc3339_millis(SystemTime)
    pub ts_unix_ms: u64,
    pub kind: &'static str,          // "http" | "upstream_connect" | "upstream_timeout" | "upstream_error" | "no_healthy_upstream"
                                     // | "payload_too_large" | "upstream_body_error" | "health" | "acme" | "config" | "rate_limited" | "auth"
    pub status: Option<u16>,
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,        // path WITHOUT query string (no query secrets in logs)
    pub route_id: Option<String>,
    pub client_ip: Option<String>,
    pub upstream: Option<String>,
    pub duration_ms: Option<u64>,
    pub detail: Option<String>,      // error message (truncated to 512 characters, on a char boundary)
    pub user_agent: Option<String>,  // truncated to 256
}
pub struct FlightRecorder { inner: std::sync::Mutex<VecDeque<Arc<Incident>>>, capacity: usize, total: AtomicU64 }
impl FlightRecorder {
    pub fn new(capacity: usize) -> Self;
    pub fn record(&self, i: Incident);          // push_back; if len > capacity: pop_front; total += 1
    pub fn get(&self, trace_id: &str) -> Vec<Arc<Incident>>;  // all entries for this trace_id (chronological order)
    pub fn query(&self, q: &Query) -> Vec<Arc<Incident>>;     // most recent first
    pub fn total(&self) -> u64;
    pub fn len(&self) -> usize;
}
// at the top of the file: `use rmcp::schemars;` (see plans/00 §2)
#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct Query {
    pub limit: Option<usize>,        // default 50, max 500
    pub status_min: Option<u16>, pub status_max: Option<u16>,
    pub host: Option<String>,        // exact equality (normalized lowercase)
    pub route_id: Option<String>,
    pub kind: Option<String>,
    pub since_unix_ms: Option<u64>,
    pub path_prefix: Option<String>,
}
```
* `std::sync::Mutex` lock: O(1) critical section for `record`, O(n≤capacity) for `query` (copying `Arc`s); never held across an `.await`. Poisoned mutex ⇒ `lock().unwrap_or_else(PoisonError::into_inner)` (no panic).
* Unknown `trace_id` in `get` ⇒ `vec![]`.
* **What to record** (single rule applied by `EntryService`, `plans/02` §5.13): `status >= 400` **or** `ProxyFailure` extension present. `kind` = `ProxyFailure.kind` if present, otherwise `IncidentKind(&'static str)` extension set by a layer (`"rate_limited"`, `"auth"`, `"geo_blocked"`), otherwise `"http"`. Plus non-request events: health (`plans/05`), acme (`plans/07`), config (`plans/02` §7), trace_id = `nz128()`.
* `upstream_body_error`: see §4.

## 4. `WatchBody` (`body_watch.rs`): errors during streaming

The status is already sent when a backend cuts off in the middle of the body; we can only record it. `EntryService` wraps **every** response body that has an `UpstreamUsed` extension:
```rust
pin_project_lite::pin_project! {
    pub struct WatchBody { #[pin] inner: Body, on_error: Option<Box<dyn FnOnce(String) + Send + Sync>> }
}
impl WatchBody { pub fn new(inner: Body, f: Box<dyn FnOnce(String) + Send + Sync>) -> Self { Self { inner, on_error: Some(f) } } }
impl http_body::Body for WatchBody {
    type Data = Bytes; type Error = BoxError;
    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.project();
        let r = this.inner.poll_frame(cx);
        if let Poll::Ready(Some(Err(e))) = &r && let Some(f) = this.on_error.take() { f(e.to_string()) }
        r
    }
    fn is_end_stream(&self) -> bool { self.inner.is_end_stream() }
    fn size_hint(&self) -> http_body::SizeHint { self.inner.size_hint() }
}
```
(Compiled, strict clippy OK, test `records_error_once` OK; `if let ... && let` = let-chains, stable in edition 2024 / rustc 1.95, required by clippy `collapsible_if`.) `on_error` records an `Incident { kind: "upstream_body_error", ... }` with the request's trace_id. The response is then `boxed()`.

## 5. Error rendering (`fallback.rs`, pure)

```rust
pub enum Format { Html, Json }
pub fn negotiate(accept: Option<&HeaderValue>) -> Format;
// Json if Accept contains "application/json" (or "+json") AND does not contain "text/html"; otherwise Html. Absent ⇒ Html.
pub struct ErrorPage<'a> { pub status: StatusCode, pub title: &'a str, pub message: &'a str,
                           pub incident_id: Option<&'a str>, pub ts: &'a str }
pub fn render(p: &ErrorPage, f: Format) -> Resp;
pub fn render_error(status: StatusCode, req_headers: &HeaderMap, trace: &TraceCtx) -> Resp; // default titles §5.3
```
### 5.1 JSON
```json
{"error":{"status":503,"title":"Service temporarily unavailable","message":"...","incident_id":"4bf92f3577b34da6a3ce929d0e0e4736","timestamp":"2026-09-30T12:00:00.000Z"}}
```
`incident_id` omitted if `show-incident-id=#false`. `Content-Type: application/json`. Serialized with `serde_json` (escaping guaranteed).

### 5.2 HTML (`fallback.html`, < 4 KB, `include_str!`)
Template with markers `{{STATUS}}`, `{{TITLE}}`, `{{MESSAGE}}`, `{{INCIDENT_BLOCK}}`, `{{TS}}`. All values **HTML-escaped** (`&`,`<`,`>`,`"`,`'`) by a function `html_escape(&str) -> Cow<str>` (pure, tested). `INCIDENT_BLOCK` = `<p class="id">Incident ID: <code id="iid">{{ID}}</code> <button type="button" id="cp">Copy</button></p>` or empty.
Content: `<!doctype html><html lang="en">`, `<meta name="viewport" ...>`, `<meta name="robots" content="noindex">`, inline CSS (≤ 1 KB, `system-ui` font stack, centered, dark mode via `prefers-color-scheme`), minimal inline JS: click ⇒ `navigator.clipboard.writeText(document.getElementById('iid').textContent)`.
Headers: `Content-Type: text/html; charset=utf-8`, `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`.
(Static page with no unescaped user content ⇒ `unsafe-inline` acceptable here; the gatekeeper uses a nonce, cf. plans/09.)

### 5.3 Default titles (non-fallback pages generated by the gateway)
| Status | Title | Message |
|---|---|---|
| 400 | Bad request | The request could not be understood. |
| 401 | Authentication required | You must authenticate to access this resource. |
| 403 | Access denied | You are not allowed to access this resource. |
| 404 | Unknown site | No site is configured for this domain name. |
| 413 | Request too large | The request body exceeds the allowed size. |
| 429 | Too many requests | Please wait before trying again. |
| 502/503/504 | (config fallback) | (config fallback) |
| 508 | Loop detected | The request was rejected because it loops through the gateway. |
| other | Error | An error occurred. |
All of them display the Incident ID (except fallback 5xx with `show-incident-id=#false`).

## 6. `FallbackLayer` (`layers/fallback.rs`)

Concrete Tower pattern (plans/00 §5). `call`:
1. Remember `accept = req.headers().get(ACCEPT).cloned()`, `trace = req.extensions().get::<TraceCtx>().cloned()`, `method`.
2. `let resp = inner.ready().await?.call(req).await?`.
3. If `resp.status()` ∈ `cfg.on` (default {502,503,504}):
   * `let failure = resp.extensions().get::<ProxyFailure>().cloned()`.
   * **Only if** `failure.is_some()` **or** the response body is empty (`size_hint().exact() == Some(0)`): replace the response with `render(ErrorPage { status: cfg.status, ... })`, **copying** the `ProxyFailure` and `UpstreamUsed` extensions onto the new response. If the backend returned a 503 **with** a body (application maintenance page), we let it pass through as is (the backend knows better).
   * The returned status is `cfg.status` (default 503) whatever the original status (502/503/504): consistent with the SPECS example `fallback status=503`. The original status is kept in `Incident.detail` (`"origin_status=502 ..."`).
   * `Retry-After: 30` added.
4. For `HEAD`: same status/headers, empty body.
5. Otherwise return `resp` unchanged.

## 7. Access log

`EntryService` emits at the end of the request: `tracing::info!(target: "access", method, host, path, status, dur_ms, upstream, trace_id, client_ip)` at **debug** level for status < 400, **info** for 4xx, **warn** for 5xx. (The default `info` level therefore shows only 4xx/5xx: minimal log footprint.)

## 8. Tests

- `trace::tests::reuses_valid_incoming_trace_id`, `generates_when_absent`, `rejects_invalid_version_zero_ids_garbage`, `encode_roundtrip`.
- `recorder::tests::capacity_evicts_oldest` (cap 3, 5 inserts ⇒ 3 most recent), `query_filters_combined`, `get_by_trace_id_multiple_entries`, `limit_capped_500`, `detail_truncated_on_char_boundary` (string with multi-byte characters).
- `fallback::tests::negotiate_json_vs_html`, `html_escapes_all`, `html_has_incident_id_and_csp`, `json_omits_incident_when_disabled`.
- `layers::fallback::tests::replaces_proxy_failure_502_with_503_page`, `keeps_backend_503_with_body`, `head_has_empty_body`, `passes_200`.
- `body_watch::tests::records_error_once` (body that emits a frame then an error).
- Integration: `tests/proxy.rs::fallback_incident_id_matches_recorder`: backend stopped ⇒ HTML page contains a 32-hex ID, which is found via `shared.recorder.get(id)` (then via MCP in P11).

## 9. DoD P6
- [ ] Tests §8 green. Commit `P6: observability & fallback`.
