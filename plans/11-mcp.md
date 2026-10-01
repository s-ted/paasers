# P11: MCP server (`src/mcp/`)

> DECISION D25: rmcp 3.5.0 **Streamable HTTP** transport (successor of SSE), **stateless** mode + JSON responses, served directly by hyper (no axum). All the code in this document has been **compiled and executed** (tests `initialize`, `tools/list`, `tools/call`, error result).

## 1. Files

| File | Role |
|---|---|
| `mcp/mod.rs` | `pub async fn serve(cfg: McpCfg, state: Arc<McpState>, shutdown)`: listener + accept loop |
| `mcp/auth.rs` | Wrapper service: `/healthz`, Bearer check, `/mcp` route |
| `mcp/server.rs` | `Gw` (ServerHandler + `#[tool_router]`) |
| `mcp/tools.rs` | pure functions that build the output JSON (testable without rmcp) |

## 2. Accessible state

```rust
pub struct McpState {
    pub current: Arc<ArcSwap<Runtime>>,     // routes, balancers (health), caches
    pub recorder: Arc<FlightRecorder>,
    pub certs_db: storage::Db,              // not_after per domain
    pub started_at: SystemTime,
    pub tunnels: Arc<AtomicUsize>,
}
```

## 3. rmcp handler (exact validated pattern)

```rust
use rmcp::{ErrorData, ServerHandler, handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig}, schemars, tool, tool_handler, tool_router};

#[derive(Clone)]
pub struct Gw { state: Arc<McpState>, tool_router: ToolRouter<Self> }
fn json_result(v: &serde_json::Value) -> CallToolResult { CallToolResult::success(vec![ContentBlock::text(v.to_string())]) }
fn tool_error(msg: &str) -> CallToolResult { CallToolResult::error(vec![ContentBlock::text(msg.to_owned())]) }

#[tool_router]
impl Gw {
    pub fn new(state: Arc<McpState>) -> Self { Self { state, tool_router: Self::tool_router() } }
    #[tool(description = "...")]
    async fn get_route_status(&self, Parameters(a): Parameters<RouteStatusArgs>) -> Result<CallToolResult, ErrorData> { ... }
    // same for the 3 other tools
}
#[tool_handler]
impl ServerHandler for Gw {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("paasers", env!("CARGO_PKG_VERSION")))
            .with_instructions("Edge gateway paasers. Tools: get_route_status, query_flight_recorder, inspect_incident, purge_cache. The Incident ID shown to users is the W3C trace_id (32 hex).")
    }
}
pub fn service(state: Arc<McpState>) -> StreamableHttpService<Gw, LocalSessionManager> {
    let mut cfg = StreamableHttpServerConfig::default().disable_allowed_hosts();
    cfg.json_response = true;
    cfg.legacy_session_mode = false;
    StreamableHttpService::new(move || Ok(Gw::new(state.clone())), Default::default(), cfg)
}
```
* `disable_allowed_hosts()`: by default rmcp only accepts loopback `Host` values (anti DNS-rebinding); protection here is provided by the **Bearer token** (and/or loopback listening, plans/01 §3.3). If **no** token is configured, do **not** call `disable_allowed_hosts()` (keep rmcp's loopback protection).
* Business errors (unknown id, invalid argument) ⇒ `Ok(tool_error(..))` (`isError: true`, verified); `Err(ErrorData)` reserved for unexpected internal errors (`ErrorData::internal_error(msg, None)`).
* Argument structs derive `Debug, Default, serde::Deserialize, schemars::JsonSchema` (`use rmcp::schemars`). Optional fields = `Option<T>` (schema `["string","null"]`, verified). Descriptions via `#[schemars(description = "...")]`.

## 4. Tools: exact inputs / outputs

All outputs = **one** `ContentBlock::text` containing compact JSON.

### 4.1 `get_route_status`
Description: "Route status: hosts, upstreams (health, weight, last error), cache, TLS certificates."
Input: `{ "route": string? }` (host or route_id; absent = all).
Output:
```json
{"generation":3,"uptime_s":1234,"active_tunnels":2,
 "routes":[{"id":"client.com","hosts":["client.com","www.client.com"],"tls":"acme",
   "upstreams":[{"addr":"10.0.1.10:8080","weight":90,"healthy":true,"consecutive_failures":0,"last_change":"2026-09-30T12:00:00.000Z","last_error":null}],
   "healthy_upstreams":1,"total_upstreams":2,
   "cache":{"entries":12,"weight_bytes":34567,"capacity_bytes":256000000,"hits":100,"misses":20,"stale":3,"bypass":5},
   "certificates":[{"domain":"client.com","not_after":"2026-12-29T00:00:00.000Z","days_left":90,"self_signed":false}],
   "features":["cache","compression","geoip","fallback"]}]}
```
`cache` = `null` if not configured. `certificates`: read from the database (`storage::list_certs`); a domain without a database row but in ACME mode ⇒ `{"domain":..,"not_after":null,"days_left":null,"self_signed":true}`. Unknown route ⇒ `tool_error("unknown route")`.

### 4.2 `query_flight_recorder`
Description: "Lists the latest failed requests (4xx/5xx/timeouts) and events (health, acme, config), most recent first."
Input = `observe::recorder::Query` (plans/06 §3): `limit?`, `status_min?`, `status_max?`, `host?`, `route_id?`, `kind?`, `since_unix_ms?`, `path_prefix?`.
Output: `{"total_recorded":1234,"returned":50,"capacity":500,"incidents":[Incident, ...]}` (serde serialization of `Incident`).

### 4.3 `inspect_incident`
Description: "Details of an incident from the Incident ID (W3C trace_id, 32 hexadecimal characters) shown to the user."
Input: `{ "id": string }` required. Normalization: trim, lowercase, removal of any dashes; must be 32 hex otherwise `tool_error("invalid incident id: expected 32 hex characters")`.
Output: `{"id":"...","found":true,"entries":[Incident...],"route":<route object from 4.1 for entries[0].route_id or null>,"hint":"..."}`.
`hint` (deterministic rules on the `kind` of the last entry):
| kind | hint |
|---|---|
| `upstream_connect` | "Backend {upstream} refuses the connection: process stopped or wrong port." |
| `upstream_timeout` | "Backend {upstream} did not respond in time (request timeouts)." |
| `no_healthy_upstream` | "No healthy backend for route {route_id}: see get_route_status." |
| `upstream_error` / `upstream_body_error` | "Protocol error or connection cut by backend {upstream} during the response." |
| `rate_limited` | "Client limited by rate-limit." |
| `auth` | "Authentication failure (gatekeeper/JWT/API key)." |
| `geo_blocked` | "Country blocked by the GeoIP rule." |
| `payload_too_large` | "Request body larger than limits max-body." |
| other | "See detail." |
Not found (evicted from the ring buffer or unknown) ⇒ `{"id":"...","found":false,"entries":[],"route":null,"hint":"Unknown incident or evicted from the flight recorder (capacity N)."}` (**not** a tool error).

### 4.4 `purge_cache`
Description: "Purges the HTTP cache by Surrogate-Key tags, by host/path prefix, or entirely."
Input: `{ "route": string?, "tags": [string]?, "host": string?, "path_prefix": string?, "all": bool? }`.
* At least one of `tags`, `host`, `path_prefix`, `all=true`; otherwise `tool_error("specify tags, host, path_prefix or all")`.
* `route` absent ⇒ all routes that have a cache; otherwise that route (unknown ⇒ `tool_error`).
* `host` provided without `route` ⇒ route resolved via `table.lookup(host)`.
Output: `{"purged":42,"routes":["client.com"]}`. `info!` with the criteria (audit).

## 5. HTTP wrapper (`auth.rs`)

Concrete hyper service per connection:
1. `GET /healthz` ⇒ 200 `text/plain` `ok` (no auth).
2. Path ≠ `/mcp` ⇒ 404.
3. If a token is configured: the `Authorization` header must equal `Bearer <token>`; **constant-time** comparison: `subtle::ConstantTimeEq` on `sha256(provided)` vs `sha256(expected)` (equalizes lengths). Failure ⇒ 401 `WWW-Authenticate: Bearer` + JSON `{"error":"unauthorized"}`.
4. Body limited to 1 MiB (`Limited`), converted to `Body`; call `service.clone().oneshot(req)`; the rmcp response (`Response<BoxBody<Bytes, Infallible>>`) is converted via `map_resp`.

Server: listener `bind(cfg.listen)` (plans/02 §4.1), `hyper_util::server::conn::auto::Builder` **http1 only**, no TLS (loopback/admin network; put behind an SSH tunnel if remote). Shutdown via the same `CancellationToken` + `GracefulShutdown`.

## 6. Client configuration (documented in README)

```json
{ "mcpServers": { "paasers": { "url": "http://127.0.0.1:9090/mcp",
    "headers": { "Authorization": "Bearer secret-mcp-token-interne" } } } }
```
(Claude Desktop / Cursor: "streamable-http" transport.) Via tunnel: `ssh -L 9090:127.0.0.1:9090 gateway-vm`.

## 7. Tests

Unit (`tools.rs`, pure functions): `route_status_json_shape`, `hint_per_kind`, `normalize_incident_id` (uppercase, dashes, length), `purge_requires_criteria`.
Integration `tests/mcp.rs` (full gateway launched via `spawn_gateway`, raw JSON-RPC requests via hyper client, headers `Content-Type: application/json`, `Accept: application/json, text/event-stream`, `MCP-Protocol-Version: 2025-11-25`):
- `healthz_no_auth`, `mcp_requires_token_401`, `wrong_token_401`.
- `initialize_ok` (response contains `"serverInfo":{"name":"paasers"`).
- `tools_list_has_four_tools`.
- `incident_roundtrip`: backend stopped ⇒ request ⇒ fallback page; extract the Incident ID (regex `[0-9a-f]{32}`) ⇒ `tools/call inspect_incident` ⇒ `found: true`, kind `upstream_connect` or `no_healthy_upstream`.
- `purge_by_tag`: backend returns `Surrogate-Key: product-1` + `Cache-Control: max-age=60`; GET ×2 (HIT); purge tag ⇒ `purged: 1`; next GET ⇒ MISS.
- `query_flight_recorder_filters_status`.

## 8. DoD P11
- [ ] Tests §7 green. Commit `P11: mcp`.
