//! rmcp handler: the four tools exposed to AI agents.
use super::{McpState, tools};
use crate::observe::Query;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use rmcp::{
    ErrorData, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
};
use serde_json::{Value, json};
use std::sync::Arc;

fn json_result(v: &Value) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(v.to_string())])
}

fn tool_error(msg: &str) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(msg.to_owned())])
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct RouteStatusArgs {
    #[schemars(description = "Host or route id. Omit to list every route.")]
    pub route: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct InspectArgs {
    #[schemars(description = "Incident ID shown to the user: the W3C trace_id, 32 hexadecimal characters.")]
    pub id: String,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct PurgeArgs {
    #[schemars(description = "Route id or host. Omit to target every route that has a cache.")]
    pub route: Option<String>,
    #[schemars(description = "Surrogate-Key tags to purge.")]
    pub tags: Option<Vec<String>>,
    #[schemars(description = "Purge entries of this host.")]
    pub host: Option<String>,
    #[schemars(description = "Purge entries whose path starts with this prefix.")]
    pub path_prefix: Option<String>,
    #[schemars(description = "Purge everything.")]
    pub all: Option<bool>,
}

#[derive(Clone)]
pub struct Gw {
    state: Arc<McpState>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl Gw {
    pub fn new(state: Arc<McpState>) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Route status: hosts, upstreams (health, weight, last error), cache, TLS certificates."
    )]
    async fn get_route_status(
        &self,
        Parameters(a): Parameters<RouteStatusArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let certs = self.state.certs.report();
        let rt = self.state.current.load_full();
        let uptime = self.state.started_at.elapsed().map_or(0, |d| d.as_secs());
        let tunnels = self.state.tunnels.load(std::sync::atomic::Ordering::Relaxed);
        Ok(
            match tools::status_json(&rt, a.route.as_deref(), &certs, uptime, tunnels) {
                Ok(v) => json_result(&v),
                Err(e) => tool_error(&e),
            },
        )
    }

    #[tool(
        description = "Lists the latest failed requests (4xx/5xx/timeouts) and events (health, acme, config), most recent first."
    )]
    async fn query_flight_recorder(
        &self,
        Parameters(q): Parameters<Query>,
    ) -> Result<CallToolResult, ErrorData> {
        let r = &self.state.recorder;
        let incidents = r.query(&q);
        Ok(json_result(&json!({
            "total_recorded": r.total(), "returned": incidents.len(), "capacity": r.capacity(), "incidents": incidents,
        })))
    }

    #[tool(
        description = "Details of an incident from the Incident ID (W3C trace_id, 32 hexadecimal characters) shown to the user."
    )]
    async fn inspect_incident(
        &self,
        Parameters(a): Parameters<InspectArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let id = match tools::normalize_incident_id(&a.id) {
            Ok(i) => i,
            Err(e) => return Ok(tool_error(e)),
        };
        let entries = self.state.recorder.get(&id);
        let Some(last) = entries.last() else {
            let hint = format!(
                "Unknown incident or evicted from the flight recorder (capacity {}).",
                self.state.recorder.capacity()
            );
            return Ok(json_result(
                &json!({"id": id, "found": false, "entries": [], "route": null, "hint": hint}),
            ));
        };
        let rt = self.state.current.load_full();
        let certs = self.state.certs.report();
        let route = entries
            .first()
            .and_then(|e| e.route_id.as_deref())
            .and_then(|r| tools::find_route(&rt, r))
            .map(|r| tools::route_json(r, &certs));
        Ok(json_result(
            &json!({"id": id, "found": true, "entries": entries, "route": route, "hint": tools::hint(last)}),
        ))
    }

    #[tool(description = "Purges the HTTP cache by Surrogate-Key tags, by host/path prefix, or entirely.")]
    async fn purge_cache(&self, Parameters(a): Parameters<PurgeArgs>) -> Result<CallToolResult, ErrorData> {
        let purge = match tools::purge_from(a.tags, a.host.clone(), a.path_prefix, a.all) {
            Ok(p) => p,
            Err(e) => return Ok(tool_error(e)),
        };
        let rt = self.state.current.load_full();
        let targets = match (a.route.as_deref(), a.host.as_deref()) {
            (Some(r), _) => match tools::find_route(&rt, r) {
                Some(x) => vec![x.clone()],
                None => return Ok(tool_error("unknown route")),
            },
            (None, Some(h)) => match rt.table.lookup(&h.trim().to_ascii_lowercase()) {
                Some(x) => vec![x.clone()],
                None => return Ok(tool_error("unknown route")),
            },
            (None, None) => rt.table.routes().to_vec(),
        };
        let (mut purged, mut routes) = (0, Vec::new());
        for r in targets.iter().filter(|r| r.cache.is_some()) {
            if let Some(c) = &r.cache {
                purged += c.purge(&purge);
                routes.push(r.id.to_string());
            }
        }
        tracing::info!(purged, routes = ?routes, tags = ?purge.tags, host = ?purge.host, prefix = ?purge.path_prefix, all = purge.all, "cache purged via MCP");
        Ok(json_result(&json!({"purged": purged, "routes": routes})))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Gw {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("paasers", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Edge gateway paasers. Tools: get_route_status, query_flight_recorder, inspect_incident, purge_cache. \
                 The Incident ID shown to users is the W3C trace_id (32 hex).",
            )
    }
}

/// Stateless Streamable HTTP service with JSON responses. Without a token, rmcp's loopback `Host` check stays on.
pub fn service(state: Arc<McpState>, has_token: bool) -> StreamableHttpService<Gw, LocalSessionManager> {
    let mut cfg = StreamableHttpServerConfig::default();
    if has_token {
        cfg = cfg.disable_allowed_hosts();
    }
    cfg.json_response = true;
    cfg.legacy_session_mode = false;
    StreamableHttpService::new(move || Ok(Gw::new(state.clone())), Default::default(), cfg)
}
