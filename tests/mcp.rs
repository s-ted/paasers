//! MCP server integration tests (P11): raw JSON-RPC against a full gateway.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod common;
use bytes::Bytes;
use common::*;
use http_body_util::Full;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::time::Duration;

const TOKEN: &str = "mcp-secret-token-0123456789";

fn kdl(backend: SocketAddr, extra: &str) -> String {
    format!(
        "gateway {{\n listen \"127.0.0.1:0\"\n}}\nmcp-server {{\n listen \"127.0.0.1:0\"\n token \"{TOKEN}\"\n}}\nroute \"app.test\" {{\n upstream \"{backend}\"\n{extra}\n}}\n"
    )
}

fn mcp_addr(g: &GatewayHandle) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], g.addrs.mcp.unwrap().port()))
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
}

async fn tool(g: &GatewayHandle, name: &str, args: Value) -> (bool, Value) {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}});
    let (status, v) = mcp_call(mcp_addr(g), Some(TOKEN), &body).await;
    assert_eq!(status, 200, "{v}");
    let res = &v["result"];
    let text = res["content"][0]["text"].as_str().unwrap_or_default();
    (
        res["isError"].as_bool().unwrap_or(false),
        serde_json::from_str(text).unwrap_or(Value::String(text.into())),
    )
}

#[tokio::test]
async fn healthz_no_auth_and_token_required() {
    let dead = closed_port().await;
    let g = spawn_gateway(&kdl(dead, "")).await;
    let r = raw_request(
        mcp_addr(&g),
        "GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 200") && r.ends_with("ok"), "{r}");
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let (status, _) = mcp_call(mcp_addr(&g), None, &init).await;
    assert_eq!(status, 401);
    let (status, _) = mcp_call(mcp_addr(&g), Some("wrong-token-wrong-token"), &init).await;
    assert_eq!(status, 401);
    let r = raw_request(
        mcp_addr(&g),
        "GET /other HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 404"), "{r}");
    g.stop().await;
}

#[tokio::test]
async fn initialize_and_list_tools() {
    let dead = closed_port().await;
    let g = spawn_gateway(&kdl(dead, "")).await;
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}});
    let (status, v) = mcp_call(mcp_addr(&g), Some(TOKEN), &init).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["result"]["serverInfo"]["name"], "paasers", "{v}");
    let (_, v) = mcp_call(
        mcp_addr(&g),
        Some(TOKEN),
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )
    .await;
    let mut names: Vec<_> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "get_route_status",
            "inspect_incident",
            "purge_cache",
            "query_flight_recorder"
        ]
    );
    assert!(v["result"]["tools"][0]["inputSchema"].is_object());
    g.stop().await;
}

#[tokio::test]
async fn incident_roundtrip() {
    let dead = closed_port().await;
    let g = spawn_gateway(&kdl(dead, " health-check interval=\"30s\"")).await;
    let page = raw_request(g.http_addr(), &get("/boom")).await;
    assert!(page.starts_with("HTTP/1.1 503"), "{page}");
    let id = page
        .split("id=\"iid\">")
        .nth(1)
        .and_then(|t| t.split('<').next())
        .unwrap()
        .to_string();
    assert_eq!(id.len(), 32);
    let (err, v) = tool(&g, "inspect_incident", json!({"id": id.to_ascii_uppercase()})).await;
    assert!(!err);
    assert_eq!(v["found"], true, "{v}");
    assert_eq!(v["entries"][0]["kind"], "upstream_connect");
    assert_eq!(v["entries"][0]["path"], "/boom");
    assert!(v["hint"].as_str().unwrap().contains("refuses the connection"));
    assert_eq!(v["route"]["id"], "app.test");
    // Unknown IDs are a normal answer, malformed ones a tool error.
    let (err, v) = tool(&g, "inspect_incident", json!({"id": "0".repeat(32)})).await;
    assert!(!err && v["found"] == false);
    let (err, v) = tool(&g, "inspect_incident", json!({"id": "nope"})).await;
    assert!(err && v.as_str().unwrap().contains("invalid incident id"), "{v}");
    g.stop().await;
}

#[tokio::test]
async fn query_flight_recorder_filters_status() {
    let dead = closed_port().await;
    let g = spawn_gateway(&kdl(dead, " health-check interval=\"30s\"")).await;
    raw_request(g.http_addr(), &get("/a")).await;
    raw_request(
        g.http_addr(),
        "GET /x HTTP/1.1\r\nHost: unknown.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    let (_, all) = tool(&g, "query_flight_recorder", json!({})).await;
    assert!(
        all["returned"].as_u64().unwrap() >= 2 && all["capacity"] == 500,
        "{all}"
    );
    let (_, only404) = tool(
        &g,
        "query_flight_recorder",
        json!({"status_min": 400, "status_max": 404}),
    )
    .await;
    let list = only404["incidents"].as_array().unwrap();
    assert!(
        !list.is_empty() && list.iter().all(|i| i["status"] == 404),
        "{only404}"
    );
    let (_, by_host) = tool(
        &g,
        "query_flight_recorder",
        json!({"host": "unknown.test", "limit": 1}),
    )
    .await;
    assert_eq!(by_host["returned"], 1);
    g.stop().await;
}

#[tokio::test]
async fn route_status_reports_health_and_cache() {
    let (b, _h) = spawn_echo_backend().await;
    let g = spawn_gateway(&kdl(b, " cache")).await;
    let (err, v) = tool(&g, "get_route_status", json!({})).await;
    assert!(!err, "{v}");
    let r = &v["routes"][0];
    assert_eq!(
        (r["id"].as_str(), r["healthy_upstreams"].as_u64()),
        (Some("app.test"), Some(1))
    );
    assert!(r["cache"]["capacity_bytes"].is_u64());
    assert_eq!(r["upstreams"][0]["healthy"], true);
    let (err, v) = tool(&g, "get_route_status", json!({"route": "nope"})).await;
    assert!(err && v == "unknown route");
    g.stop().await;
}

#[tokio::test]
async fn purge_by_tag() {
    let (b, _h) = spawn_backend(|_| async {
        http::Response::builder()
            .header("cache-control", "max-age=60")
            .header("surrogate-key", "product-1")
            .body(Full::new(Bytes::from_static(b"item")))
            .unwrap()
    })
    .await;
    let g = spawn_gateway(&kdl(b, " cache")).await;
    raw_request(g.http_addr(), &get("/p/1")).await;
    for _ in 0..100 {
        if g.shared
            .caches
            .get("app.test")
            .is_some_and(|c| c.stats().entries >= 1)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let hit = raw_request(g.http_addr(), &get("/p/1"))
        .await
        .to_ascii_lowercase();
    assert!(hit.contains("x-cache: hit"), "{hit}");
    let (err, v) = tool(&g, "purge_cache", json!({})).await;
    assert!(err && v.as_str().unwrap().contains("specify tags"), "{v}");
    let (err, v) = tool(&g, "purge_cache", json!({"tags": ["product-1"]})).await;
    assert!(!err, "{v}");
    assert_eq!(
        (v["purged"].as_u64(), v["routes"][0].as_str()),
        (Some(1), Some("app.test"))
    );
    let miss = raw_request(g.http_addr(), &get("/p/1"))
        .await
        .to_ascii_lowercase();
    assert!(miss.contains("x-cache: miss"), "{miss}");
    let (err, _) = tool(&g, "purge_cache", json!({"all": true, "route": "nope"})).await;
    assert!(err);
    g.stop().await;
}
