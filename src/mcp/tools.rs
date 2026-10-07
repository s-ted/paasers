//! Pure builders of the MCP tool outputs (testable without rmcp).
use crate::cache::Purge;
use crate::observe::Incident;
use crate::routing::{RouteRuntime, Runtime};
use crate::storage::now_unix;
use crate::tls::HostCert;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::SystemTime;

fn rfc3339(unix: i64) -> String {
    let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(unix.max(0).unsigned_abs());
    humantime::format_rfc3339_millis(t).to_string()
}

fn features(r: &RouteRuntime) -> Vec<&'static str> {
    let c = &r.cfg;
    [
        (c.static_files.is_some(), "static"),
        (c.cache.is_some(), "cache"),
        (c.compression.is_some(), "compression"),
        (c.geoip.is_some(), "geoip"),
        (c.allow_ips.is_some(), "allow-ips"),
        (!c.rate_limits.is_empty(), "rate-limit"),
        (c.gatekeeper.is_some(), "gatekeeper"),
        (c.jwt.is_some(), "jwt"),
        (c.api_keys.is_some(), "api-keys"),
        (c.transform.is_some(), "transform"),
        (c.fallback.is_some(), "fallback"),
        (c.retry, "retry"),
    ]
    .into_iter()
    .filter_map(|(on, n)| on.then_some(n))
    .collect()
}

pub type CertReport = std::collections::HashMap<String, HostCert>;

fn certificates(r: &RouteRuntime, certs: &CertReport) -> Vec<Value> {
    if r.cfg.tls.is_none() {
        return Vec::new();
    }
    let now = now_unix();
    r.hosts
        .iter()
        .map(|h| match certs.get(h) {
            Some(c) => json!({
                "domain": h, "source": c.source, "not_after": rfc3339(c.not_after),
                "days_left": (c.not_after - now).div_euclid(86_400),
                "path": c.path, "acme_directory": c.acme_directory,
            }),
            None => json!({"domain": h, "source": null, "not_after": null, "days_left": null}),
        })
        .collect()
}

pub fn route_json(r: &RouteRuntime, certs: &CertReport) -> Value {
    let ups: Vec<Value> = r
        .balancer
        .upstreams
        .iter()
        .map(|u| {
            json!({
                "addr": u.addr.to_string(), "weight": u.weight, "healthy": u.health.is_healthy(),
                "last_change": rfc3339(u.health.last_change_unix()), "last_error": u.health.last_error(),
            })
        })
        .collect();
    let tls = match r.cfg.tls.as_ref().map(|t| &t.mode) {
        Some(crate::config::TlsMode::Auto { .. }) => json!("auto"),
        Some(crate::config::TlsMode::SelfSigned) => json!("self-signed"),
        None => Value::Null,
    };
    json!({
        "id": &*r.id, "hosts": r.hosts, "tls": tls, "upstreams": ups,
        "static_dir": r.cfg.static_files.as_ref().map(|s| s.root.display().to_string()),
        "healthy_upstreams": r.balancer.healthy_count(), "total_upstreams": r.balancer.upstreams.len(),
        "cache": r.cache.as_ref().map(|c| c.stats()),
        "certificates": certificates(r, certs), "features": features(r),
    })
}

/// A route is selected by id or by any of its hosts.
pub fn find_route<'a>(rt: &'a Runtime, name: &str) -> Option<&'a Arc<RouteRuntime>> {
    let name = name.trim().to_ascii_lowercase();
    rt.table
        .routes()
        .iter()
        .find(|r| *r.id == *name || r.hosts.contains(&name))
}

pub fn status_json(
    rt: &Runtime,
    route: Option<&str>,
    certs: &CertReport,
    uptime_s: u64,
    tunnels: usize,
) -> Result<Value, String> {
    let routes: Vec<Value> = match route {
        Some(n) => vec![route_json(find_route(rt, n).ok_or("unknown route")?, certs)],
        None => rt.table.routes().iter().map(|r| route_json(r, certs)).collect(),
    };
    Ok(
        json!({"generation": rt.generation, "uptime_s": uptime_s, "active_tunnels": tunnels, "routes": routes}),
    )
}

/// Trims, lowercases and removes dashes; must be exactly 32 hex characters.
pub fn normalize_incident_id(s: &str) -> Result<String, &'static str> {
    let n: String = s
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| *c != '-')
        .collect();
    if n.len() == 32 && n.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(n)
    } else {
        Err("invalid incident id: expected 32 hex characters")
    }
}

pub fn hint(last: &Incident) -> String {
    let up = last.upstream.as_deref().unwrap_or("?");
    let route = last.route_id.as_deref().unwrap_or("?");
    match last.kind {
        "upstream_connect" => format!("Backend {up} refuses the connection: process stopped or wrong port."),
        "upstream_timeout" => format!("Backend {up} did not respond in time (request timeouts)."),
        "no_healthy_upstream" => format!("No healthy backend for route {route}: see get_route_status."),
        "upstream_error" | "upstream_body_error" => {
            format!("Protocol error or connection cut by backend {up} during the response.")
        }
        "rate_limited" => "Client limited by rate-limit.".into(),
        "auth" => "Authentication failure (gatekeeper/JWT/API key).".into(),
        "geo_blocked" => "Country blocked by the GeoIP rule.".into(),
        "ip_blocked" => format!("Client address not in the allow-ips list of route {route}."),
        "tls_fallback" => "Certificate source changed for this host: check certs-dir and ACME.".into(),
        "payload_too_large" => "Request body larger than limits max-body.".into(),
        _ => "See detail.".into(),
    }
}

pub fn purge_from(
    tags: Option<Vec<String>>,
    host: Option<String>,
    path_prefix: Option<String>,
    all: Option<bool>,
) -> Result<Purge, &'static str> {
    let p = Purge {
        tags: tags.unwrap_or_default(),
        host: host
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty()),
        path_prefix: path_prefix.filter(|p| !p.is_empty()),
        all: all.unwrap_or(false),
    };
    if p.tags.is_empty() && p.host.is_none() && p.path_prefix.is_none() && !p.all {
        return Err("specify tags, host, path_prefix or all");
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use crate::server::Shared;

    fn runtime() -> Runtime {
        let src = "route \"a.com\" \"www.a.com\" {\n upstream \"10.0.0.1:80\" weight=9\n upstream \"10.0.0.2:80\"\n cache\n compression\n}\nroute \"b.com\" {\n upstream \"10.0.0.3:80\"\n cache off\n}";
        let cfg = Arc::new(parse_str(src, &|_| None).unwrap());
        crate::routing::build(&cfg, &Shared::new()).unwrap()
    }

    #[test]
    fn route_status_json_shape() {
        let rt = runtime();
        rt.table.lookup("a.com").unwrap().balancer.upstreams[1]
            .health
            .report_failure_passive();
        let v = status_json(&rt, None, &CertReport::new(), 5, 2).unwrap();
        assert_eq!(
            (
                v["generation"].as_u64(),
                v["uptime_s"].as_u64(),
                v["active_tunnels"].as_u64()
            ),
            (Some(1), Some(5), Some(2))
        );
        let a = &v["routes"][0];
        assert_eq!(a["id"], "a.com");
        assert_eq!(
            (a["healthy_upstreams"].as_u64(), a["total_upstreams"].as_u64()),
            (Some(1), Some(2))
        );
        assert_eq!(a["upstreams"][0]["weight"], 9);
        assert_eq!(a["upstreams"][1]["healthy"], false);
        assert!(
            a["cache"]["capacity_bytes"].is_u64()
                && a["features"].as_array().unwrap().contains(&json!("compression"))
        );
        assert!(v["routes"][1]["cache"].is_null());
        assert!(
            status_json(&rt, Some("www.a.com"), &CertReport::new(), 0, 0).unwrap()["routes"][0]["id"]
                == "a.com"
        );
        assert_eq!(
            status_json(&rt, Some("nope"), &CertReport::new(), 0, 0).unwrap_err(),
            "unknown route"
        );
    }

    #[test]
    fn certificates_report_source_and_expiry() {
        let src = "gateway {\n listen \":80\" \":443\"\n default-email \"x@y.z\"\n}\nroute \"a.com\" \"www.a.com\" {\n tls\n upstream \"10.0.0.1:80\"\n}";
        let cfg = Arc::new(parse_str(src, &|_| None).unwrap());
        let rt = crate::routing::build(&cfg, &Shared::new()).unwrap();
        let mut rep = CertReport::new();
        rep.insert(
            "a.com".into(),
            HostCert {
                source: "local",
                not_after: now_unix() + 90 * 86_400 + 5,
                path: Some("/c/full.pem".into()),
                acme_directory: None,
            },
        );
        let v = status_json(&rt, None, &rep, 0, 0).unwrap();
        let c = &v["routes"][0]["certificates"];
        assert_eq!(
            (
                c[0]["days_left"].as_i64(),
                c[0]["source"].as_str(),
                c[0]["path"].as_str()
            ),
            (Some(90), Some("local"), Some("/c/full.pem"))
        );
        assert!(c[1]["source"].is_null() && c[1]["domain"] == "www.a.com");
        assert_eq!(v["routes"][0]["tls"], "auto");
    }

    #[test]
    fn hint_per_kind() {
        let mk = |k: &'static str| {
            let mut i = Incident::new("t".into(), k);
            i.upstream = Some("10.0.0.1:80".into());
            i.route_id = Some("a.com".into());
            i
        };
        assert!(
            hint(&mk("upstream_connect")).contains("10.0.0.1:80")
                && hint(&mk("upstream_connect")).contains("refuses")
        );
        assert!(hint(&mk("no_healthy_upstream")).contains("a.com"));
        for k in [
            "upstream_timeout",
            "upstream_error",
            "upstream_body_error",
            "rate_limited",
            "auth",
            "geo_blocked",
            "ip_blocked",
            "payload_too_large",
            "tls_fallback",
        ] {
            assert_ne!(hint(&mk(k)), "See detail.", "{k}");
        }
        assert_eq!(hint(&mk("http")), "See detail.");
    }

    #[test]
    fn normalize_incident_id() {
        let id = "4bf92f3577b34da6a3ce929d0e0e4736";
        assert_eq!(
            super::normalize_incident_id(&format!("  {} ", id.to_ascii_uppercase())).unwrap(),
            id
        );
        assert_eq!(
            super::normalize_incident_id("4bf92f35-77b3-4da6-a3ce-929d0e0e4736").unwrap(),
            id
        );
        for bad in ["", "abc", &id[..31], &format!("{id}0"), &id.replace('4', "g")] {
            assert!(super::normalize_incident_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn purge_requires_criteria() {
        assert!(purge_from(None, None, None, None).is_err());
        assert!(purge_from(Some(vec![]), Some(" ".into()), Some(String::new()), Some(false)).is_err());
        assert!(purge_from(Some(vec!["t".into()]), None, None, None).is_ok());
        assert_eq!(
            purge_from(None, Some(" A.com ".into()), None, None)
                .unwrap()
                .host
                .as_deref(),
            Some("a.com")
        );
        assert!(purge_from(None, None, None, Some(true)).unwrap().all);
    }
}
