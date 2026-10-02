//! Configuration parser tests.
use super::*;
use std::time::Duration;

const HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$ftC9LdPXCcZ6MiQpvWUwXA$haZvTFqngv2fUrBLJTBmAw2Ltxdy9HonzbKTkg4bXhI";
const GEO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/GeoIP2-Country-Test.mmdb"
);

fn env(k: &str) -> Option<String> {
    match k {
        "JWT_SECRET_KEY" => Some("test-secret-at-least-32-bytes-long!!".into()),
        "PSK_HASH" => Some(HASH.into()),
        "TOTP" => Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
        "MCP_TOKEN" => Some("0123456789abcdef0123".into()),
        _ => None,
    }
}

fn parse(s: &str) -> Result<Config, ConfigError> {
    parse_str(s, &env)
}

fn err(s: &str) -> String {
    parse(s).unwrap_err().to_string()
}

fn route(body: &str) -> String {
    format!("route \"a.com\" {{\n upstream \"10.0.0.1:80\"\n {body}\n}}")
}

fn specs(file: &str) -> Config {
    let src = std::fs::read_to_string(format!("{}/{file}", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let src = src.replace(
        "/var/lib/geoip/GeoLite2-Country.mmdb",
        "tests/fixtures/GeoIP2-Country-Test.mmdb",
    );
    parse(&src.replace("tests/fixtures/GeoIP2-Country-Test.mmdb", GEO)).unwrap()
}

#[test]
fn empty_file_gives_defaults() {
    let c = parse("").unwrap();
    assert!(c.routes.is_empty() && c.mcp.is_none());
    assert_eq!(c.gateway.listen_http.to_string(), "[::]:80");
    assert_eq!(c.gateway.listen_https.unwrap().to_string(), "[::]:443");
    assert_eq!(c.gateway.storage_path.to_str(), Some("/var/lib/gateway/certs.db"));
    assert_eq!(c.gateway.flight_recorder_capacity, 500);
    assert_eq!(c.gateway.limits.max_connections, 10_000);
}

#[test]
fn specs_example_v1_equals_v2() {
    let v1 = specs("tests/fixtures/specs_verbatim.kdl");
    let v2 = specs("examples/gateway.kdl");
    assert_eq!(v1, v2);
    assert_eq!(v1.routes.len(), 2);
    assert_eq!(v1.routes[0].hosts, vec!["client.com", "www.client.com"]);
    assert_eq!(v1.routes[0].upstreams[0].weight, 90);
    assert_eq!(v1.routes[0].cache.as_ref().unwrap().max_size, 256_000_000);
    assert_eq!(
        v1.routes[0].cache.as_ref().unwrap().stale_while_revalidate,
        Duration::from_secs(30)
    );
    assert_eq!(
        v1.routes[1].gatekeeper.as_ref().unwrap().cookie_name,
        "__Host-gate"
    );
}

#[test]
fn gateway_all_properties() {
    let c = parse(
        r#"gateway {
        listen "127.0.0.1:8080"
        storage-path "/tmp/x.db"
        acme-directory "staging"
        default-email "a@b.c"
        trusted-proxies "10.0.0.0/8" "::1"
        flight-recorder capacity=10
        log format="json" level="debug"
        limits max-connections=5 max-body="1MiB" header-read-timeout="5s" max-headers-size="16KiB"
        worker-threads 2
        shutdown-grace "10s"
    }"#,
    )
    .unwrap()
    .gateway;
    assert_eq!(c.listen_http.port(), 8080);
    assert!(c.listen_https.is_none());
    assert_eq!(c.acme_directory, AcmeDirectory::Staging);
    assert_eq!(c.trusted_proxies.len(), 2);
    assert_eq!(c.flight_recorder_capacity, 10);
    assert!(c.log.json);
    assert_eq!(c.limits.max_body, 1024 * 1024);
    assert_eq!(c.worker_threads, Some(2));
    assert_eq!(c.shutdown_grace, Duration::from_secs(10));
}

#[test]
fn mcp_defaults_and_rules() {
    let m = parse("mcp-server").unwrap().mcp.unwrap();
    assert_eq!(m.listen.to_string(), "127.0.0.1:9090");
    assert!(m.token.is_none());
    let m = parse("mcp-server { token-env \"MCP_TOKEN\" }")
        .unwrap()
        .mcp
        .unwrap();
    assert_eq!(m.token.as_deref(), Some("0123456789abcdef0123"));
    assert!(err("mcp-server { token \"short\" }").contains("16"));
}

#[test]
fn mcp_public_without_token() {
    assert!(err("mcp-server { listen \"0.0.0.0:9090\" }").contains("loopback"));
}

#[test]
fn route_defaults() {
    let r = parse(&route("")).unwrap().routes.remove(0);
    assert_eq!(&*r.id, "a.com");
    assert!(r.tls.is_none() && !r.redirect_https);
    assert_eq!(r.upstreams[0].weight, 1);
    assert_eq!(r.health, HealthCfg::default());
    assert_eq!(r.request_timeout, Duration::from_secs(60));
    assert_eq!(r.fallback, FallbackCfg::default());
    assert!(r.cache.is_none() && r.compression.is_none() && r.gatekeeper.is_none());
}

#[test]
fn route_simple_children_all_properties() {
    let r = parse(&route(
        r#"health-check path="/up" interval="10s" timeout="1s" unhealthy-after=3 healthy-after=4 mode="tcp" enabled=#false
        timeouts request="5s"
        fallback status=502 show-incident-id=#false title="T" message="M" on="503"
        redirect-https #false"#,
    ))
    .unwrap()
    .routes
    .remove(0);
    assert_eq!(r.health.path, "/up");
    assert_eq!(r.health.mode, HealthMode::Tcp);
    assert!(!r.health.enabled);
    assert_eq!((r.health.unhealthy_after, r.health.healthy_after), (3, 4));
    assert_eq!(r.request_timeout, Duration::from_secs(5));
    assert_eq!((r.fallback.status, r.fallback.on.clone()), (502, vec![503]));
    assert!(!r.fallback.show_incident_id);
}

fn tls_of(src: &str) -> TlsCfg {
    parse(src).unwrap().routes.remove(0).tls.unwrap()
}

const GW_EMAIL: &str = "gateway { default-email \"d@x.y\" }\n";

#[test]
fn tls_auto_defaults() {
    let src = format!("{GW_EMAIL}{}", route("tls"));
    assert_eq!(
        tls_of(&src).mode,
        TlsMode::Auto {
            acme: Some(AcmeTarget {
                email: "d@x.y".into(),
                staging: false
            })
        }
    );
    assert!(parse(&src).unwrap().routes[0].redirect_https);
}

#[test]
fn tls_staging_child() {
    let src = format!("{GW_EMAIL}{}", route("tls {\n staging\n }"));
    assert!(matches!(
        tls_of(&src).mode,
        TlsMode::Auto {
            acme: Some(AcmeTarget { staging: true, .. })
        }
    ));
    assert!(err(&format!("{GW_EMAIL}{}", route("tls {\n other\n }"))).contains("unknown node"));
    assert!(err(&format!("{GW_EMAIL}{}", route("tls {\n staging 1\n }"))).contains("arguments"));
}

#[test]
fn tls_self_signed() {
    let r = parse(&route("tls self-signed=#true")).unwrap().routes.remove(0);
    assert_eq!(r.tls.unwrap().mode, TlsMode::SelfSigned);
    assert!(r.redirect_https);
    let w = "route \"*.a.com\" { upstream \"10.0.0.1:80\"\n tls self-signed=#true }";
    assert!(parse(w).is_ok());
    let off = format!("{GW_EMAIL}{}", route("tls self-signed=#false"));
    assert!(matches!(tls_of(&off).mode, TlsMode::Auto { .. }));
}

#[test]
fn self_signed_with_email_rejected() {
    assert!(err(&route("tls self-signed=#true email=\"a@b.c\"")).contains("self-signed"));
}

#[test]
fn self_signed_with_staging_rejected() {
    assert!(err(&route("tls self-signed=#true {\n staging\n }")).contains("staging"));
}

#[test]
fn cert_file_removed_with_hint() {
    let e = err(&route("tls cert-file=\"/x\" key-file=\"/y\""));
    assert!(e.contains("certs-dir") && e.contains("removed"), "{e}");
}

#[test]
fn no_email_without_local_cert_rejected() {
    let e = err(&route("tls"));
    assert!(e.contains("no local certificate") && e.contains("email"), "{e}");
}

#[test]
fn wildcard_without_local_cert_rejected() {
    let s = format!("{GW_EMAIL}route \"*.a.com\" {{ upstream \"10.0.0.1:80\"\n tls }}");
    let e = err(&s);
    assert!(e.contains("wildcard"), "{e}");
}

fn certs_dir(names: &[&str]) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
    std::fs::write(
        d.path().join("fullchain.pem"),
        params.self_signed(&key).unwrap().pem(),
    )
    .unwrap();
    std::fs::write(d.path().join("privkey.pem"), key.serialize_pem()).unwrap();
    d
}

#[test]
fn local_cert_satisfies_wildcard_and_no_email_warns() {
    let d = certs_dir(&["*.a.com"]);
    let s = format!(
        "gateway {{ certs-dir \"{}\" }}\nroute \"*.a.com\" {{ upstream \"10.0.0.1:80\"\n tls }}",
        d.path().display()
    );
    let cfg = parse(&s).unwrap();
    assert!(matches!(
        cfg.routes[0].tls.as_ref().unwrap().mode,
        TlsMode::Auto { acme: None }
    ));
    let w = crate::config::warnings(&cfg);
    assert!(
        w.len() == 1 && w[0].contains("no ACME fallback for *.a.com"),
        "{w:?}"
    );
}

#[test]
fn certs_dir_must_be_directory() {
    let e = err("gateway { certs-dir \"/definitely/not/here\" }");
    assert!(e.contains("certs-dir"), "{e}");
}

#[test]
fn redirect_https_default_true_for_all_modes() {
    let a = format!("{GW_EMAIL}{}", route("tls"));
    assert!(parse(&a).unwrap().routes[0].redirect_https);
    assert!(parse(&route("tls self-signed=#true")).unwrap().routes[0].redirect_https);
    let off = format!("{GW_EMAIL}{}", route("tls\n redirect-https #false"));
    assert!(!parse(&off).unwrap().routes[0].redirect_https);
}

#[test]
fn feature_defaults() {
    let r = parse(&route(&format!(
        "cache\n compression\n geoip database=\"{GEO}\"\n rate-limit rps=10\n api-keys {{ key \"{}\" name=\"ci\" }}\n transform",
        "47BD0E2F856FE258EBBA4D00930AB811D0C004DAFAE068C9D72511CA3512CCA6"
    )))
    .unwrap()
    .routes
    .remove(0);
    let c = r.cache.unwrap();
    assert_eq!((c.max_size, c.max_object_size), (64 << 20, 8 << 20));
    assert_eq!(c.default_ttl, Duration::ZERO);
    let z = r.compression.unwrap();
    assert!(z.zstd && z.brotli && z.gzip && z.min_size == 1024);
    let g = r.geoip.unwrap();
    assert!(g.inject_header && g.block.is_empty());
    assert_eq!(
        r.rate_limits[0],
        RateLimitCfg {
            rps: 10,
            burst: 10,
            path: None
        }
    );
    let k = r.api_keys.unwrap();
    assert_eq!(k.header, "X-Api-Key");
    assert_eq!(k.keys[0].hash_hex.len(), 64);
    assert!(k.keys[0].hash_hex.chars().all(|c| !c.is_ascii_uppercase()));
    assert_eq!(r.transform.unwrap(), TransformCfg::default());
}

#[test]
fn feature_all_properties() {
    let r = parse(&route(&format!(
        r#"cache max-size="1MiB" stale-while-revalidate="5s" stale-if-error=10 default-ttl="1m" max-object-size="512KiB"
        compression zstd=#false brotli=#false gzip=#true min-size=10
        geoip database="{GEO}" allow-countries="fr, be" inject-header=#false
        rate-limit rps=5 burst=20 path="/login"
        rate-limit rps=50
        api-keys header="X-K" {{ key "{}" name="a" }}"#,
        "a".repeat(64)
    )))
    .unwrap()
    .routes
    .remove(0);
    let c = r.cache.unwrap();
    assert_eq!(c.stale_if_error, Duration::from_secs(10));
    assert_eq!(c.default_ttl, Duration::from_secs(60));
    let z = r.compression.unwrap();
    assert!(!z.zstd && !z.brotli && z.gzip && z.min_size == 10);
    assert_eq!(r.geoip.as_ref().unwrap().allow, vec!["FR", "BE"]);
    assert!(!r.geoip.unwrap().inject_header);
    assert_eq!(r.rate_limits.len(), 2);
    assert_eq!(r.api_keys.unwrap().header, "X-K");
}

#[test]
fn gatekeeper_defaults_and_all() {
    let g = parse(&route(&format!("gatekeeper {{ psk \"{HASH}\" }}")))
        .unwrap()
        .routes
        .remove(0)
        .gatekeeper
        .unwrap();
    assert_eq!(g.title, "Protected access");
    assert_eq!(g.cookie_name, "gate");
    assert_eq!((g.attempts, g.window), (5, Duration::from_secs(900)));
    assert!(g.totp_secret.is_none() && !g.passkey);
    let src = format!(
        r#"gateway {{
 default-email "a@b.c"
}}
route "a.com" {{
 upstream "10.0.0.1:80"
 tls
 gatekeeper {{
  title "T"
  psk-env "PSK_HASH"
  totp-secret-env "TOTP"
  session-duration "1h"
  rate-limit attempts=2 window="1m"
  passkey {passkey}
  cookie-name "c"
 }}
}}"#,
        passkey = cfg!(feature = "passkey")
    );
    let g = parse(&src).unwrap().routes.remove(0).gatekeeper.unwrap();
    assert_eq!(g.totp_secret.unwrap().len(), 20);
    assert_eq!(g.session_duration, Duration::from_secs(3600));
    assert_eq!(g.passkey, cfg!(feature = "passkey"));
    assert_eq!(g.cookie_name, "c");
}

#[test]
fn jwt_defaults_and_all() {
    let j = parse(&route("jwt-validation { secret-env \"JWT_SECRET_KEY\" }"))
        .unwrap()
        .routes
        .remove(0)
        .jwt
        .unwrap();
    assert_eq!(j.algorithms, vec![jsonwebtoken::Algorithm::HS256]);
    assert_eq!(j.leeway, Duration::from_secs(60));
    assert!(j.inject_headers && j.cookie.is_none());
    let j = parse(&route(
        "jwt-validation { secret-env \"JWT_SECRET_KEY\"\n algorithms \"HS512\"\n issuer \"i\"\n audience \"a\" \"b\"\n leeway \"5s\"\n inject-headers #false\n cookie \"jwt\" }",
    ))
    .unwrap()
    .routes
    .remove(0)
    .jwt
    .unwrap();
    assert_eq!(j.algorithms, vec![jsonwebtoken::Algorithm::HS512]);
    assert_eq!((j.issuers.len(), j.audiences.len()), (1, 2));
    assert!(!j.inject_headers);
    assert_eq!(j.cookie.as_deref(), Some("jwt"));
}

#[test]
fn transform_all_ops() {
    let t = parse(&route(
        r#"transform {
        request { set "X-A" "{client_ip}"
 add "X-B" "1"
 remove "X-C"
 replace "X-D" "a(.)" "$1" }
        response { remove "Server"
 status from=404 to=410 }
    }"#,
    ))
    .unwrap()
    .routes
    .remove(0)
    .transform
    .unwrap();
    assert_eq!(t.request.len(), 4);
    assert_eq!(t.response.len(), 1);
    assert_eq!(t.status, vec![(404, 410)]);
}

#[test]
fn unknown_top_level_node() {
    assert!(err("foo").contains("unknown node"));
}

#[test]
fn unknown_route_child() {
    assert!(err(&route("bogus")).contains("unknown node"));
}

#[test]
fn unknown_property() {
    assert!(err(&route("timeouts connect=\"1s\"")).contains("unknown property"));
}

#[test]
fn duplicate_property() {
    assert!(err(&route("cache max-size=\"1MB\" max-size=\"2MB\"")).contains("duplicate property"));
}

#[test]
fn duplicate_singleton_node() {
    assert!(err(&route("cache\n cache")).contains("duplicate node"));
}

#[test]
fn upstream_hostname_rejected() {
    assert!(err("route \"a.com\" { upstream \"backend:80\" }").contains("ip:port"));
}

#[test]
fn weight_sum_zero() {
    assert!(err("route \"a.com\" { upstream \"10.0.0.1:80\" weight=0 }").contains("weights"));
}

#[test]
fn psk_truncated_hash_rejected() {
    assert!(
        err(&route(
            "gatekeeper { psk \"$argon2id$v=19$m=19456,t=2,p=1$...\" }"
        ))
        .contains("psk")
    );
}

#[test]
fn psk_argon2i_rejected() {
    let h = HASH.replace("$argon2id$", "$argon2i$");
    assert!(err(&route(&format!("gatekeeper {{ psk \"{h}\" }}"))).contains("argon2id"));
}

#[test]
fn jwt_two_key_sources() {
    assert!(
        err(&route(
            "jwt-validation { secret-env \"JWT_SECRET_KEY\"\n public-key-file \"/x\" }"
        ))
        .contains("exactly one")
    );
}

#[test]
fn jwt_secret_env_missing() {
    assert!(err(&route("jwt-validation { secret-env \"NOPE\" }")).contains("NOPE"));
}

#[test]
fn geoip_block_and_allow() {
    let g = format!("geoip database=\"{GEO}\" block-countries=\"CN\" allow-countries=\"FR\"");
    assert!(err(&route(&g)).contains("mutually exclusive"));
}

#[test]
fn compression_all_false() {
    assert!(err(&route("compression zstd=#false brotli=#false gzip=#false")).contains("no algorithm"));
}

#[test]
fn transform_forbidden_header() {
    assert!(err(&route("transform { request { set \"Host\" \"x\" } }")).contains("cannot be modified"));
}

#[test]
fn transform_bad_regex() {
    assert!(err(&route("transform { response { replace \"X\" \"(\" \"y\" } }")).contains("regex"));
}

#[test]
fn error_position_line_col() {
    let e = parse("gateway {\n}\nbogus-node\n").unwrap_err();
    assert!(e.to_string().starts_with("3:1:"), "{e}");
}

#[test]
fn syntax_error_has_position() {
    assert!(matches!(parse("route \"a\" {"), Err(ConfigError::Syntax { .. })));
}

#[test]
fn duplicate_host_across_routes() {
    let s = "route \"a.com\" { upstream \"10.0.0.1:80\" }\nroute \"b.com\" \"a.com\" { upstream \"10.0.0.2:80\" }";
    assert!(err(s).contains("a.com"));
}

#[cfg(feature = "passkey")]
#[test]
fn passkey_requires_tls() {
    assert!(
        err(&route(&format!(
            "gatekeeper {{ psk \"{HASH}\"\n passkey #true }}"
        )))
        .contains("tls")
    );
}

#[test]
fn default_cert_must_be_tls_route() {
    assert!(err(&format!("gateway {{ default-cert \"a.com\" }}\n{}", route(""))).contains("default-cert"));
}

#[test]
fn listen_conflicts() {
    assert!(err("gateway { listen \":80\" \":80\" }").contains("differ"));
    assert!(
        err("gateway { listen \"127.0.0.1:9090\" }\nmcp-server { listen \"127.0.0.1:9090\" }")
            .contains("conflicts")
    );
}

#[test]
fn tls_route_needs_https_listener() {
    let s = "gateway { listen \":80\" }\nroute \"a.com\" { upstream \"10.0.0.1:80\"\n tls email=\"a@b.c\" }";
    assert!(err(s).contains("HTTPS listener"));
}

#[test]
fn health_timeout_must_be_below_interval() {
    assert!(err(&route("health-check interval=\"1s\" timeout=\"2s\"")).contains("lower than interval"));
}

#[test]
fn limits_bounds() {
    assert!(err("gateway { limits max-headers-size=\"1KiB\" }").contains("max-headers-size"));
}
