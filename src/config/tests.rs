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
    assert!(c.routes.is_empty());
    assert!(c.mcp.as_ref().is_some_and(|m| m.implicit && m.token.is_none()));
    assert_eq!(c.gateway.trusted_proxies, defaults::trusted_proxies());
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
    assert_eq!(r.fallback, Some(FallbackCfg::default()));
    assert!(r.retry);
    assert_eq!(r.cache, Some(CacheCfg::default()));
    assert!(r.compression == Some(CompressionCfg::default()) && r.gatekeeper.is_none());
    assert_eq!(r.rate_limits, vec![defaults::rate_limit()]);
    assert_eq!(r.transform, Some(defaults::security_transform()));
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
    let f = r.fallback.clone().unwrap();
    assert_eq!((f.status, f.on.clone()), (502, vec![503]));
    assert!(!f.show_incident_id);
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
    assert_eq!(r.transform.unwrap(), defaults::security_transform());
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
    assert_eq!(g.cookie_name, "__gate");
    assert_eq!((g.attempts, g.window), (5, Duration::from_secs(900)));
    assert!(g.totp_secret.is_none());
    let src = r#"gateway {
 default-email "a@b.c"
}
route "a.com" {
 upstream "10.0.0.1:80"
 tls
 gatekeeper {
  title "T"
  psk-env "PSK_HASH"
  totp-secret-env "TOTP"
  session-duration "1h"
  rate-limit attempts=2 window="1m"
  cookie-name "c"
 }
}"#;
    let g = parse(src).unwrap().routes.remove(0).gatekeeper.unwrap();
    assert_eq!(g.totp_secret.unwrap().len(), 20);
    assert_eq!(g.session_duration, Duration::from_secs(3600));
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
    let builtin = defaults::security_transform().response.len();
    assert_eq!(t.request.len(), 4);
    assert_eq!(t.response.len(), builtin + 1);
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
fn compression_off() {
    let r = parse(&route("compression off")).unwrap().routes.remove(0);
    assert!(r.compression.is_none());
    assert!(err(&route("compression on")).contains("only the argument"));
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

#[test]
fn passkey_option_is_gone() {
    assert!(err(&route(&format!("gatekeeper {{ psk \"{HASH}\"\n passkey #true }}"))).contains("passkey"));
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

fn static_route(body: &str) -> String {
    format!("route \"s.com\" {{\n {body}\n}}")
}

fn tmp_dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn static_defaults() {
    let d = tmp_dir();
    let p = d.path().display();
    let r = parse(&static_route(&format!("static \"{p}\"")))
        .unwrap()
        .routes
        .remove(0);
    let s = r.static_files.unwrap();
    assert_eq!(s.root, d.path());
    assert_eq!(s.index, "index.html");
    assert!(s.listing && !s.spa && !s.hidden && !s.follow_symlinks);
    assert_eq!(s.cache_control, None);
    assert!(r.upstreams.is_empty());
}

#[test]
fn static_all_properties() {
    let d = tmp_dir();
    let p = d.path().display();
    let r = parse(&static_route(&format!(
        "static \"{p}\" index=\"home.htm\" listing=#false spa=#true hidden=#true follow-symlinks=#true cache-control=\"max-age=60\""
    )))
    .unwrap()
    .routes
    .remove(0);
    let s = r.static_files.unwrap();
    assert_eq!(s.index, "home.htm");
    assert!(!s.listing && s.spa && s.hidden && s.follow_symlinks);
    assert_eq!(s.cache_control.as_deref(), Some("max-age=60"));
    let r = parse(&static_route(&format!("static \"{p}\" index=\"\"")))
        .unwrap()
        .routes
        .remove(0);
    assert_eq!(r.static_files.unwrap().index, "");
}

#[test]
fn static_and_upstream_are_exclusive() {
    let d = tmp_dir();
    let e = err(&static_route(&format!(
        "static \"{}\"\n upstream \"10.0.0.1:80\"",
        d.path().display()
    )));
    assert!(e.contains("mutually exclusive"), "{e}");
}

#[test]
fn static_rejects_proxy_only_nodes() {
    let d = tmp_dir();
    for node in [
        "health-check path=\"/\"",
        "timeouts request=\"5s\"",
        "cache max-size=\"1MB\"",
        "fallback status=503",
    ] {
        let e = err(&static_route(&format!(
            "static \"{}\"\n {node}",
            d.path().display()
        )));
        assert!(e.contains("does not apply to a static route"), "{node}: {e}");
    }
}

#[test]
fn static_keeps_other_layers() {
    let d = tmp_dir();
    let r = parse(&static_route(&format!(
        "static \"{}\"\n rate-limit rps=5 burst=5\n compression off",
        d.path().display()
    )))
    .unwrap()
    .routes
    .remove(0);
    assert_eq!(r.rate_limits.len(), 1);
    assert!(r.compression.is_none());
}

#[test]
fn static_directory_must_exist_and_be_a_directory() {
    let d = tmp_dir();
    let missing = d.path().join("nope");
    let e = err(&static_route(&format!("static \"{}\"", missing.display())));
    assert!(e.contains("not a directory"), "{e}");
    let file = d.path().join("f.txt");
    std::fs::write(&file, "x").unwrap();
    let e = err(&static_route(&format!("static \"{}\"", file.display())));
    assert!(e.contains("not a directory"), "{e}");
}

#[test]
fn static_index_must_be_a_plain_file_name() {
    let d = tmp_dir();
    for bad in ["a/b.html", "..", "../x"] {
        let e = err(&static_route(&format!(
            "static \"{}\" index=\"{bad}\"",
            d.path().display()
        )));
        assert!(e.contains("index"), "{bad}: {e}");
    }
}

#[test]
fn static_argument_and_duplicates() {
    let d = tmp_dir();
    let p = d.path().display();
    assert!(err(&static_route("static")).contains("argument"));
    assert!(err(&static_route(&format!("static \"{p}\" bogus=1"))).contains("unknown property"));
    let e = err(&static_route(&format!("static \"{p}\"\n static \"{p}\"")));
    assert!(e.contains("duplicate node"), "{e}");
}

#[test]
fn static_example_parses() {
    let d = tmp_dir();
    let mut src =
        std::fs::read_to_string(format!("{}/examples/static.kdl", env!("CARGO_MANIFEST_DIR"))).unwrap();
    for dir in ["/srv/site", "/srv/app/dist", "/srv/downloads"] {
        let real = d.path().join(dir.trim_start_matches('/'));
        std::fs::create_dir_all(&real).unwrap();
        src = src.replace(&format!("\"{dir}\""), &format!("\"{}\"", real.display()));
    }
    let c = parse(&src).unwrap();
    assert_eq!(c.routes.len(), 5);
    assert_eq!(c.routes[4].static_files, Some(StaticCfg::default()));
    assert!(c.routes[0].static_files.as_ref().is_some_and(|s| !s.listing));
    assert!(c.routes[1].static_files.as_ref().is_some_and(|s| s.spa));
    assert!(c.routes[2].static_files.is_some() && c.routes[2].gatekeeper.is_some());
    assert!(c.routes[3].static_files.is_none() && !c.routes[3].upstreams.is_empty());
}

#[test]
fn route_without_backend_serves_current_directory() {
    let r = parse(&static_route("")).unwrap().routes.remove(0);
    assert_eq!(r.static_files, Some(StaticCfg::default()));
    assert_eq!(r.static_files.unwrap().root, std::path::Path::new("."));
    assert!(r.upstreams.is_empty());
}

#[test]
fn implicit_static_route_rejects_proxy_only_nodes() {
    let e = err(&static_route("cache max-size=\"1MB\""));
    assert!(e.contains("does not apply to a static route"), "{e}");
}

#[test]
fn mcp_off_and_explicit() {
    assert!(parse("mcp-server off").unwrap().mcp.is_none());
    assert!(err("mcp-server on").contains("only the argument"));
    let m = parse("mcp-server { listen \"127.0.0.1:9191\" }")
        .unwrap()
        .mcp
        .unwrap();
    assert!(!m.implicit);
}

#[test]
fn cache_off_and_static_has_no_default_cache() {
    assert!(parse(&route("cache off")).unwrap().routes[0].cache.is_none());
    assert!(err(&route("cache nope")).contains("only the argument"));
    let d = tmp_dir();
    let r = parse(&static_route(&format!("static \"{}\"", d.path().display())))
        .unwrap()
        .routes
        .remove(0);
    assert!(r.cache.is_none());
}

#[test]
fn rate_limit_default_off_and_override() {
    let r = &parse(&route("")).unwrap().routes[0];
    assert_eq!(
        r.rate_limits,
        vec![RateLimitCfg {
            rps: 100,
            burst: 200,
            path: None
        }]
    );
    assert!(
        parse(&route("rate-limit off")).unwrap().routes[0]
            .rate_limits
            .is_empty()
    );
    assert!(err(&route("rate-limit off\n rate-limit rps=1")).contains("cannot be combined"));
    let own = &parse(&route("rate-limit rps=5")).unwrap().routes[0];
    assert_eq!(own.rate_limits.len(), 1);
    assert_eq!(own.rate_limits[0].rps, 5);
    // A path rule alone keeps the built-in global rule.
    let p = &parse(&route("rate-limit path=\"/login\" rps=1")).unwrap().routes[0];
    assert_eq!(p.rate_limits.len(), 2);
    assert!(p.rate_limits[0].path.is_none() && p.rate_limits[0].rps == 100);
}

#[test]
fn security_transform_default_and_off() {
    let r = &parse(&route("")).unwrap().routes[0];
    let t = r.transform.as_ref().unwrap();
    assert!(t.response.iter().any(|o| o.header == "x-content-type-options"));
    // No HSTS by default, even with TLS.
    let tls = parse(&format!("{GW_EMAIL}{}", route("tls"))).unwrap();
    assert!(
        !tls.routes[0]
            .transform
            .as_ref()
            .unwrap()
            .response
            .iter()
            .any(|o| o.header == "strict-transport-security")
    );
    assert!(
        parse(&route("transform off")).unwrap().routes[0]
            .transform
            .is_none()
    );
    // User operations run after the defaults.
    let u = &parse(&route(
        "transform { response { set \"X-Content-Type-Options\" \"x\" } }",
    ))
    .unwrap()
    .routes[0];
    assert_eq!(
        u.transform.as_ref().unwrap().response.last().unwrap().header,
        "x-content-type-options"
    );
}

#[test]
fn trusted_proxies_default_private_and_empty_override() {
    let d = parse("").unwrap().gateway.trusted_proxies;
    assert!(d.iter().any(|n| n.to_string() == "10.0.0.0/8"));
    assert!(
        !d.iter()
            .any(|n| n.contains(&"127.0.0.1".parse::<std::net::IpAddr>().unwrap()))
    );
    assert!(
        parse("gateway { trusted-proxies }")
            .unwrap()
            .gateway
            .trusted_proxies
            .is_empty()
    );
}

#[test]
fn fallback_retry_flight_recorder_off() {
    assert!(
        parse(&route("fallback off")).unwrap().routes[0]
            .fallback
            .is_none()
    );
    assert!(err(&route("fallback on")).contains("only the argument"));
    assert!(!parse(&route("retry off")).unwrap().routes[0].retry);
    assert!(err(&route("retry on")).contains("only the argument"));
    assert_eq!(
        parse("gateway { flight-recorder off }")
            .unwrap()
            .gateway
            .flight_recorder_capacity,
        0
    );
    assert!(err("gateway { flight-recorder nope }").contains("only the argument"));
    assert_eq!(
        parse("gateway { flight-recorder capacity=7 }")
            .unwrap()
            .gateway
            .flight_recorder_capacity,
        7
    );
}

/// Every feature that is on without configuration must have an opt-out. Keep in sync with
/// docs/features/defaults.md.
#[test]
fn every_default_feature_can_be_disabled() {
    let d = parse(&route("")).unwrap();
    let r = &d.routes[0];
    assert!(d.mcp.is_some() && r.cache.is_some() && r.compression.is_some() && !r.rate_limits.is_empty());
    assert!(r.transform.is_some() && r.fallback.is_some() && r.retry && r.health.enabled);
    assert!(r.redirect_https || r.tls.is_none());
    assert!(!d.gateway.trusted_proxies.is_empty() && d.gateway.flight_recorder_capacity > 0);
    let off = parse(&format!(
        "mcp-server off\ngateway {{ trusted-proxies\n flight-recorder off }}\n{}",
        route("cache off\n compression off\n rate-limit off\n transform off\n fallback off\n retry off\n health-check enabled=#false")
    ))
    .unwrap();
    let r = &off.routes[0];
    assert!(off.mcp.is_none() && r.cache.is_none() && r.compression.is_none() && r.rate_limits.is_empty());
    assert!(r.transform.is_none() && r.fallback.is_none() && !r.retry && !r.health.enabled);
    assert!(off.gateway.trusted_proxies.is_empty() && off.gateway.flight_recorder_capacity == 0);
    let tls = parse(&format!("{GW_EMAIL}{}", route("tls\n redirect-https #false"))).unwrap();
    assert!(!tls.routes[0].redirect_https);
    let d = tmp_dir();
    let s = parse(&static_route(&format!(
        "static \"{}\" listing=#false",
        d.path().display()
    )))
    .unwrap();
    assert!(!s.routes[0].static_files.as_ref().unwrap().listing);
}
