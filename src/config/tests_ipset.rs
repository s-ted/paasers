//! `ip-set`, `allow-ips` and the shared IP list syntax (plans/15 §4).
use super::*;
use ipnet::IpNet;

fn env(_: &str) -> Option<String> {
    None
}

fn parse(s: &str) -> Result<Config, ConfigError> {
    parse_str(s, &env)
}

fn err(s: &str) -> String {
    parse(s).unwrap_err().to_string()
}

fn route(body: &str) -> String {
    format!("route \"a.com\" {{\n upstream \"10.0.0.1:80\"\n {body}\n}}\n")
}

fn nets(v: &[&str]) -> Vec<IpNet> {
    v.iter().map(|s| s.parse().unwrap()).collect()
}

fn allow(src: &str) -> Option<Vec<IpNet>> {
    parse(src).unwrap().routes[0].allow_ips.clone()
}

#[test]
fn allow_ips_absent_is_none() {
    assert_eq!(allow(&route("")), None);
}

#[test]
fn allow_ips_block_and_positional_mixed() {
    let got = allow(&route(
        "allow-ips \"192.0.2.1\" {\n - \"2001:db8::/32\"\n - \"198.51.100.0/24\"\n}",
    ));
    assert_eq!(
        got,
        Some(nets(&["192.0.2.1/32", "198.51.100.0/24", "2001:db8::/32"]))
    );
}

#[test]
fn allow_ips_resolves_set_and_aggregates() {
    let src = format!(
        "ip-set \"staff\" {{\n - \"10.0.0.0/25\"\n - \"10.0.0.128/25\"\n - \"10.0.0.7\"\n}}\n{}",
        route("allow-ips {\n - \"staff\"\n - \"10.0.0.0/24\"\n - \"192.0.2.9\"\n}")
    );
    assert_eq!(allow(&src), Some(nets(&["10.0.0.0/24", "192.0.2.9/32"])));
}

#[test]
fn allow_ips_host_bits_cleared() {
    assert_eq!(
        allow(&route("allow-ips { - \"10.1.2.3/8\"; }")),
        Some(nets(&["10.0.0.0/8"]))
    );
}

#[test]
fn ip_set_declared_after_use() {
    let src = format!(
        "{}ip-set \"late\" {{ - \"192.0.2.0/24\"; }}\n",
        route("allow-ips \"late\"")
    );
    assert_eq!(allow(&src), Some(nets(&["192.0.2.0/24"])));
}

#[test]
fn ip_set_reused_by_two_routes() {
    let src = "ip-set \"s\" { - \"192.0.2.0/24\"; }
route \"a.com\" { upstream \"10.0.0.1:80\"; allow-ips \"s\"; }
route \"b.com\" { upstream \"10.0.0.1:80\"; allow-ips { - \"s\"; - \"::1\"; }; }";
    let c = parse(src).unwrap();
    assert_eq!(c.routes[0].allow_ips, Some(nets(&["192.0.2.0/24"])));
    assert_eq!(c.routes[1].allow_ips, Some(nets(&["192.0.2.0/24", "::1/128"])));
}

#[test]
fn trusted_proxies_block_form_and_set() {
    let src = "ip-set \"lb\" { - \"10.0.0.2\"; - \"10.0.0.3\"; }
gateway {
    trusted-proxies \"::1\" {
        - \"lb\"          // front load balancers
        - \"127.0.0.1\"
    }
}";
    assert_eq!(
        parse(src).unwrap().gateway.trusted_proxies,
        nets(&["10.0.0.2/31", "127.0.0.1/32", "::1/128"])
    );
    // The positional form and the empty list keep working.
    assert_eq!(
        parse("gateway { trusted-proxies \"10.0.0.0/8\"; }")
            .unwrap()
            .gateway
            .trusted_proxies,
        nets(&["10.0.0.0/8"])
    );
    assert!(
        parse("gateway { trusted-proxies {}; }")
            .unwrap()
            .gateway
            .trusted_proxies
            .is_empty()
    );
}

#[test]
fn comments_and_slashdash_ignored() {
    let got = allow(&route(
        "allow-ips {\n /* office */\n - \"192.0.2.1\" // desk\n /- - \"192.0.2.2\"\n - /-\"bad\" \"192.0.2.3\"\n}",
    ));
    assert_eq!(got, Some(nets(&["192.0.2.1/32", "192.0.2.3/32"])));
}

#[test]
fn allow_ips_empty() {
    assert!(err(&route("allow-ips")).contains("allow-ips needs at least one entry"));
    assert!(err(&route("allow-ips {}")).contains("allow-ips needs at least one entry"));
}

#[test]
fn allow_ips_unknown_set() {
    let e = err(&route("allow-ips {\n - \"nope\"\n}"));
    assert!(e.contains("unknown ip-set `nope`"), "{e}");
    assert!(e.starts_with("4:"), "positioned on the entry: {e}");
}

#[test]
fn ip_set_duplicate() {
    let e = err("ip-set \"s\" { - \"::1\"; }\nip-set \"s\" { - \"::2\"; }");
    assert!(e.contains("duplicate ip-set `s`"), "{e}");
}

#[test]
fn ip_set_empty() {
    assert!(err("ip-set \"s\" {}").contains("ip-set `s` is empty"));
    assert!(err("ip-set \"s\"").contains("ip-set `s` is empty"));
}

#[test]
fn ip_set_nested_rejected() {
    let e = err("ip-set \"a\" { - \"::1\"; }\nip-set \"b\" { - \"a\"; }");
    assert!(e.contains("invalid network `a`"), "{e}");
}

#[test]
fn ip_set_invalid_name() {
    assert!(err("ip-set \"10.0.0.0/8\" { - \"::1\"; }").contains("invalid ip-set name"));
    assert!(err("ip-set \"a b\" { - \"::1\"; }").contains("invalid ip-set name"));
    assert!(err("ip-set { - \"::1\"; }").contains("expects 1..=1 arguments"));
    assert!(err("ip-set \"a\" x=1 { - \"::1\"; }").contains("unknown property"));
}

#[test]
fn list_child_not_dash() {
    let e = err(&route("allow-ips { net \"::1\"; }"));
    assert!(e.contains("unknown node `net`"), "{e}");
    assert!(err("ip-set \"s\" { ip \"::1\"; }").contains("unknown node `ip`"));
}

#[test]
fn list_child_with_property() {
    assert!(err(&route("allow-ips { - \"::1\" note=\"x\"; }")).contains("unknown property"));
    assert!(err(&route("allow-ips { - \"::1\" \"::2\"; }")).contains("expects 1..=1 arguments"));
    assert!(err(&route("allow-ips { - \"::1\" { - \"::2\"; }; }")).contains("has no children"));
    assert!(err(&route("allow-ips x=1 { - \"::1\"; }")).contains("unknown property"));
}

#[test]
fn duplicate_allow_ips() {
    let e = err(&route("allow-ips \"::1\"\n allow-ips \"::2\""));
    assert!(e.contains("duplicate node `allow-ips`"), "{e}");
}
