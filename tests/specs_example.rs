//! The reference configuration of SPECS.md, verbatim and then actually served (P12).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod common;
use common::*;
use rcgen::{CertificateParams, Issuer, KeyPair};

const GEO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/GeoIP2-Country-Test.mmdb"
);
const VERBATIM: &str = include_str!("fixtures/specs_verbatim.kdl");
/// One request over TLS, trusting only `ca`.
async fn tls_request(
    addr: std::net::SocketAddr,
    ca: &rustls::pki_types::CertificateDer<'static>,
    sni: &str,
    req: &str,
) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg))
        .connect(
            rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap(),
            tcp,
        )
        .await
        .unwrap();
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out).into_owned()
}

const KEY: &str = "test-api-key-0123456789";

fn env(k: &str) -> Option<String> {
    (k == "JWT_SECRET_KEY").then(|| "test-secret-at-least-32-bytes-long!!".to_string())
}

#[test]
fn specs_example_parses() {
    let src = VERBATIM.replace("/var/lib/geoip/GeoLite2-Country.mmdb", &kp(GEO));
    let cfg = paasers::config::parse_str(&src, &env).unwrap();
    assert_eq!(cfg.routes.len(), 2);
    assert_eq!(cfg.routes[0].hosts, ["client.com", "www.client.com"]);
    assert!(cfg.routes[1].gatekeeper.is_some() && cfg.routes[1].jwt.is_some());
}

#[test]
fn the_truncated_psk_of_the_specs_is_rejected_with_a_clear_message() {
    // SPECS.md shows `$argon2id$v=19$m=19456,t=2,p=1$...`, which is not a valid hash.
    let src = VERBATIM
        .replace("/var/lib/geoip/GeoLite2-Country.mmdb", &kp(GEO))
        .replace(
            "$argon2id$v=19$m=19456,t=2,p=1$ftC9LdPXCcZ6MiQpvWUwXA$haZvTFqngv2fUrBLJTBmAw2Ltxdy9HonzbKTkg4bXhI",
            "$argon2id$v=19$m=19456,t=2,p=1$...",
        );
    let err = paasers::config::parse_str(&src, &env).unwrap_err().to_string();
    assert!(err.contains("psk"), "{err}");
}

#[tokio::test]
async fn specs_example_serves() {
    let (backend, _j) = spawn_echo_backend().await;
    let (backend2, _j2) = spawn_echo_backend().await;
    // A certificate for the TLS routes, from a throwaway CA (clients are not part of this test).
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_der = ca.clone().self_signed(&ca_key).unwrap().der().clone();
    let leaf_key = KeyPair::generate().unwrap();
    let hosts = ["client.com", "www.client.com", "dev.client.com"]
        .map(String::from)
        .to_vec();
    let leaf = CertificateParams::new(hosts)
        .unwrap()
        .signed_by(&leaf_key, &Issuer::new(ca, &ca_key))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let certs = dir.path().join("certs");
    std::fs::create_dir(&certs).unwrap();
    std::fs::write(certs.join("fullchain.pem"), leaf.pem()).unwrap();
    std::fs::write(certs.join("privkey.pem"), leaf_key.serialize_pem()).unwrap();
    let api_hash = "47bd0e2f856fe258ebba4d00930ab811d0c004dafae068c9d72511ca3512cca6";
    let src = VERBATIM
        .replace("/var/lib/geoip/GeoLite2-Country.mmdb", &kp(GEO))
        .replace("listen \":80\" \":443\"", "listen \"127.0.0.1:0\" \"127.0.0.1:0\"")
        .replace("storage-path \"/var/lib/gateway/certs.db\"", &format!("storage-path \"{}\"", kp(dir.path().join("db"))))
        .replace("listen \"127.0.0.1:9090\"", "listen \"127.0.0.1:0\"")
        .replace("gateway {", &format!("gateway {{\n    certs-dir \"{}\"", kp(&certs)))
        .replace("\"10.0.1.10:8080\"", &format!("\"{backend}\""))
        .replace("\"10.0.1.20:8080\"", &format!("\"{backend2}\""))
        .replace("\"10.0.1.11:8080\"", &format!("\"{backend}\""))
        .replace("fallback status=503 show-incident-id=true", &format!("fallback status=503 show-incident-id=true\n    redirect-https false\n    api-keys {{\n        key \"{api_hash}\" name=\"ci\"\n    }}"));
    let cfg = paasers::config::parse_str(&src, &env).unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let token = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(paasers::server::run_with(cfg, None, tx, token.clone()));
    let addrs = rx.await.unwrap();
    let http = std::net::SocketAddr::from(([127, 0, 0, 1], addrs.http.port()));
    let ask = |host: &str, extra: &str| {
        format!(
            "GET /x HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\nAccept-Encoding: zstd\r\n\r\n"
        )
    };
    // client.com and www.client.com are routed to the same backend with the example features on.
    for host in ["client.com", "www.client.com"] {
        let r = raw_request(http, &ask(host, &format!("X-Api-Key: {KEY}\r\n")))
            .await
            .to_ascii_lowercase();
        assert!(r.starts_with("http/1.1 200"), "{host}: {r}");
        assert!(r.contains("x-seen-host: ") && r.contains(host), "{host}: {r}");
    }
    // dev.client.com is a TLS route: plain HTTP is redirected, HTTPS reaches the gatekeeper.
    let r = raw_request(http, &ask("dev.client.com", "")).await;
    assert!(
        r.starts_with("HTTP/1.1 301") && r.contains("https://dev.client.com"),
        "{r}"
    );
    let https = std::net::SocketAddr::from(([127, 0, 0, 1], addrs.https.unwrap().port()));
    let r = tls_request(https, &ca_der, "dev.client.com", &ask("dev.client.com", "")).await;
    assert!(
        r.starts_with("HTTP/1.1 401") && r.contains("gatekeeper_login_required"),
        "{r}"
    );
    let r = tls_request(
        https,
        &ca_der,
        "dev.client.com",
        "GET /__gate/login HTTP/1.1\r\nHost: dev.client.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        r.starts_with("HTTP/1.1 200") && r.contains("Preview Environment"),
        "{r}"
    );
    // Any host that is not in the file is unknown.
    assert!(
        raw_request(http, &ask("other.com", ""))
            .await
            .starts_with("HTTP/1.1 404")
    );
    assert!(addrs.mcp.is_some());
    token.cancel();
    let _ = task.await;
}
