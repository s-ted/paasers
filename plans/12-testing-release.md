# P12: Integration tests, CI, build, deployment, README (`tests/`, `scripts/`, `deploy/`)

## 1. Common test harness (`tests/common/mod.rs`)

```rust
pub struct GatewayHandle { pub http: SocketAddr, pub https: Option<SocketAddr>, pub mcp: Option<SocketAddr>,
                           pub shutdown: CancellationToken, pub join: JoinHandle<anyhow::Result<()>>, _dir: tempfile::TempDir }
/// Parses `kdl` (after replacing `{{DB}}` with a temporary path, `{{GEOIP}}` with the fixture),
/// forces all listen addresses to 127.0.0.1:0, launches `paasers::server::run_with`, waits for `ready`.
pub async fn spawn_gateway(kdl: &str, env: &[(&str, &str)]) -> GatewayHandle;
/// Local hyper backend: `routes` = fn(Request) -> Response; returns address + call counter + shutdown handle.
pub async fn spawn_backend(handler: impl Fn(http::Request<Incoming>) -> BoxFuture<'static, http::Response<Body>> + Send + Sync + 'static) -> Backend;
pub fn echo_backend() -> ...;   // returns as JSON the method, path, received headers, version, body (≤ 1 MiB)
/// Minimal HTTP/1.1 client (hyper::client::conn::http1) to `addr` with a Host header.
pub async fn get(addr: SocketAddr, host: &str, path: &str, headers: &[(&str, &str)]) -> (StatusCode, HeaderMap, Bytes);
pub async fn post(addr, host, path, headers, body) -> (StatusCode, HeaderMap, Bytes);
pub fn test_ca() -> (rcgen::Certificate, rcgen::Issuer<'static, rcgen::KeyPair>);  // code validated in the spike (plans/07 §9)
```
Fake env passed to `config::parse_str(src, &|k| env.iter().find(..))` (no `std::env::set_var`, unsafe in multi-threaded code).
Each integration test: `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`, timeouts `tokio::time::timeout(10s, ..)` around every wait so CI never hangs.

## 2. Integration files and contents

| File | Tests (exact names, defined in the sub-plans) |
|---|---|
| `tests/proxy.rs` | plans/02 §9, plans/05 §9, `fallback_incident_id_matches_recorder` (plans/06) |
| `tests/health.rs` | `backend_down_gives_502_then_503_after_unhealthy`, `health_recovery`, `weighted_90_10_over_http` (1000 requests, share ∈ [0.85,0.95]) |
| `tests/tls.rs` | plans/07 §9 |
| `tests/gatekeeper.rs` | plans/09 §9 |
| `tests/cache.rs` | plans/08 §7 integration |
| `tests/security.rs` | JWT + API key + rate-limit + GeoIP end-to-end on one route, anti-spoofing of incoming `x-user-id` removed, `trusted-proxies` XFF |
| `tests/reload.rs` | `reload_on_file_change` (write new file ⇒ new route served ≤ 5 s), `invalid_reload_keeps_old`, `inflight_request_survives_reload`, `health_state_survives_reload` |
| `tests/mcp.rs` | plans/11 §7 |
| `tests/acme.rs` | `#[ignore]`: real issuance via pebble (§4) |
| `tests/specs_example.rs` | `specs_example_parses` (verbatim fixture), `specs_example_serves` (replaces upstreams with local backends, `tls` with a test cert-file, geoip with the fixture; checks routing of the 3 hosts, gatekeeper on `dev.client.com`, zstd compression, JWT required) |

## 3. Fixtures (`tests/fixtures/`, committed)

| File | Origin |
|---|---|
| `GeoIP2-Country-Test.mmdb` | `https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoIP2-Country-Test.mmdb` (MIT/Apache license, 19,492 bytes; `81.2.69.160` ⇒ `GB`) |
| `specs_verbatim.kdl` | plans/01 §7 |
| `jwt_rsa_priv.pem`, `jwt_rsa_pub.pem` | `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt_rsa_priv.pem && openssl pkey -in jwt_rsa_priv.pem -pubout -out jwt_rsa_pub.pem` |
| test `*.kdl` | written inline in the tests (raw strings `r#"..."#`) rather than as files, except `specs_verbatim.kdl` |

## 4. ACME with pebble (CI only, `scripts/pebble.sh`)

```bash
#!/usr/bin/env bash
set -euo pipefail
V=v2.10.1
D="${PEBBLE_DIR:-$PWD/target/pebble}"; mkdir -p "$D"; cd "$D"
[ -x pebble ] || { curl -sSL "https://github.com/letsencrypt/pebble/releases/download/$V/pebble-linux-amd64.tar.gz" | tar xz --strip-components=1 -C . ; }
curl -sSL -o pebble.minica.pem https://raw.githubusercontent.com/letsencrypt/pebble/main/test/certs/pebble.minica.pem
mkdir -p certs/localhost
curl -sSL -o certs/localhost/cert.pem https://raw.githubusercontent.com/letsencrypt/pebble/main/test/certs/localhost/cert.pem
curl -sSL -o certs/localhost/key.pem  https://raw.githubusercontent.com/letsencrypt/pebble/main/test/certs/localhost/key.pem
cat > pebble.json <<EOF
{"pebble":{"listenAddress":"127.0.0.1:14000","managementListenAddress":"127.0.0.1:15000",
 "certificate":"certs/localhost/cert.pem","privateKey":"certs/localhost/key.pem",
 "httpPort":${PEBBLE_HTTP_PORT:-5002},"tlsPort":5001,"ocspResponderURL":"","externalAccountBindingRequired":false}}
EOF
PEBBLE_VA_NOSLEEP=1 PEBBLE_VA_ALWAYS_VALID=0 ./pebble -config pebble.json &
echo $! > pebble.pid
```
DECISIONS for the ACME test:
* Pebble validates HTTP-01 by connecting to `<domain>:httpPort` via the **system** resolver (pebble launched without `-dnsserver`).
* Test domain: `acme-test.localhost` (RFC 6761). Observed on the dev machine: it resolves to `::1` (not 127.0.0.1) ⇒ the test gateway listens **dual-stack** `listen "[::]:5002" "[::]:5443"` to accept v4 and v6.
* `PEBBLE_HTTP_PORT=5002` = fixed HTTP port of the test gateway.
* Config of the `tests/acme.rs` test: `acme-directory "https://127.0.0.1:14000/dir"`, `acme-ca-root "$PEBBLE_DIR/pebble.minica.pem"`, `default-email "t@example.com"`, `route "acme-test.localhost" { tls; upstream "127.0.0.1:<backend>" }`.
* Success: ≤ 60 s, a `certs` row for `acme-test.localhost` exists, and a TLS handshake with SNI `acme-test.localhost` on `[::1]:5443` presents a certificate with `issuer != subject` (test client with a `ServerCertVerifier` that accepts everything and captures the chain; the verifier exists only in `tests/`).
* Precondition: if `tokio::net::lookup_host("acme-test.localhost:80")` fails **or** if `PEBBLE_DIR` is not set, the test prints the reason and returns (neutral success). It is `#[ignore]` anyway.

## 5. CI (`scripts/ci.sh`, completed)

Steps, in order (failure ⇒ stop):
1. `cargo fmt --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo clippy --all-targets --no-default-features -- -D warnings`
4. check ≤ 250 lines/file (plans/00 §9)
5. `cargo test` (full suite, excluding `#[ignore]`)
6. `cargo test --no-default-features` (without passkey)
7. `scripts/pebble.sh && PEBBLE_DIR=target/pebble cargo test --test acme -- --ignored` (separate job, tolerant of network outages)
8. `cargo zigbuild --release --target x86_64-unknown-linux-musl` then `file target/x86_64-unknown-linux-musl/release/paasers | grep -q 'statically linked'`
9. `scripts/rss.sh`

`grep -rn "unwrap()\|expect(" src/ | grep -v "#\[cfg(test)\]"` is **not** needed: the `deny` lints guarantee it.

## 6. Memory measurement (`scripts/rss.sh`)

```bash
#!/usr/bin/env bash
set -euo pipefail
BIN=target/x86_64-unknown-linux-musl/release/paasers
T=$(mktemp -d); trap 'kill $GW $BE 2>/dev/null; rm -rf "$T"' EXIT
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$T" >/dev/null 2>&1 & BE=$!
cat > "$T/gw.kdl" <<EOF
gateway { listen "127.0.0.1:18000"; storage-path "$T/db.sqlite"; }
route "rss.test" { upstream "127.0.0.1:18080"; }
EOF
"$BIN" run -c "$T/gw.kdl" & GW=$!
sleep 1
for i in $(seq 1 1000); do curl -s -o /dev/null -H 'Host: rss.test' http://127.0.0.1:18000/; done
RSS=$(awk '/VmRSS/{print $2}' /proc/$GW/status)
echo "RSS=${RSS} kB"
[ "$RSS" -lt 20480 ]
```
(The `;` separates KDL nodes on one line: valid KDL v2 syntax.)

## 7. Deployment

### 7.1 `deploy/paasers.service`
```ini
[Unit]
Description=paasers edge gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=paasers
Group=paasers
ExecStart=/usr/local/bin/paasers run -c /etc/paasers/gateway.kdl
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
StateDirectory=gateway
StateDirectoryMode=0700
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/etc/paasers /var/lib/geoip
EnvironmentFile=-/etc/paasers/env
LimitNOFILE=65536
MemoryMax=64M
TimeoutStopSec=35

[Install]
WantedBy=multi-user.target
```
`StateDirectory=gateway` ⇒ `/var/lib/gateway` (default `storage-path`). Secrets (`JWT_SECRET_KEY`, MCP token via `token-env`) in `/etc/paasers/env` (0600).

### 7.2 Procedure (follows PLAN.md §6)
1. `useradd --system --no-create-home paasers`; copy binary, config, env.
2. `paasers check -c /etc/paasers/gateway.kdl` (in GitOps CI too).
3. `systemctl enable --now paasers`.
4. Config update: atomic write (`install -m 0644 new.kdl /etc/paasers/gateway.kdl` does a rename) ⇒ auto reload ≤ 2 s; or `systemctl reload paasers`.
5. Binary update: `install` new binary ⇒ `systemctl restart paasers` (graceful shutdown 30 s); rollback = `.prev` binary.

## 8. README.md (expected content, written in P12)

Sections: Overview (1 paragraph); Build (`cargo zigbuild ...`); Quick start (5-line minimal config); Configuration reference (table copied from plans/01 §3, with defaults); Gatekeeper (`hash-password`, `gen-totp`, passkeys); MCP (plans/11 §6); Operations (reload, logs, Incident ID, flight recorder); Known limitations (PLAN.md §8).

## 9. Documented manual tests (not automatable)

1. **Passkeys**: Chrome ⇒ DevTools ⇒ ⋮ More tools ⇒ WebAuthn ⇒ "Enable virtual authenticator environment" ⇒ add a `ctap2` / `internal` authenticator with `resident key` + `user verification`; open `https://dev.client.test` (route `tls cert-file` with imported test CA) ⇒ PSK login ⇒ passkey page ⇒ Register ⇒ logout ⇒ "Sign in with a passkey" ⇒ access.
2. **Claude Desktop / Cursor**: config §plans/11 §6 ⇒ ask "inspect incident <ID>".
3. **Let's Encrypt staging** on a real VM with public DNS (`acme-directory "staging"`).

## 10. DoD P12 (= global DoD PLAN.md §10)
- [ ] CI steps §5 1-6, 8, 9 green locally; step 7 green in CI (or documented if network unavailable).
- [ ] README written. Commit `P12: integration tests & release`. Tag `v0.1.0`.
