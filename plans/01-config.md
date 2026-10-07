# P1: KDL configuration (`src/config/`)

> The central data model. **Any option not listed here does not exist.** An unknown node or property is an **error** (not a warning): fail-fast for GitOps.

## 1. Files

| File | Role | Target LOC |
|---|---|---|
| `config/mod.rs` | `pub fn load(path) -> Result<Config, ConfigError>`, `pub fn parse_str(src, env) -> Result<Config, ConfigError>`, re-exports | 60 |
| `config/model.rs` | structs/enums of §3 (pure data, `Debug + Clone + PartialEq`) | 220 |
| `config/kdl_ext.rs` | typed read helpers on `KdlNode` (§4) | 200 |
| `config/units.rs` | parse duration, size, listen, host, country, IP/CIDR | 150 |
| `config/parse.rs` | `gateway`, `mcp-server`, top-level | 150 |
| `config/parse_route.rs` | `route` and its simple children (tls, upstream, health, timeouts, fallback) | 220 |
| `config/parse_features.rs` | cache, compression, geoip, rate-limit, jwt, api-keys, transform | 240 |
| `config/parse_gate.rs` | gatekeeper | 120 |
| `config/validate.rs` | cross validations (§5) | 200 |
| `config/error.rs` | `ConfigError`, `Diag` (§6) | 80 |

## 2. KDL parsing: general rules

* `kdl::KdlDocument::parse(src)` (feature `v1-fallback`: tries KDL v2 then v1). So `true` **and** `#true` are accepted.
* **Comments** `//`, `/* */`, `/-` are ignored by the crate.
* Node name: `node.name().value()`. Positional arguments: entries where `entry.name().is_none()`. Properties: `entry.name() == Some(..)`. Children: `node.children()` (`Option<&KdlDocument>`).
* Values: `KdlValue::{String, Integer(i128), Float, Bool, Null}`; access via `as_string()`, `as_integer()`, `as_bool()`.
* Error position: `entry.span()` / `node.span()` (`miette::SourceSpan`, `.offset()`, `.len()`), converted to `line:column` via `line_col(src, offset)` (pure function in `error.rs`: counts the `\n` before the offset, column = number of `char` since the last `\n` + 1).
* A property repeated on the same node ⇒ error `duplicate property`. A repeated singleton node (e.g. two `cache` in one route) ⇒ error `duplicate node`.
* A **property boolean** accepts only `Bool` (not `"true"` as a string).
* Numbers: `Integer` only; out of bounds (u16/u32/u64) ⇒ error `out of range`.

## 3. Complete grammar, Rust types and defaults

Notation: `node arg... prop=value { children }`. **(req)** = required. Default indicated otherwise.

### 3.1 Top-level
```text
gateway { ... }            singleton, optional (all defaults)
mcp-server { ... }         singleton, optional (absent = MCP disabled)
route <host>+ { ... }      0..n
ip-set "<name>" { ... }   0..n, named IP list (plans/15 §2)
```
Any other top-level node ⇒ error `unknown node`.

```rust
pub struct Config { pub gateway: GatewayCfg, pub mcp: Option<McpCfg>, pub routes: Vec<RouteCfg> }
```

### 3.2 `gateway`
| Node | Syntax | Rust type | Default |
|---|---|---|---|
| `listen` | `listen "<http>" ["<https>"]` | `listen_http: SocketAddr`, `listen_https: Option<SocketAddr>` | `":80" ":443"` |
| `storage-path` | `storage-path "<path>"` | `PathBuf` | `/var/lib/gateway/certs.db` |
| `acme-directory` | `acme-directory "production"\|"staging"\|"<https url>"` | `AcmeDirectory { Production, Staging, Custom(String) }` | `production` |
| `acme-ca-root` | `acme-ca-root "<pem path>"` | `Option<PathBuf>` (pebble tests) | absent |
| `certs-dir` | `certs-dir "<directory>"` | `Option<PathBuf>`: local certificates scanned by TLS auto mode (`plans/13` §3) | absent |
| `default-email` | `default-email "<email>"` | `Option<String>` | absent |
| `trusted-proxies` | `trusted-proxies ["<entry>"...] [{ - "<entry>" }]` (IP list, plans/15 §2) | `Vec<ipnet::IpNet>` | private ranges |
| `flight-recorder` | `flight-recorder capacity=<u32>` | `flight_recorder_capacity: usize` (1..=100 000) | 500 |
| `log` | `log format="text"\|"json" level="<EnvFilter>"` | `LogCfg { json: bool, level: String }` | `text`, `info` (overridden by `RUST_LOG` if set) |
| `limits` | `limits max-connections=<u32> max-body="<size>" header-read-timeout="<dur>" max-headers-size="<size>"` | `Limits { max_connections: usize, max_body: u64, header_read_timeout: Duration, max_headers_size: u64 }` | 10000, `100MiB`, `30s`, `64KiB` |
| `worker-threads` | `worker-threads <u16>` | `Option<usize>` | `min(nb_cpus, 4)` |
| `default-cert` | `default-cert "<host>"` | `Option<String>` (must be a host of a tls route) | absent |
| `shutdown-grace` | `shutdown-grace "<dur>"` | `Duration` | `30s` |

**`listen` format** (function `units::parse_listen`):
* 1 argument ⇒ HTTP only (`listen_https = None`, no TLS listener; a route with `tls` is then a config **error**). 2 arguments ⇒ HTTP then HTTPS. 0 or > 2 ⇒ error.
* `":80"` ⇒ `[::]:80` (dual-stack, see `plans/02` §2).
* `"0.0.0.0:80"`, `"127.0.0.1:8080"`, `"[::1]:8443"` ⇒ literal `SocketAddr`.
* Port 0 accepted (tests).
* Other ⇒ error `invalid listen address`.

### 3.3 `mcp-server`
| Node | Type | Default |
|---|---|---|
| `listen "<addr>"` | `SocketAddr` | `127.0.0.1:9090` |
| `token "<string>"` | `Option<String>`; **or** `token-env "<VAR>"` (read at validation) | absent |

Rule: if neither `token` nor `token-env` ⇒ `listen` must be loopback (`ip().is_loopback()`), otherwise error `mcp-server without token must listen on loopback`. Token length ≥ 16 otherwise error.

### 3.4 `route <host>+ { ... }`
Arguments: ≥ 1 host (otherwise error). Normalization `units::normalize_host`: ASCII lowercase, removal of a trailing `.`, validation: labels `[a-z0-9-]{1,63}` not starting/ending with `-`, total ≤ 253, **or** wildcard `*.` followed by a valid name of at least 2 labels (`*.client.com`). IDN: the operator must provide punycode (`xn--...`); any non-ASCII byte ⇒ error.
`RouteCfg.id: Arc<str>` = first normalized host.

Children of `route` (all optional except `upstream`):

| Node | Cardinality | See |
|---|---|---|
| `upstream` | 1..n **(req)** | 3.5 |
| `health-check` | 0..1 | 3.6 |
| `timeouts` | 0..1 | 3.7 |
| `tls` | 0..1 | 3.8 |
| `fallback` | 0..1 | 3.9 |
| `cache` | 0..1 | 3.10 |
| `compression` | 0..1 | 3.11 |
| `geoip` | 0..1 | 3.12 |
| `rate-limit` | 0..n | 3.13 |
| `gatekeeper` | 0..1 | 3.14 |
| `jwt-validation` | 0..1 | 3.15 |
| `api-keys` | 0..1 | 3.16 |
| `transform` | 0..1 | 3.17 |
| `allow-ips` | 0..1 | plans/15 |
| `redirect-https` | 0..1: `redirect-https #false` | `bool`, default `#true` if `tls` present, whatever the TLS mode |

### 3.5 `upstream "<ip:port>" [weight=<u32>]`
* Address: literal `SocketAddr` (IP required, no DNS name: D23). Otherwise error `upstream must be ip:port`.
* `weight`: 0..=1000, default 1. `weight=0` = drained (never chosen, but health-checked).
* Sum of weights > 0 required.
* Duplicate address within a route ⇒ error.
* Non-private IP (not RFC1918, not loopback, not ULA `fc00::/7`, not link-local, not CGNAT `100.64/10`) ⇒ `warn!` (not an error).

```rust
pub struct UpstreamCfg { pub addr: SocketAddr, pub weight: u32 }
```

### 3.6 `health-check`
`health-check path="/" interval="5s" timeout="2s" unhealthy-after=2 healthy-after=2 mode="http"|"tcp" enabled=#true`
| Property | Type | Default |
|---|---|---|
| `path` | `String` starting with `/` | `/` |
| `interval` | `Duration` ≥ 1s | `5s` |
| `timeout` | `Duration` < interval | `2s` |
| `unhealthy-after` | `u32` ≥ 1 | 2 |
| `healthy-after` | `u32` ≥ 1 | 2 |
| `mode` | `HealthMode { Http, Tcp }` | `http` |
| `enabled` | `bool` | `#true` |
Absent ⇒ all defaults (health-check **active by default**, convention).

### 3.7 `timeouts request="60s"`
`request` (max delay between sending the request and receiving the response **headers**): default `60s`, bounds [100ms, 1h]. The connect timeout is fixed (5 s, not configurable, cf. `plans/05` §2). Property `connect` ⇒ error `unknown property` like any other.

### 3.8 `tls` (superseded by `plans/13-tls-modes.md` §2, summary)
`tls [email="<email>"] [self-signed=#true] { [staging] }`
* **auto** mode (default): per host, a valid local certificate from `gateway.certs-dir`, otherwise Let's Encrypt
  (ACME HTTP-01, `email` or `gateway.default-email`), otherwise a temporary self-signed certificate.
  Optional child `staging` uses Let's Encrypt staging for this route.
* **self-signed** mode: `self-signed=#true`, certificate generated in memory; incompatible with `email` and `staging`.
* `cert-file` / `key-file` are **removed** (error `unknown property`, hint `use gateway certs-dir`).
```rust
pub enum TlsMode { Auto { acme: Option<AcmeTarget> }, SelfSigned }
pub struct AcmeTarget { pub email: String, pub staging: bool }
pub struct TlsCfg { pub mode: TlsMode }
```

### 3.9 `fallback status=503 show-incident-id=#true [title="..."] [message="..."]`
| Property | Default |
|---|---|
| `status` | 503. Status **returned to the client** when the fallback activates (u16 ∈ 500..=599) |
| `show-incident-id` | `#true` |
| `title` | `"Service temporarily unavailable"` |
| `message` | `"We are working on restoring the service. Please try again in a few moments."` |
| `on` | `"502,503,504"`: list of statuses that trigger the fallback |
Always active, even without the node (convention).

### 3.10 `cache`
`cache max-size="256MB" stale-while-revalidate=30 [default-ttl="0s"] [max-object-size="8MiB"] [stale-if-error=300]`
| Property | Type | Default |
|---|---|---|
| `max-size` | size (bytesize: `256MB` = 256 000 000, `256MiB` = 268 435 456) | `64MiB` |
| `stale-while-revalidate` | **integer seconds** or duration string (`30`, `"30s"`) | 0 |
| `stale-if-error` | same | 0 |
| `default-ttl` | duration | `0s` (= no caching without explicit headers) |
| `max-object-size` | size | `8MiB` |
Constraint: `max-object-size` ≤ `max-size`.

### 3.11 `compression zstd=#true brotli=#true gzip=#true min-size=1024`
Defaults: all `#true`, `min-size` 1024 (`u64`, bounds 0..=16 MiB; integer = bytes, or size string `"1KiB"`). If all three are `#false` ⇒ error `compression with no algorithm`. Node absent ⇒ **no** compression (opt-in, the backend may already compress).

### 3.12 `geoip database="<path>" [block-countries="CN,RU"] [allow-countries="FR,BE"] [inject-header=#true]`
* `database` **(req)**: readable file, opened (mmap) at load; failure ⇒ error.
* Countries: CSV of ISO 3166-1 alpha-2 codes, spaces tolerated, normalized to uppercase, each code `[A-Z]{2}` otherwise error.
* `block-countries` and `allow-countries` mutually exclusive; neither = enrichment only.
* `inject-header` default `#true`.

### 3.13 `rate-limit rps=<u32> burst=<u32> [path="/prefix"]`
* `rps` ≥ 1 **(req)**, `burst` default = `rps`, ≥ 1.
* At most **one** `rate-limit` without `path` (global route limit); `path` values distinct from each other. Evaluation order: longest matching prefix, then the global one.

### 3.14 `gatekeeper { ... }`
| Node | Type | Default |
|---|---|---|
| `title "<txt>"` | `String` | `"Protected access"` |
| `psk "<argon2id PHC>"` **(req, or `psk-env`)** | `String` validated by `argon2::password_hash::phc::PasswordHash::new` **and** algo = `argon2id` | — |
| `psk-env "<VAR>"` | the variable contains the PHC hash | — |
| `totp-secret "<base32>"` / `totp-secret-env "<VAR>"` | secret ≥ 16 decoded bytes (`totp_rs::Secret::try_from_base32`) | absent |
| `session-duration "<dur>"` | `Duration` 1m..=90d | `14d` |
| `rate-limit attempts=<u32> window="<dur>"` | anti brute-force | `5`, `15m` |
| `passkey <bool>` | enables WebAuthn | `#false`; `#true` without cargo feature `passkey` ⇒ error |
| `cookie-name "<name>"` | `[A-Za-z0-9_-]+` | `__Host-gate` if route `tls`, otherwise `__gate` (`__Host-` needs `Secure`, so it cannot be used over plain HTTP) |
Exactly one of `psk`/`psk-env` ⇒ otherwise error.

### 3.15 `jwt-validation { ... }`
| Node | Type | Default |
|---|---|---|
| `secret-env "<VAR>"` | HMAC; the variable must exist and be non-empty at load | — |
| `public-key-file "<pem>"` | RSA / EC P-256/P-384 / Ed25519, detected by the PEM header (`RSA PUBLIC KEY`/`PUBLIC KEY` + successive attempts `from_rsa_pem`, `from_ec_pem`, `from_ed_pem`) | — |
| `algorithms "HS256" ...` | `Vec<jsonwebtoken::Algorithm>` | HMAC ⇒ `[HS256]`; RSA ⇒ `[RS256]`; EC ⇒ `[ES256]`; Ed ⇒ `[EdDSA]` |
| `issuer "<iss>"...` | `Vec<String>` | empty = not checked |
| `audience "<aud>"...` | `Vec<String>` | empty = not checked |
| `leeway "<dur>"` | | `60s` |
| `inject-headers <bool>` | | `#true` |
| `cookie "<name>"` | alternative token source | absent |
Exactly one key source. Algorithm incompatible with the key ⇒ error.

### 3.16 `api-keys header="X-Api-Key" { key "<sha256 hex 64>" name="<label>" }`
`header` default `X-Api-Key`. ≥ 1 `key`. Lowercase/uppercase hex accepted, normalized to lowercase, 64 characters otherwise error. `name` **(req)**, unique.

### 3.17 `transform { request { ... } response { ... } }`
Children of `request` and `response`:
```text
set "<Header>" "<value>"          replaces (removes all occurrences then inserts)
add "<Header>" "<value>"          append
remove "<Header>"                 removes all occurrences
replace "<Header>" "<regex>" "<replacement>"   regex on each value; $1 etc.; invalid value after replacement ⇒ header removed + warn
```
In `response` only: `status from=<u16> to=<u16>` (0..n).
Values subject to variable interpolation (only in `set`/`add`): `{client_ip}`, `{trace_id}`, `{host}`, `{country}`; any other brace stays literal.
Invalid header name (`HeaderName::from_bytes`) or invalid regex ⇒ config error. Touching `host`, `content-length`, `transfer-encoding`, `connection` is forbidden ⇒ error.

## 4. `kdl_ext.rs`: internal API (pure, tested)

```rust
pub struct NodeCtx<'a> { pub node: &'a KdlNode, pub src: &'a str }
impl<'a> NodeCtx<'a> {
    pub fn args(&self) -> impl Iterator<Item = &'a KdlEntry>;         // positional
    pub fn arg_str(&self, i: usize) -> Result<&'a str, ConfigError>;  // error "expected string argument #i"
    pub fn args_str(&self) -> Result<Vec<&'a str>, ConfigError>;
    pub fn prop(&self, name: &str) -> Option<&'a KdlEntry>;
    pub fn prop_str(&self, name: &str) -> Result<Option<&'a str>, ConfigError>;
    pub fn prop_bool(&self, name: &str) -> Result<Option<bool>, ConfigError>;
    pub fn prop_u32(&self, name: &str) -> Result<Option<u32>, ConfigError>;   // same for u16/u64
    pub fn prop_dur(&self, name: &str) -> Result<Option<Duration>, ConfigError>; // humantime string OR integer = seconds
    pub fn prop_size(&self, name: &str) -> Result<Option<u64>, ConfigError>;
    pub fn children(&self) -> impl Iterator<Item = NodeCtx<'a>>;
    /// Checks that no property outside `allowed` exists and that none is duplicated.
    pub fn check_props(&self, allowed: &[&str]) -> Result<(), ConfigError>;
    /// Checks the number of positional arguments.
    pub fn check_args(&self, min: usize, max: usize) -> Result<(), ConfigError>;
    pub fn err(&self, msg: impl Into<String>) -> ConfigError;         // attaches the node span
}
```
Durations: `humantime::parse_duration` (accepts `14d`, `15m`, `30s`, `1h 30m`). Sizes: `bytesize::ByteSize::from_str` (`"256MB"` ⇒ 256 000 000; tested).

## 5. Cross validations (`validate.rs`)

1. No (normalized) host present in two routes (including the same wildcard). The error cites both routes.
2. `default-cert` ⇒ host of a route with `tls`.
3. `listen_http != listen_https`, and ≠ `mcp.listen`.
4. Every host of a `tls` auto route is covered by a local certificate in `certs-dir` **or** ACME is possible for the route (email defined, no wildcard host); a host covered only locally without ACME is a warning (`plans/13` §5.1). `certs-dir`, when set, is a readable directory.
5. `*-env`: variable present and non-empty (`std::env::var`), read via an injected `&dyn Fn(&str) -> Option<String>` (testable without touching the real environment).
6. `geoip.database` exists and opens; routes sharing the same path share the same `Arc<Reader>` (deduplication in the runtime builder, not here).
7. `public-key-file`, `acme-ca-root`: readable files.
8. Rate-limit `path`: starts with `/`.
9. Health `timeout < interval`.
10. `passkey #true` ⇒ `tls` route required (WebAuthn requires a secure context) otherwise error.
11. `limits.max-headers-size` ∈ [8KiB, 1MiB] (hyper `assert!` if < 8192: panic avoided by validation); `max-connections` ≥ 1; `max-body` ≥ 1KiB; `header-read-timeout` ≥ 1s.

## 6. Errors

```rust
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{path}: cannot read: {source}")] Io { path: PathBuf, source: std::io::Error },
    #[error("KDL syntax error at {line}:{col}: {msg}")] Syntax { line: usize, col: usize, msg: String },
    #[error("{line}:{col}: {msg}")] Invalid { line: usize, col: usize, msg: String },
    #[error("{0}")] Semantic(String),     // cross validations without a single position
}
```
Syntax: for `KdlError`, take `err.diagnostics.first()`: `span.offset()` ⇒ line/col, `message.or(label)` ⇒ msg.
`paasers check` displays only the **first** error encountered (sequential parse, simple, deterministic), on stderr, in the format `error: <path>:<Display of ConfigError>`, exit code 2.

## 7. Reference example: `examples/gateway.kdl`

Exactly the example from SPECS.md §4 with two changes: `psk` replaced by a real hash and the v2 syntax (`#true`). Fixture hash (password `preview`, generated and verified with argon2 0.6, params `m=19456,t=2,p=1`):

```text
$argon2id$v=19$m=19456,t=2,p=1$ftC9LdPXCcZ6MiQpvWUwXA$haZvTFqngv2fUrBLJTBmAw2Ltxdy9HonzbKTkg4bXhI
```

A second file `tests/fixtures/specs_verbatim.kdl` contains the **verbatim** SPECS text (v1 syntax, bare `true`) with only this hash in place of `$argon2id$v=19$m=19456,t=2,p=1$...`; both must parse to **equal** `Config` values (test `config::tests::specs_example_v1_equals_v2`).

Test environment: `JWT_SECRET_KEY=test-secret-at-least-32-bytes-long!!` provided via the injected fake env (§5.5). The example's GeoIP database (`/var/lib/geoip/...`) does not exist in tests: tests replace the path with `tests/fixtures/GeoIP2-Country-Test.mmdb` via `src.replace(..)` before parsing.

Fixture API key: plaintext key `test-api-key-0123456789`, SHA-256 hex `47bd0e2f856fe258ebba4d00930ab811d0c004dafae068c9d72511ca3512cca6`.

Rust 2024 pitfall: `gen` is a reserved keyword. Never name a function/module `gen` (use `generate`; `gen_totp` is accepted since it is a compound identifier).

## 8. Tests (mandatory, in the corresponding files)

`units.rs`
- `listen_colon_port_is_dual_stack` (`":80"` ⇒ `[::]:80`), `listen_explicit_v4_v6`, `listen_invalid`.
- `normalize_host_lower_trailing_dot`, `host_rejects_underscore_and_unicode`, `wildcard_ok`, `wildcard_single_label_rejected` (`*.com`).
- `size_mb_vs_mib`, `duration_days_minutes`, `duration_integer_is_seconds`.
- `countries_csv_normalized`, `country_invalid`.

`parse*.rs` (via `parse_str` with fake env)
- `empty_file_gives_defaults` (0 routes, default listen, default storage).
- `specs_example_v1_equals_v2`.
- For **each** node of §3: a "defaults" test and an "all properties" test.
- Errors: `unknown_top_level_node`, `unknown_route_child`, `unknown_property`, `duplicate_property`, `duplicate_singleton_node`, `upstream_hostname_rejected`, `weight_sum_zero`, `psk_truncated_hash_rejected` (SPECS hash with `...`), `psk_argon2i_rejected`, `jwt_two_key_sources`, `jwt_secret_env_missing`, `geoip_block_and_allow`, `compression_all_false`, `transform_forbidden_header`, `transform_bad_regex`, `mcp_public_without_token`.
- `error_position_line_col`: an error on line 3 reports `3:<col>`.

`validate.rs`
- `duplicate_host_across_routes`, `wildcard_without_local_cert_rejected` (replaces `wildcard_with_acme_rejected`), `passkey_requires_tls`, `default_cert_must_be_tls_route`, `listen_conflicts`.
- TLS mode tests: `plans/13` §9 (config section).

## 9. DoD P1
- [ ] All §8 tests pass: `cargo test config::`.
- [ ] `paasers check -c examples/gateway.kdl` ⇒ `OK: 2 routes` and exit 0 (implemented in P2/cli, but the `config::load` function is ready).
- [ ] Commit `P1: config`.
