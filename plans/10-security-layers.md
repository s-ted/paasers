# P10: Security layers and "Quick Wins" (`src/layers/`)

Each layer follows **exactly** the concrete Tower pattern from `plans/00` §5 and is tested in isolation with `tower::ServiceExt::oneshot` on a dummy `service_fn` that echoes back the received headers (JSON) so the injection can be asserted.

## 1. Rate-limit (`layers/ratelimit.rs`)

* Registry `LimiterRegistry`: `Mutex<HashMap<(Arc<str> /*route*/, Option<String> /*path*/), (RateLimitCfg, Arc<governor::DefaultKeyedRateLimiter<IpAddr>>)>>`; `get_or_create` reuses the instance if the config (`rps`, `burst`) is identical, otherwise creates a new one.
* Quota: `Quota::per_second(NonZeroU32::new(rps)?).allow_burst(NonZeroU32::new(burst)?)` (validated; `None` impossible after config validation ⇒ `BuildError`).
* Selection: among the `path=Some(p)` limiters, the one with the longest prefix `p` such that `req.path().starts_with(p)`; then the global one (`path=None`) if it exists. **Both** are checked (prefix then global); the first refusal wins.
* Refusal: `check_key(&ip)` ⇒ `Err(nu)` ⇒ 429, `Retry-After: max(1, ceil(nu.wait_time_from(DefaultClock::default().now()).as_secs_f64()))`, body via `observe::fallback::render_error(429, ...)`, extension `IncidentKind("rate_limited")`.
* Maintenance: global task every 60 s ⇒ for each limiter `retain_recent()` then `shrink_to_fit()` (R9).
* Tests: `allows_burst_then_429` (rps=1 burst=2: 2 OK, 3rd 429 with `Retry-After: 1`), `per_ip_isolated`, `path_prefix_more_specific`, `global_and_prefix_both_apply`, `retry_after_at_least_1`.

## 2. GeoIP (`layers/geoip.rs`)

* `GeoRegistry`: `Mutex<HashMap<PathBuf, (SystemTime /*mtime*/, Arc<GeoDb>)>>`. The concrete type `Reader<Mmap>` is never named (`memmap2` is not a direct dependency): it is encapsulated in a closure.
* Exact code (compiled, strict clippy OK, tested):
  ```rust
  pub struct GeoDb(Box<dyn Fn(IpAddr) -> Option<[u8; 2]> + Send + Sync>);
  impl GeoDb { pub fn country(&self, ip: IpAddr) -> Option<[u8; 2]> { (self.0)(ip) } }
  #[allow(unsafe_code)]
  pub fn open(path: &Path) -> Result<GeoDb, maxminddb::MaxMindDbError> {
      // SAFETY: file only replaced by atomic rename; never modified in place.
      let r = unsafe { maxminddb::Reader::open_mmap(path) }?;
      Ok(GeoDb(Box::new(move |ip| {
          let res = r.lookup(ip).ok()?;
          let c: Option<&str> = res.decode_path(&maxminddb::path!["country", "iso_code"]).ok()?;
          c.and_then(|s| <[u8; 2]>::try_from(s.as_bytes()).ok())
      })))
  }
  ```
  (Validated: `81.2.69.160` ⇒ `GB`, `10.0.0.1` ⇒ `None` on `GeoIP2-Country-Test.mmdb`.)
* Reloading the `.mmdb` file: on config reload only if the file's `mtime` has changed (the registry remembers `(mtime, Arc<GeoDb>)`).
* `call`: `cc = geodb.country(client_ip).unwrap_or(*b"XX")`.
  * `block` contains `cc` ⇒ 403 (`render_error`), `IncidentKind("geo_blocked")`.
  * `allow` non-empty and does not contain `cc` ⇒ 403 (same; `XX` blocked, D18).
  * Otherwise: extension `CountryCode(cc)`; if `inject_header` ⇒ `x-country-code: <cc>` on the request.
* Tests (fixture `tests/fixtures/GeoIP2-Country-Test.mmdb`, MIT, downloaded from `https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoIP2-Country-Test.mmdb`, committed): `gb_ip_resolves` (`81.2.69.160`), `unknown_ip_xx` (`10.0.0.1`), `block_gb_403`, `allow_list_blocks_xx`, `header_injected_and_spoof_stripped`.

## 3. API keys (`layers/apikey.rs`)

* Compiled config: `Vec<([u8; 32], Arc<str> /*name*/)>` (hex decoded).
* `call`: read `header` (config); absent ⇒ if `jwt_configured` **let it pass** to the JwtLayer (D16: one or the other); otherwise 401 JSON `{"error":"api_key_required"}` + `WWW-Authenticate: ApiKey header="X-Api-Key"`, `IncidentKind("auth")`.
* Present: `h = sha256(value_bytes)`; compare against **all** keys with `subtle::ConstantTimeEq` (`h.ct_eq(&k)`), walking the entire list (no early exit); found ⇒ remove the header, insert `x-api-key-name: <name>`, extension `ApiKeyAuthenticated`; not found ⇒ 401 `{"error":"invalid_api_key"}` (even if JWT is configured: a wrong key is an error).
* Tests: `valid_key_forwarded_with_name_and_header_removed` (fixture key plans/01 §7), `invalid_key_401`, `missing_key_401_without_jwt`, `missing_key_passes_to_jwt_when_configured`.

## 4. JWT (`layers/jwt.rs`)

* Build: `DecodingKey`:
  * `secret-env` ⇒ `DecodingKey::from_secret(value.as_bytes())`.
  * `public-key-file` ⇒ read PEM; try in order `from_rsa_pem`, `from_ec_pem`, `from_ed_pem`; detected family = first one that succeeds ⇒ default algorithms (plans/01 §3.15). None ⇒ `BuildError::Jwt`.
  * `Validation::new(algs[0])` then `v.algorithms = algs.clone()`; `v.leeway = leeway_secs`; `v.validate_exp = true`; `v.required_spec_claims = {"exp"}`; non-empty `issuer` ⇒ `v.set_issuer(&iss)`; non-empty `audience` ⇒ `v.set_audience(&aud)` otherwise `v.validate_aud = false`.
  * Algorithm incompatible with the key (e.g. `RS256` + secret) ⇒ `BuildError` (checked by family: HS* ⇔ secret, RS*/PS* ⇔ RSA, ES* ⇔ EC, EdDSA ⇔ Ed).
  * Verified in the spike (jsonwebtoken 11.1, aws_lc_rs): `from_rsa_pem`/`from_ec_pem` **fail** on an Ed25519 PEM (so the detection order is safe); EdDSA sign/verify OK; HS256 token rejected by an Ed key; `alg: none` token rejected.
* `call`:
  1. Extension `ApiKeyAuthenticated` present ⇒ `inner` directly (D16).
  2. Token: `Authorization: Bearer <t>` (case-insensitive scheme, one space) otherwise the config `cookie` cookie. Absent ⇒ 401 `{"error":"token_required"}` + `WWW-Authenticate: Bearer realm="{route_id}"`.
  3. `jsonwebtoken::decode::<serde_json::Map<String, Value>>(t, &key, &validation)` (API validated; ~µs). Error ⇒ 401 `{"error":"invalid_token"}` + `WWW-Authenticate: Bearer error="invalid_token"`, `IncidentKind("auth")`, error detail **not** returned to the client (logged at `debug!`).
  4. `inject_headers` ⇒ `x-user-id` = `sub` (string or converted number), `x-user-email` = `email` (string), `x-user-roles` = `roles`: array of strings joined with `,` or string; `x-jwt-claims` = base64url-nopad(`serde_json::to_vec(&claims)`) if ≤ 8 KiB otherwise omitted. Values invalid for `HeaderValue` ⇒ header omitted.
  5. The `Authorization` header is **kept** toward the backend (the backend may re-verify).
* Performance test `jwt_decode_under_50us_hs256` (`#[ignore]`, run with `cargo test --release -- --ignored jwt_decode_under_50us_hs256`): 2,000 HS256 decodes of a token with `sub`, `exp`, `iss`, `email`, `roles`; assert median < 50 µs (measured during design: 3 µs). No assertion for EdDSA/RSA (EdDSA measured at 50 µs median, see PLAN R14).
* Tests (keys generated in the test: HS256 via `EncodingKey::from_secret`, Ed25519 via `rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)` ⇒ `serialize_pem()` / `public_key_pem()`, RSA: fixture PEM `tests/fixtures/jwt_rsa_{priv,pub}.pem` generated once with `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`): `hs256_valid_injects_claims`, `expired_401`, `wrong_issuer_401`, `wrong_audience_401`, `alg_none_rejected` (hand-forged token `eyJhbGciOiJub25lIn0.<claims>.`), `hs_token_on_rsa_key_rejected`, `eddsa_valid`, `rs256_valid`, `cookie_source`, `api_key_bypasses_jwt`, `roles_array_joined`.

## 5. Compression (`layers/compression.rs`, validated in the spike)

```rust
pub fn wrap(inner: RouteSvc, cfg: &CompressionCfg) -> RouteSvc {
    use tower::{Layer, ServiceExt};
    use tower_http::compression::{CompressionLayer, CompressionLevel, predicate::{DefaultPredicate, Predicate, SizeAbove}};
    let pred = DefaultPredicate::new().and(SizeAbove::new(cfg.min_size)).and(extra_ok as fn(http::StatusCode, http::Version, &http::HeaderMap, &http::Extensions) -> bool);
    let layer = CompressionLayer::new().gzip(cfg.gzip).br(cfg.brotli).zstd(cfg.zstd)
        .quality(CompressionLevel::Default).compress_when(pred);
    RouteSvc::new(layer.layer(inner).map_response(map_resp))
}
fn extra_ok(status: http::StatusCode, _v: http::Version, h: &http::HeaderMap, _e: &http::Extensions) -> bool {
    !(status.is_informational() || status == http::StatusCode::NO_CONTENT
      || status == http::StatusCode::NOT_MODIFIED || h.contains_key(http::header::CONTENT_RANGE))
}
```
* `SizeAbove::new` takes a `u64` (tower-http 0.7.1, verified in the source; the spike failed when passing a `u16`) ⇒ `cfg.min_size: u64` (plans/01 §3.11).
* `DefaultPredicate` already excludes: gRPC, images, `text/event-stream`, responses < 32 B; `tower-http` never recompresses a response that has `Content-Encoding`, and handles `Accept-Encoding` (q-values) + `Vary: accept-encoding`. Brotli `Default` = quality 4 (verified in tower-http).
* Tests: `zstd_when_accepted` (validated in the spike), `gzip_fallback`, `no_compress_small`, `no_compress_101` (validated), `no_compress_already_encoded`, `vary_header_added`.

## 6. Transform (`layers/transform.rs`)

Compiled config:
```rust
pub enum HeaderOp { Set(HeaderName, Template), Add(HeaderName, Template), Remove(HeaderName), Replace(HeaderName, regex::Regex, String) }
pub struct Template(Vec<Part>); pub enum Part { Lit(String), ClientIp, TraceId, Host, Country }
pub struct TransformRt { pub request: Vec<HeaderOp>, pub response: Vec<HeaderOp>, pub status: Vec<(StatusCode, StatusCode)> }
```
* `Template::parse`: replaces `{client_ip}`, `{trace_id}`, `{host}`, `{country}`; any other `{..}` is literal. Rendering: `client_ip` = `ClientIp`, `trace_id` = 32 hex, `host` = normalized Host header, `country` = `CountryCode` or `XX`. Rendered value invalid for `HeaderValue` ⇒ operation skipped + `debug!`.
* Applied **in declaration order**. `Replace`: for each value (`get_all`), if `to_str()` OK ⇒ `re.replace_all(v, repl)`; invalid result ⇒ value removed + `warn!`.
* Request: ops applied before `inner`. Response: ops applied after; then `status`: first `(from,to)` where `from == resp.status()` ⇒ `*resp.status_mut() = to`.
* Context (ip, trace, host, country) captured from the request **before** calling `inner` (for the response ops).
* Tests: `set_add_remove_order`, `replace_regex_capture`, `template_variables`, `unknown_braces_literal`, `status_mapping_first_match`, `invalid_value_skipped`.

## 7. DoD P10
- [ ] Tests §1-6 green (`cargo test layers::`). Commit `P10: security layers`.
