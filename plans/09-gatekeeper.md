# P9: Gatekeeper (Argon2id PSK, TOTP, HMAC cookie, Passkeys, UI) (`src/gatekeeper/`)

## 1. Files

| File | Role |
|---|---|
| `gatekeeper/mod.rs` | `GateShared`, `GateCfgRt` (compiled config per route), `GateError` |
| `gatekeeper/layer.rs` | `GatekeeperLayer` / `Gatekeeper` (concrete Service): dispatch `/__gate/*` + cookie check |
| `gatekeeper/session.rs` | HMAC-SHA256 signed cookie (pure) |
| `gatekeeper/psk.rs` | Argon2id verification (spawn_blocking + semaphore) |
| `gatekeeper/totp.rs` | TOTP verification + anti-replay |
| `gatekeeper/limiter.rs` | anti brute-force limiters |
| `gatekeeper/passkey.rs` | WebAuthn (`#[cfg(feature = "passkey")]`) |
| `gatekeeper/pages.rs` | HTML rendering (escaping, CSP nonce) |
| `gatekeeper/login.html` | single template (login + passkey), `include_str!` |

## 2. Shared state (`GateShared`, in `Shared`, survives reloads)

```rust
pub struct GateShared {
    pub hmac_key: [u8; 32],                                  // storage::get_or_create_secret("session-hmac", 32) at startup
    pub argon_sem: Arc<tokio::sync::Semaphore>,              // 2 permits
    pub login_limiters: std::sync::Mutex<HashMap<Arc<str>, Arc<LoginLimiter>>>, // per route_id
    pub totp_used: std::sync::Mutex<HashMap<Arc<str>, VecDeque<u64>>>,           // TOTP steps already consumed (<= 8 per route)
    #[cfg(feature = "passkey")]
    pub wa_pending: std::sync::Mutex<HashMap<String, (Instant, PendingCeremony)>>, // random id -> state, TTL 5 min, max 1000 entries
    pub db: storage::Db,
}
```
`PendingCeremony` = `enum { Register(webauthn_rs::prelude::PasskeyRegistration, Arc<str> /*route*/), Login(PasskeyAuthentication, Arc<str>) }`. The WebAuthn state stays **in memory**: no need for the `danger-allow-state-serialisation` feature (not enabled, consistent with Cargo.toml). Expired entries purged on each insertion (O(n), n <= 1000); beyond 1000 entries => 429 refusal.

`LoginLimiter { per_ip: DefaultKeyedRateLimiter<IpAddr>, global: DefaultDirectRateLimiter }`:
* `per_ip`: `Quota::with_period(window / attempts)` then `.allow_burst(attempts)` (e.g. 5 / 15 min => 1 token every 3 min, burst 5). `with_period` returns `Option` => `None` impossible after config validation (window > 0); treat it as a build error.
* `global`: same period divided by 20, burst `attempts * 20` (protects against distributed brute force).
* Single rule: **every attempt** (POST login or passkey/login/start), successful or not, consumes 1 token from `per_ip` (key = `ClientIp`) **then** 1 token from `global`, **before** any verification. Refusal by either => 429 with `Retry-After` = `ceil(wait_time_from(DefaultClock::default().now()).as_secs())` on the returned `NotUntil` (governor API validated).
* Recreated if `attempts`/`window` change on reload (comparison), otherwise kept.

## 3. Session cookie (`session.rs`, pure)

Format (ASCII, no `;`/`,`/space): `v1.<exp>.<m>.<sig>`
* `exp` = Unix expiration seconds (`now + session_duration`).
* `m` = `p` (PSK[+TOTP]) or `k` (passkey).
* `sig` = base64url without padding of `HMAC-SHA256(hmac_key, "v1|{route_id}|{exp}|{m}|{psk_fingerprint}")`, where `psk_fingerprint` = hex of the first 8 bytes of `SHA-256(psk_phc_string + "|" + totp_secret_or_empty)`. Changing the PSK or the TOTP secret therefore invalidates all sessions (D8).
* Verification: split into 4, `v1`, `exp` parses as `i64` and `> now`, recompute HMAC, **constant-time** comparison via `Mac::verify_slice` (hmac 0.13, validated in the spike). Any anomaly => invalid (never a 500 error).
```rust
// Exact code (compiled, strict clippy OK, tested: roundtrip, expiration, other route, other fp, 8 malformed inputs).
use hmac::{Hmac, KeyInit, Mac};
use base64::Engine;
type HS = Hmac<sha2::Sha256>;
fn mac(key: &[u8; 32], route: &str, exp: i64, m: char, fp: &str) -> Option<HS> {
    let mut h = HS::new_from_slice(key).ok()?;
    h.update(format!("v1|{route}|{exp}|{m}|{fp}").as_bytes());
    Some(h)
}
pub fn issue(key: &[u8; 32], route: &str, fp: &str, m: char, exp: i64) -> String {
    let sig = mac(key, route, exp, m, fp).map(|h| h.finalize().into_bytes().to_vec()).unwrap_or_default();
    format!("v1.{exp}.{m}.{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig))
}
pub fn verify(key: &[u8; 32], route: &str, fp: &str, cookie: &str, now: i64) -> bool {
    let mut it = cookie.split('.');
    let (Some("v1"), Some(exp), Some(m), Some(sig), None) = (it.next(), it.next(), it.next(), it.next(), it.next()) else { return false };
    let Ok(exp) = exp.parse::<i64>() else { return false };
    let mut chars = m.chars();
    let (Some(mc), None) = (chars.next(), chars.next()) else { return false };
    if exp <= now || !matches!(mc, 'p' | 'k') { return false; }
    let Ok(sig) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig) else { return false };
    mac(key, route, exp, mc, fp).is_some_and(|h| h.verify_slice(&sig).is_ok())
}
```
Verified note: without the `danger-allow-state-serialisation` feature, `PasskeyRegistration`/`PasskeyAuthentication` are **not** `Serialize` (compilation error observed) but are `Send + Sync + 'static`: hence the in-memory storage (§2). `Passkey` is `Serialize + Deserialize`; `CreationChallengeResponse` serializes with the `publicKey` key (tested).
`Set-Cookie` attributes: `{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={secs}` + `; Secure` if the route has `tls`. Default name `__Host-gate` (tls, requires Secure+Path=/ without Domain) otherwise `gate`. Logout: same name, empty value, `Max-Age=0`.
Reading: iterate over **all** `Cookie` values, split `;`, trim, `name=value`; take the first value with the right name.

## 4. PSK (`psk.rs`)

```rust
pub async fn verify_psk(sem: &Semaphore, phc: Arc<str>, candidate: String) -> bool {
    let Ok(_permit) = sem.acquire().await else { return false };
    tokio::task::spawn_blocking(move || {
        use argon2::{Argon2, PasswordVerifier};
        Argon2::default().verify_password(candidate.as_bytes(), phc.as_ref()).is_ok()
    }).await.unwrap_or(false)
}
```
(argon2 0.6 API validated: `PasswordVerifier<str>` directly accepts the PHC string; the hash parameters are used.) Candidate password limited to 1024 bytes (otherwise immediate failure, anti-DoS).

## 5. TOTP (`totp.rs`)

* Built when the route is built: `totp_rs::Builder::new().with_secret(totp_rs::Secret::try_from_base32(b32)?).build()?` (SHA1, 6 digits, 30 s step, skew 1: validated defaults).
* Verification: `code` cleaned (spaces removed), 6 ASCII digits otherwise failure. `totp.check(code, now_unix)` => `Option<u64>` = step. `None` => failure. `Some(step)`: if `step` in `totp_used[route]` => failure "code already used"; otherwise add it (keep the last 8).
* Order: TOTP verified **after** the PSK (avoids consuming a step if the PSK is wrong).

## 6. Passkeys (`passkey.rs`, feature `passkey`)

* One `Webauthn` per route **host** (rp_id = host, origin = `https://{host}`, + port if `listen_https` != 443): `WebauthnBuilder::new(host, &Url::parse(origin)?)?.rp_name(&title).build()?`, built when the route is built, stored as `HashMap<String, Arc<Webauthn>>`. Request host absent from the map => 404.
* Registration (only with a valid PSK session `m=p`):
  1. `POST /__gate/passkey/register/start`: `existing = db.list_passkeys(route)`; `exclude = existing.cred_ids`; `(ccr, state) = wa.start_passkey_registration(Uuid::new_v4(), "team", "Team", Some(exclude))`; store `state` under `id = hex(random 16)`; respond JSON `{"id": id, "options": ccr}` (`serde_json::to_value(&ccr)`).
  2. `POST /__gate/passkey/register/finish` JSON body `{"id": ..., "credential": RegisterPublicKeyCredential, "label": "<<=64 chars>"}` (body limit 64 KiB); remove the state (single use); `passkey = wa.finish_passkey_registration(&cred, &state)?`; `db.add_passkey(route, passkey.cred_id().as_ref(), serde_json::to_string(&passkey)?, label)` (`Passkey: Serialize` without the danger feature, validated); 200 `{"ok":true}`.
* Login (without session):
  1. `POST /__gate/passkey/login/start`: counts against the limiter; `passkeys = db.list_passkeys(route)` deserialized; empty => 404 JSON; `(rcr, state) = wa.start_passkey_authentication(&passkeys)?`; `{"id","options": rcr}`.
  2. `POST /__gate/passkey/login/finish` `{"id","credential": PublicKeyCredential}`; `res = wa.finish_passkey_authentication(&cred, &state)?`; find the passkey by `res.cred_id()`, `update_credential(&res)`; if `Some(true)` => `db.update_passkey(cred_id, json, now)`, otherwise `touch`; issue cookie `m=k`; `{"ok":true,"next":"<next>"}`.
* Any WebAuthn error => 400 JSON `{"ok":false,"error":"passkey_failed"}` + incident `kind="auth"` (without sensitive detail).
* Feature `passkey` absent => the `/__gate/passkey/*` routes return 404 (and the config rejects `passkey #true`).

## 7. `Gatekeeper::call`: exact algorithm

Preconditions: `cfg: Arc<GateCfgRt>` (route_id, cookie_name, session_duration, phc, psk_fp, totp: Option<Totp>, title, passkey_enabled, secure: bool, webauthn map).

1. `path = req.uri().path()`.
2. If `path` starts with `/__gate/` => dispatch (never forwarded to the backend):
   | Method + path | Action |
   |---|---|
   | `GET /__gate/login` | login page (§8), `next` from query |
   | `POST /__gate/login` | §7.1 |
   | `POST /__gate/logout` | cookie cleared, 303 `Location: /__gate/login` |
   | `GET /__gate/passkey` | session `p` required otherwise 303 login; registration page |
   | `POST /__gate/passkey/register/start|finish` | session `p` required otherwise 401 JSON; §6 |
   | `POST /__gate/passkey/login/start|finish` | §6 |
   | other | 404 |
3. Otherwise: read the cookie; valid => **remove** this cookie from the `Cookie` header (rebuild the header without it; header removed if it becomes empty) then `inner.call(req)`.
4. Invalid/absent:
   * `GET`/`HEAD` and `Accept` contains `text/html` => 303 `Location: /__gate/login?next=<percent-encode(path_and_query)>`; `Cache-Control: no-store`.
   * Otherwise => 401 JSON `{"error":"gatekeeper_login_required","login":"/__gate/login"}`, extension `IncidentKind("auth")`.

### 7.1 POST /__gate/login
* Body `application/x-www-form-urlencoded` limited to 8 KiB (`Limited`), parsed with `url::form_urlencoded::parse`: fields `password`, `totp` (optional), `next`.
* Limiter (§2): refusal => login page with message "Too many attempts. Try again in N minutes." status 429.
* `verify_psk`; if TOTP configured: `totp` required + §5.
* Failure => login page status 401 with message "Invalid credentials." (identical message whatever the cause: PSK or TOTP, no oracle), incident `kind="auth"`.
* Success => `Set-Cookie` session `m=p`; 303 to `safe_next(next)`; if `passkey_enabled` and no passkey for the route => 303 to `/__gate/passkey?next=...` (D7: offer registration after the first login).
* `safe_next(s)`: accepted only if it starts with `/`, does not start with `//` or `/\`, no control characters, <= 2048; otherwise `/`.
* **CSRF**: same-origin form, `SameSite=Lax` cookie; additionally, POST refused (403) if the `Origin` header is present and differs from the request's `{scheme}://{host}`.

## 8. UI (`login.html`, `pages.rs`)

Single page, two modes (`login` / `passkey`), < 12 KB, `lang="en"`, zero external resources. English by default.
* Placeholders: `{{TITLE}}`, `{{NONCE}}`, `{{MESSAGE}}` (`<p class="err" role="alert">` block or empty), `{{NEXT}}`, `{{TOTP_FIELD}}`, `{{PASSKEY_BUTTON}}`, `{{MODE}}`.
* `login` mode: title = config `title`; subtitle "This environment is protected."; `password` field (`type=password`, `autocomplete=current-password`, `required`, autofocus); if TOTP: `totp` field (`inputmode=numeric`, `pattern=[0-9 ]{6,7}`, `autocomplete=one-time-code`, label "6-digit code"); button "Enter"; if passkey enabled and >= 1 registered passkey: button "Sign in with a passkey".
* `passkey` mode: "Register a passkey (Touch ID, Face ID, security key) for your next visits", label field, buttons "Register" and "Later" (link to `next`).
* Inline JS (nonce): helpers `b64u2buf(s)` / `buf2b64u(b)`; conversion of the options (`challenge`, `user.id`, `excludeCredentials[].id`, `allowCredentials[].id`) to `ArrayBuffer`; `navigator.credentials.create({publicKey: options.publicKey})` / `.get(...)`; serialization of the response (`id`, `rawId`, `type`, `response.{attestationObject|authenticatorData,clientDataJSON,signature,userHandle}` in base64url, `extensions: {}`), field names matching `RegisterPublicKeyCredential`/`PublicKeyCredential` from webauthn-rs-proto (verified: `rawId`, `clientDataJSON`, `attestationObject`, `authenticatorData`, `userHandle`); `fetch` POST JSON; success => `location = next`. If `!window.PublicKeyCredential` => button hidden.
* Headers: `Content-Type: text/html; charset=utf-8`, `Cache-Control: no-store`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; style-src 'nonce-{N}'; script-src 'nonce-{N}'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'` with `N` = base64url(16 random bytes) per response.
* All dynamic values HTML-escaped (same function as plans/06 `html_escape`).

## 9. Tests

- `session::tests::roundtrip`, `expired_rejected`, `tampered_sig_rejected`, `other_route_rejected`, `psk_change_invalidates`, `malformed_never_panics` (table of 20 odd inputs).
- `psk::tests::verify_fixture_hash` (`preview` hash from plans/01 §7), `wrong_password`, `oversized_password_rejected`.
- `totp::tests::valid_code_then_replay_rejected` (`totp.generate(t)` then `check`), `wrong_code`, `non_digit_rejected`.
- `limiter::tests::burst_then_429_with_retry_after`.
- `layer::tests::redirects_html_to_login_with_next`, `json_gets_401`, `valid_cookie_forwards_and_strips_cookie`, `login_success_sets_cookie_and_redirects`, `login_failure_401_same_message`, `safe_next_rejects_open_redirect` (`//evil.com`, `/\evil.com`, `https://evil.com`), `origin_mismatch_403`, `gate_paths_never_forwarded`.
- `pages::tests::csp_nonce_matches_script_tag`, `title_escaped`.
- Integration `tests/gatekeeper.rs`: full PSK+TOTP flow over real HTTP (GET => 303, POST login => cookie, GET with cookie => backend receives the request **without** the gate cookie), 6 wrong attempts => 429.
- Passkeys: full WebAuthn ceremonies require an authenticator; unit tests limited to `register_start_returns_options_json` (checks `publicKey.challenge` present) and `finish_with_unknown_id_400`. Manual test documented in `plans/12` (Chrome DevTools "WebAuthn" virtual authenticator).

## 10. DoD P9
- [ ] §9 tests green, `cargo clippy --all-targets --no-default-features -- -D warnings` OK (passkey disabled). Commit `P9: gatekeeper`.
