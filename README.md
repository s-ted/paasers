# paasers

A single static binary that terminates TLS, routes by host name and proxies to your private backends. It is the edge gateway of a PaaS: automatic Let's Encrypt certificates, weighted load balancing with health checks, an HTTP cache, a "preview environment" gatekeeper, and an MCP server so an AI agent can investigate incidents from the **Incident ID** shown to your users.

* One KDL config file, one SQLite file, no external service.
* Hot reload (`SIGHUP` or file change), graceful shutdown.
* Memory budget: 32 MB. Measured on the static musl release build after 1000 requests with an empty cache: about 21.5 MB with the default of up to 4 worker threads, about 19 MB with `worker-threads 2` (`scripts/rss.sh`). The cache grows this by up to its `max-size`.

## Build

```bash
cargo build --release                                   # dynamic, for development
cargo zigbuild --release --target x86_64-unknown-linux-musl   # static binary
```

Build without passkeys (and without OpenSSL): `--no-default-features`.

## Quick start

```kdl
gateway {
    listen ":80" ":443"
}

route "app.example.com" {
    tls email="ops@example.com"
    upstream "10.0.0.10:8080"
}
```

```bash
paasers check -c gateway.kdl      # validate (exit code 2 and a line:column diagnostic on error)
paasers run   -c gateway.kdl
```

Certificates are issued over ACME HTTP-01, so port 80 must be reachable from the Internet. Until the first certificate is issued a temporary self-signed certificate is served.

## Command line

| Command | Purpose |
|---|---|
| `paasers run -c <file>` | run the gateway (default `/etc/paasers/gateway.kdl`) |
| `paasers check -c <file>` | validate a configuration |
| `paasers hash-password` | read a password on stdin, print its argon2id hash (8 characters minimum) |
| `paasers hash-api-key` | read an API key on stdin, print its SHA-256 hex digest |
| `paasers gen-totp` | print a TOTP secret (base32) and its `otpauth://` URL |

## Configuration reference

Both KDL v2 (`#true`) and KDL v1 (`true`) are accepted. Any unknown node or property is an error. `${X}-env` options read an environment variable at load time.

### `gateway`

| Node | Default |
|---|---|
| `listen "<http>" ["<https>"]` | `":80" ":443"` (`":80"` is dual-stack `[::]:80`). One argument means HTTP only. |
| `storage-path "<file>"` | `/var/lib/gateway/certs.db` |
| `acme-directory` | `production` (`staging` or an https URL) |
| `acme-ca-root "<pem>"` | none (private ACME CA, tests) |
| `default-email "<email>"` | none |
| `trusted-proxies "<cidr>"...` | none. `X-Forwarded-For` is trusted only from these peers. |
| `flight-recorder capacity=<n>` | 500 |
| `log format="text"\|"json" level="<filter>"` | `text`, `info` (`RUST_LOG` wins) |
| `limits max-connections max-body header-read-timeout max-headers-size` | 10000, 100MiB, 30s, 64KiB |
| `worker-threads <n>` | `min(cpus, 4)`. Lower it on small machines to save a few MB. |
| `default-cert "<host>"` | none (served when the client sends no SNI) |
| `shutdown-grace "<duration>"` | 30s |

`listen`, `storage-path`, `mcp-server`, `worker-threads` and `log` need a restart: a reload that changes them keeps the old values and logs a warning.

### `mcp-server`

`listen "<addr>"` (default `127.0.0.1:9090`), `token "<string>"` or `token-env "<VAR>"` (16 characters minimum). Without a token the listener must be loopback.

### `route "<host>"... { ... }`

The first host is the route id. Each host belongs to one route. `*.example.com` matches exactly one label.

| Node | Notes |
|---|---|
| `upstream "<ip:port>" [weight=<0..1000>]` | at least one, literal IP only, weight 0 drains |
| `health-check path interval timeout unhealthy-after healthy-after mode enabled` | active by default: `GET /` every 5s, below 500 is healthy, `mode="tcp"` for a connect probe |
| `timeouts request="60s"` | time to receive the response headers |
| `tls [email=..] { staging }` | auto: valid certificate from `certs-dir`, else Let's Encrypt, else temporary self-signed. `staging` uses Let's Encrypt staging for this route |
| `tls self-signed=#true` | in-memory self-signed certificate (new on every restart), wildcards allowed |
| `certs-dir "<dir>"` (gateway) | directory scanned for PEM certificates and keys (any file names, paired by public key, matched by SAN) |
| `redirect-https #false` | redirect is on by default for TLS routes |
| `fallback status=503 show-incident-id=#true title message on` | maintenance page when the backend fails |
| `cache max-size stale-while-revalidate stale-if-error default-ttl max-object-size` | shared RFC 9111 cache |
| `compression zstd brotli gzip min-size` | opt in |
| `geoip database=.. block-countries=.. allow-countries=.. inject-header` | MaxMind country database |
| `rate-limit rps=<n> burst=<n> [path="/prefix"]` | per client IP |
| `gatekeeper { ... }` | see below |
| `jwt-validation { ... }` | `secret-env` or `public-key-file`, `algorithms`, `issuer`, `audience`, `leeway`, `inject-headers`, `cookie` |
| `api-keys header="X-Api-Key" { key "<sha256>" name="ci" }` | a valid key exempts from JWT |
| `transform { request {..} response {..} }` | `set`, `add`, `remove`, `replace`, `status from= to=` |

The request goes through the layers in this fixed order: GeoIP, rate limit, gatekeeper, API key, JWT, transform, compression, cache, fallback, proxy.

Incoming `X-User-*`, `X-Jwt-Claims`, `X-Api-Key-Name` and `X-Country-Code` headers are always removed, so the backend can trust the ones it receives.

## Gatekeeper (preview environments)

```kdl
gatekeeper {
    title "Preview"
    psk "$argon2id$v=19$m=19456,t=2,p=1$..."   // from `paasers hash-password`
    totp-secret "<base32>"                      // optional, from `paasers gen-totp`
    session-duration "14d"
    rate-limit attempts=5 window="15m"
    passkey #true                               // needs a TLS route
}
```

Sessions are signed cookies. Changing the PSK or the TOTP secret invalidates every session. After a first login with the PSK the visitor can register a passkey and sign in with it afterwards.

## Incidents and the MCP server

Every response carries `traceparent` and `X-Request-Id`. When a backend is down the user sees a maintenance page with an **Incident ID** (the 32 hex digit trace id). Support gives it to an AI agent, which calls `inspect_incident`.

Tools: `get_route_status`, `query_flight_recorder`, `inspect_incident`, `purge_cache`. Client configuration (Streamable HTTP):

```json
{ "mcpServers": { "paasers": { "url": "http://127.0.0.1:9090/mcp",
    "headers": { "Authorization": "Bearer <your token>" } } } }
```

Remote access: `ssh -L 9090:127.0.0.1:9090 gateway-vm`. `GET /healthz` needs no token.

Cache entries can be tagged by the backend with `Surrogate-Key: a b c` (the header is removed before reaching the client) and purged by tag with `purge_cache`.

## Operations

* **Reload**: write the new file atomically (`install -m 0644 new.kdl /etc/paasers/gateway.kdl`) and it is applied within 2 seconds, or `systemctl reload paasers`. An invalid file keeps the previous configuration and is recorded as a `config` incident.
* **Deploy**: `deploy/paasers.service` (dedicated user, `CAP_NET_BIND_SERVICE`, state in `/var/lib/gateway`, secrets in `/etc/paasers/env`).
* **Rollback**: keep the previous binary as `paasers.prev`. The SQLite schema only evolves additively.
* **Logs**: `info` shows 4xx and 5xx accesses, `debug` shows every request. Secrets are never logged.

## Development

```bash
scripts/ci.sh                                    # fmt, clippy (two feature sets), file length
cargo test                                       # whole suite
cargo test --no-default-features                 # without passkeys
scripts/pebble.sh && PEBBLE_DIR=target/pebble cargo test --test acme -- --ignored   # real ACME
scripts/rss.sh                                   # memory budget (32 MB), needs the musl release build
```

Manual checks that cannot be automated:

1. **Passkeys**: in Chrome DevTools, More tools, WebAuthn, enable a virtual authenticator (ctap2, internal, resident key, user verification). Open a TLS route with a gatekeeper, log in with the PSK, register a passkey, log out, then use "Sign in with a passkey".
2. **MCP client**: add the configuration above to Claude Desktop or Cursor and ask for `inspect_incident <ID>`.
3. **Let's Encrypt staging** on a machine with public DNS (`acme-directory "staging"`).

## Known limitations

* Upstreams are plain HTTP over a private network, addressed by literal IP.
* The cache is in memory (lost on restart), one variant per URL, no coalescing of concurrent misses.
* ACME uses HTTP-01 only, so wildcard hosts need a local certificate in `certs-dir` (or `tls self-signed=#true`). `cert-file`/`key-file` were removed in favour of `certs-dir`.
* WebSocket works over HTTP/1.1 only.
* Passkeys pull in OpenSSL (vendored on musl). Build with `--no-default-features` to avoid it.

## License

MIT OR Apache-2.0.
