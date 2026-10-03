# paasers

**The edge gateway of a PaaS in a single static binary.** Automatic TLS, host-based routing, load balancing, static file serving, caching, access protection and AI-assisted incident diagnosis. One config file, one SQLite file, no external service.

## Why paasers

* **Effortless HTTPS**: Let's Encrypt certificates are issued and renewed automatically, a temporary certificate is served while issuance runs, local certificates and wildcards are supported.
* **One static executable, zero dependency**: no runtime, no shared library, no sidecar, no external database. Copy the file to a machine and run it. Built with musl and verified as statically linked for Linux x86_64 (about 21 MB) and aarch64 (about 19 MB). Glibc builds work too.
* **Lightweight**: 32 MB memory budget. Measured at about 21.5 MB after 1000 requests (19 MB with `worker-threads 2`).
* **Safe deployments**: weighted traffic split (canary, blue/green), active health checks, automatic retry on another backend, draining with `weight=0`.
* **Incidents solved in one sentence**: when a backend goes down, users see a maintenance page with an **Incident ID**. An AI agent passes it to the built-in MCP server and gets the root cause.
* **Protected previews**: shared password, TOTP and passkeys, with brute force protection.
* **Built-in security**: GeoIP, rate limiting, JWT, API keys, trusted identity headers are always sanitized.
* **Static files too**: a route can serve a directory (listing, index file, single page app mode, Range) behind the same TLS, login and rate limit as a proxied route. With no configuration at all, it serves the current directory.
* **Fast**: RFC 9111 cache with stale-while-revalidate and stale-if-error, zstd/brotli/gzip compression on by default.
* **Easy to operate**: hot reload (`SIGHUP` or file change), graceful shutdown, an invalid config never replaces a good one, errors report line and column.

## Quick start

```kdl
route "app.example.com" {
    tls email="ops@example.com"
    upstream "10.0.0.10:8080"
}
```

```bash
cargo zigbuild --release --target x86_64-unknown-linux-musl    # static binary (or aarch64-unknown-linux-musl)
paasers check -c gateway.kdl    # validate (exit code 2 and a line:column diagnostic on error)
paasers run   -c gateway.kdl
```

Certificates use ACME HTTP-01, so port 80 must be reachable from the Internet. Without a `gateway` block, the gateway listens on `:80` and `:443`.

### Serve the current directory

With no route configured, `paasers run` serves the current directory on every host, like a minimal file server (a missing default configuration file `/etc/paasers/gateway.kdl` is not an error). Directory listing is on, hidden files and symbolic links are not served.

The built-in `gateway` defaults still apply: ports `:80` and `:443` and the database in `/var/lib/gateway`, which suit a service running as root or under systemd. For a quick run as a normal user, give a port and a writable database path:

```kdl
// serve.kdl
gateway {
    listen ":8080"
    storage-path "/tmp/paasers.db"      // outside the served directory
}
```

```bash
cd ~/public && paasers run -c ~/serve.kdl
```

A route with neither `upstream` nor `static` does the same for its hosts, and `static "<dir>"` picks another directory. As soon as one route is configured, unknown hosts answer 404 as usual. See [Static files](docs/features/static.md).

## A complete example

```kdl
mcp-server { token-env "MCP_TOKEN" }

route "client.com" "www.client.com" {
    tls email="admin@example.com"
    upstream "10.0.1.10:8080" weight=90     // 90/10 canary
    upstream "10.0.1.20:8080" weight=10
    cache max-size="256MB" stale-while-revalidate="30s"
    geoip database="/var/lib/geoip/GeoLite2-Country.mmdb" block-countries="CN,RU"
    rate-limit rps=50 burst=100
}

route "dev.client.com" {
    tls email="admin@example.com"
    upstream "10.0.1.11:8080"
    gatekeeper { psk-env "PREVIEW_PSK_HASH" }
}
```

## Features

Each page documents the defaults and gives configuration examples.

| Feature | In short |
|---|---|
| [Global settings](docs/features/gateway.md) | listeners, logs, limits, trusted proxies |
| [Routing and load balancing](docs/features/routing.md) | hosts, wildcards, weights, timeouts, WebSocket |
| [Static files](docs/features/static.md) | serve a directory: listing, index, SPA mode, Range |
| [Health checks](docs/features/health-checks.md) | HTTP or TCP probes, thresholds |
| [TLS and certificates](docs/features/tls.md) | Let's Encrypt, `certs-dir`, self-signed |
| [Maintenance page](docs/features/fallback.md) | Incident ID, HTML or JSON |
| [HTTP cache](docs/features/cache.md) | RFC 9111, stale serving, tag purge |
| [Compression](docs/features/compression.md) | zstd, brotli, gzip |
| [GeoIP](docs/features/geoip.md) | block or allow by country |
| [Rate limit](docs/features/rate-limit.md) | per IP, global or per path |
| [Gatekeeper](docs/features/gatekeeper.md) | PSK, TOTP, passkeys |
| [JWT](docs/features/jwt.md) | HMAC or public key, identity injection |
| [API keys](docs/features/api-keys.md) | named SHA-256 digests |
| [Transform](docs/features/transform.md) | headers and status codes |
| [MCP server](docs/features/mcp.md) | incident investigation by an AI agent |

Layer order for every request: GeoIP, rate limit, gatekeeper, API key, JWT, transform, compression, cache, fallback, then the proxy or the static file service.

The format is KDL (v1 and v2 accepted). Any unknown node or property is an error, and `${X}-env` options read an environment variable at load time.

## How it compares

paasers is deliberately narrow: an HTTP edge gateway for a fleet of private backends, plus a simple static file server, with zero dependencies and a tiny footprint. Traefik, nginx and Apache httpd are far more general. This table tries to be fair about both sides. Facts about other projects were checked against their documentation in October 2026, so verify before relying on them.

| | paasers | Traefik | nginx | Apache httpd |
|---|---|---|---|---|
| **Scope** | HTTP(S) reverse proxy and gateway | HTTP, TCP and UDP proxy, dynamic ingress | web server, HTTP, TCP and UDP proxy | web server, application hosting, reverse proxy |
| **Config** | one KDL file, strict validation with line and column | static file plus dynamic providers (Docker, Kubernetes, Consul, files...) | own syntax, `nginx -t` | own syntax, `apachectl configtest` |
| **Single static executable, no dependency** | ✅ | ✅ | ❌ | ❌ |
| **Let's Encrypt** | ✅ built in, HTTP-01 only | ✅ built in, HTTP-01, TLS-ALPN-01, DNS-01 | ⚠️ separate official module, HTTP-01 and TLS-ALPN-01 | ⚠️ `mod_md` module, marked experimental, HTTP-01, TLS-ALPN-01, DNS-01 hook |
| **HTTP cache** | ✅ built in, RFC 9111 subset, in memory, tag purge | ⚠️ plugin or paid Hub, not in the open source core | ✅ built in, disk based, mature | ⚠️ `mod_cache` module, disk or shared memory |
| **Active health checks** | ✅ built in | ✅ built in | ⚠️ passive only in open source, active in NGINX Plus | ⚠️ `mod_proxy_hcheck` module |
| **JWT validation** | ✅ built in, HMAC, RSA, EC, EdDSA | ⚠️ community plugins or paid Hub | ⚠️ NGINX Plus or third party modules | ⚠️ third party modules |
| **Incident ID and AI investigation (MCP)** | ✅ built in | ❌ | ❌ | ❌ |
| **Metrics (Prometheus, OpenTelemetry)** | ❌ | ✅ built in | ⚠️ modules or Plus | ⚠️ modules |
| **Gatekeeping (login page for previews)** | ✅ built in: shared password, TOTP, passkeys | ⚠️ Basic and Digest auth built in, OIDC and JWT only in paid Hub, otherwise forward auth to another service | ⚠️ Basic auth built in, login pages via `auth_request` to another service, TOTP only through third party modules | ⚠️ `mod_auth_form` (HTML form, needs `mod_session` and an account store), TOTP and OIDC through third party modules |
| **Header and status transform** | ✅ built in: set, add, remove, regex replace, status remap | ✅ built in: `Headers` middleware, regex path rewrite, status rewrite in `Errors` | ✅ built in: `add_header`, `proxy_set_header`, `return`, rewrites | ⚠️ `mod_headers` module (set, append, edit, unset) |
| **Maintenance page** | ✅ built in, with an Incident ID, HTML or JSON | ⚠️ `Errors` middleware, needs a separate service to serve the page | ✅ built in: `error_page`, custom page file | ✅ built in: `ErrorDocument`, custom page file |
| **Geo-IP filtering** | ✅ built in: MaxMind database, country allow or block, country header | ⚠️ community plugins only | ⚠️ `ngx_http_geoip_module`, not built by default, legacy database format | ⚠️ third party modules (`mod_maxminddb`) |
| **Rate limiting** | ✅ built in: per IP, global and per path | ✅ built in: `RateLimit` middleware | ✅ built in: `limit_req`, per key | ⚠️ `mod_ratelimit` only limits bandwidth, request rates need third party modules (`mod_evasive`, `mod_qos`) |
| **HTTP/3 (QUIC)** | ❌ | ✅ | ✅ | ⚠️ experimental third party module |
| **Static files** | ✅ built in: directory listing, index file, SPA mode, Range, conditional requests | ❌ not in the core (needs a separate web server) | ✅ built in | ✅ built in |
| **FastCGI, scripting** | ❌ | ❌ | ⚠️ FastCGI built in, scripting through modules (Lua, njs) | ✅ built in (`mod_proxy_fcgi`, CGI, `mod_php` and a huge module ecosystem) |
| **Ecosystem and track record** | new, single project | large community | very large, decades in production | very large, decades in production |

Legend: ✅ built in the core product, ⚠️ available only as a separate module, plugin, extension or paid edition, ❌ not available.

**Choose paasers when** you run a small PaaS or a set of preview environments behind one VM, want HTTPS, canary routing, a login in front of staging and fast incident triage with almost no configuration, and your backends have stable private IPs.

**Choose something else when** you need dynamic discovery (Kubernetes, Docker), wildcard certificates issued automatically, HTTP/3, TCP or UDP proxying, metrics dashboards, backends reached by name or over TLS, FastCGI or scripting, static serving beyond the basics (no custom error pages, rewrites or per-directory rules), or the safety of a project with a long production history.

They also combine well: paasers can sit behind another load balancer (`trusted-proxies`), or in front of an application server, with static assets served by paasers on a separate route.

## Command line

| Command | Purpose |
|---|---|
| `paasers run -c <file>` | run the gateway (default `/etc/paasers/gateway.kdl`, built-in defaults when that file does not exist) |
| `paasers check -c <file>` | validate a configuration |
| `paasers hash-password` | read a password on stdin, print its argon2id hash (8 characters minimum) |
| `paasers hash-api-key` | read an API key on stdin, print its SHA-256 hex digest |
| `paasers gen-totp` | print a TOTP secret (base32) and its `otpauth://` URL |

## Operations

* **Reload**: write the new file atomically (`install -m 0644 new.kdl /etc/paasers/gateway.kdl`) and it is applied within 2 seconds, or `systemctl reload paasers`. An invalid file keeps the previous configuration and is recorded as a `config` incident.
* **Deploy**: `deploy/paasers.service` (dedicated user, `CAP_NET_BIND_SERVICE`, state in `/var/lib/gateway`, secrets in `/etc/paasers/env`).
* **Rollback**: keep the previous binary as `paasers.prev`. The SQLite schema only evolves additively.
* **Logs**: `info` shows 4xx and 5xx accesses, `debug` shows every request. Secrets are never logged.

## Known limitations

* Upstreams are plain HTTP over a private network, addressed by literal IP.
* The cache is in memory (lost on restart), one variant per URL, no coalescing of concurrent misses.
* ACME uses HTTP-01 only, so wildcard hosts need a certificate in `certs-dir` (or `tls self-signed=#true`).
* WebSocket works over HTTP/1.1 only.
* Passkeys pull in OpenSSL (vendored on musl). Build with `--no-default-features` to avoid it.

## Development

```bash
scripts/ci.sh                         # fmt, clippy (two feature sets), file length
cargo test                            # whole suite (also with --no-default-features)
scripts/pebble.sh && PEBBLE_DIR=target/pebble cargo test --test acme -- --ignored   # real ACME
scripts/rss.sh                        # memory budget (32 MB), needs the musl release build
```

Manual checks that cannot be automated: passkeys (Chrome DevTools virtual authenticator), an MCP client (Claude Desktop or Cursor with `inspect_incident <ID>`), Let's Encrypt staging on a machine with public DNS.

## License

MIT OR Apache-2.0.
