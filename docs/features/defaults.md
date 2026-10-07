# Features on by default

What paasers does with an empty configuration, with the default values and how to turn each one off. Everything else (TLS, GeoIP, IP allowlist, gatekeeper, JWT, API keys, `static` with a directory) is off until you write its node.

Every feature below can be disabled, and `cargo test` checks it (`every_default_feature_can_be_disabled`).

## Per route

| Feature | Default values | Turn off | Page |
|---|---|---|---|
| Compression | zstd, brotli and gzip on, `min-size=1024` | `compression off` | [compression](compression.md) |
| HTTP cache (proxied routes only) | `max-size=64MiB`, `max-object-size=8MiB`, `default-ttl=0s` (only what the backend allows with `Cache-Control` or `Expires`), no stale serving | `cache off` | [cache](cache.md) |
| Rate limit | `rps=100 burst=200` per client IP, global rule | `rate-limit off` | [rate-limit](rate-limit.md) |
| Security headers | `X-Content-Type-Options: nosniff` (if the backend sets none), removes `Server` and `X-Powered-By`. No HSTS. | `transform off` | [transform](transform.md) |
| Maintenance page | status `503`, `show-incident-id=#true`, on backend `502,503,504` | `fallback off` | [fallback](fallback.md) |
| Health checks | `mode=http`, `path=/`, `interval=5s`, `timeout=2s`, `unhealthy-after=2`, `healthy-after=2` | `health-check enabled=#false` | [health-checks](health-checks.md) |
| Retry on another backend | one retry, only `GET`, `HEAD`, `OPTIONS`, `TRACE` without body, on connection failure | `retry off` | [routing](routing.md) |
| Request timeout | `60s` to receive the response headers | `timeouts request=` (range 100ms to 1h, no "off") | [routing](routing.md) |
| HTTP to HTTPS redirect | on when the route has `tls` | `redirect-https #false` | [tls](tls.md) |
| Directory listing | on for `static` routes and for a route without `upstream` | `static "<dir>" listing=#false` | [static](static.md) |
| Static file service | a route with neither `upstream` nor `static` serves the current directory | write an `upstream` | [static](static.md) |

## Global

| Feature | Default values | Turn off | Page |
|---|---|---|---|
| MCP server | `127.0.0.1:9090`, no token, local only. A taken port is a warning, not an error. | `mcp-server off` | [mcp](mcp.md) |
| Flight recorder | in-memory ring of 500 incidents | `gateway { flight-recorder off }` | [gateway](gateway.md) |
| Trusted proxies | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` (no loopback) | `gateway { trusted-proxies }` with no argument | [gateway](gateway.md) |
| Connection limits | `max-connections=10000`, `max-body=100MiB`, `header-read-timeout=30s`, `max-headers-size=64KiB` | raise the values in `gateway { limits }` | [gateway](gateway.md) |
| Listeners | HTTP `:80` and HTTPS `:443` | `listen "<http>"` for HTTP only | [gateway](gateway.md) |
| Graceful shutdown | `shutdown-grace=30s` | `shutdown-grace "1s"` | [gateway](gateway.md) |

Protections that cannot be switched off, on purpose: removal of spoofable inbound headers (`X-Forwarded-*`, `X-Request-Id`, `X-User-*`, `X-Api-Key-Name`, `X-Country-Code`), the `Incident ID` trace headers, WebSocket support and the `Surrogate-Key` header stripping.

## Overriding a default

* A node replaces the default of the same feature: `rate-limit rps=5` replaces the global `100/200` rule. A `rate-limit path="/login" rps=1` is added on top of it.
* `transform { ... }` runs after the security headers, so it can override or remove them. `transform off` removes the security headers too.
* `trusted-proxies "<cidr>"` replaces the default list. Add `127.0.0.1` yourself if a local process fronts the gateway.

## Trying it

```kdl
// Everything optional is off, only what you ask for stays
mcp-server off
gateway {
    trusted-proxies
    flight-recorder off
}
route "app.example.com" {
    upstream "10.0.0.10:8080"
    cache off
    compression off
    rate-limit off
    transform off
    fallback off
    retry off
    health-check enabled=#false
}
```
