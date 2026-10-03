# HTTP cache (`cache`)

Shared in-memory cache implementing a subset of RFC 9111, placed in front of the proxy. It serves fresh responses, revalidates in the background, and can serve stale content when the backend is down.

## Defaults

The cache is **enabled by default** on proxied routes (not on static routes), in "the backend decides" mode: `default-ttl` is `0s`, so only responses carrying explicit freshness (`Cache-Control: max-age`, `s-maxage`, `Expires`) are stored. Memory is bounded by `max-size`. Write `cache off` to disable it on a route. A `cache` node sets the properties below:

| Property | Default | Constraint |
|---|---|---|
| `max-size` | `64MiB` | maximum cache memory |
| `max-object-size` | `8MiB` | lower than or equal to `max-size` |
| `default-ttl` | `0s` | lifetime used when the backend gives none. 0 means do not store |
| `stale-while-revalidate` | `0s` | serve stale while revalidating |
| `stale-if-error` | `0s` | serve stale if the backend fails |

Storage rules:

* `GET` only, statuses 200, 203, 204, 300, 301, 308, 404, 410.
* Freshness: `s-maxage`, else `max-age`, else `Expires`, else `default-ttl`.
* Never stored: `no-store`, `no-cache`, `private`, `Set-Cookie`, `Vary: *`, `Content-Range`, an object larger than `max-object-size`, a request with `Range`.
* Request with `Authorization` or `Cookie`: stored only if the response is `public` or has `s-maxage`.
* `Vary` is honored. One variant per URL. `must-revalidate` disables stale serving.
* `stale-while-revalidate` and `stale-if-error` from the backend override the configuration.
* The cache is lost on restart and concurrent requests for the same miss are not coalesced.
* Every response carries `X-Cache: HIT`, `MISS` or `STALE`.

## Examples

Disable on one route:

```kdl
cache off
```

Minimal cache, the backend drives it with `Cache-Control`:

```kdl
route "www.example.com" {
    upstream "10.0.0.10:8080"
    cache
}
```

Static site whose backend sends no cache headers (5 minutes):

```kdl
cache max-size="256MB" default-ttl="5m"
```

Maximum resilience, the site stays visible when the backend is down:

```kdl
cache max-size="512MiB" default-ttl="1m" stale-while-revalidate="30s" stale-if-error="1h"
```

Large assets (short videos, bundles):

```kdl
cache max-size="2GiB" max-object-size="64MiB"
```

Tag based invalidation: the backend answers with `Surrogate-Key: product-42 catalog` (the header is removed before reaching the client), then the MCP tool `purge_cache` accepts `tags`, `host`, `path_prefix` or `all`. See [mcp.md](mcp.md).
