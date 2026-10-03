# Routing and load balancing (`route`, `upstream`)

`route "<host>"...` maps one or more host names to backends. The first host is the route id. A host belongs to a single route.

## Defaults

| Option | Default |
|---|---|
| number of `upstream` nodes | any. A route without `upstream` serves a directory, see [`static`](static.md) (the current directory by default) |
| `weight` | 1 (range 0 to 1000, 0 drains) |
| `timeouts request=` | 60s (100ms to 1h), time allowed to receive the response headers |
| `redirect-https` | on when the route has `tls`, off otherwise |
| algorithm | weighted random pick among healthy backends |

Rules:

* Hosts are normalized (lowercase, trailing dot removed). `*.example.com` matches exactly one label.
* Upstreams are literal `ip:port` addresses, plain HTTP. A non-private IP logs a warning.
* No duplicate upstream, and the sum of weights must be greater than 0.
* On a connection failure, a `GET`/`HEAD`/`OPTIONS`/`TRACE` request without a body is retried once on another backend. Other methods are never retried.
* `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto` and `X-Forwarded-Host` are set by the gateway.
* WebSocket is supported (HTTP/1.1).

## Examples

A single backend:

```kdl
route "app.example.com" {
    upstream "10.0.0.10:8080"
}
```

Several names for the same app:

```kdl
route "example.com" "www.example.com" {
    upstream "10.0.0.10:8080"
}
```

Wildcard (one label, so `a.example.com` matches but `a.b.example.com` does not):

```kdl
route "*.preview.example.com" {
    tls self-signed=#true
    upstream "10.0.0.30:8080"
}
```

90/10 canary:

```kdl
route "app.example.com" {
    upstream "10.0.1.10:8080" weight=90
    upstream "10.0.1.20:8080" weight=10
}
```

Drain a backend before maintenance (it receives no new requests):

```kdl
route "app.example.com" {
    upstream "10.0.1.10:8080"
    upstream "10.0.1.20:8080" weight=0
}
```

Slow backend (exports, reports):

```kdl
route "reports.example.com" {
    timeouts request="5m"
    upstream "10.0.2.10:8080"
}
```

Layer order for every request: GeoIP, rate limit, gatekeeper, API key, JWT, transform, compression, cache, fallback, proxy.
