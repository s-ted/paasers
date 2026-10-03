# TLS and certificates (`tls`, `certs-dir`)

TLS termination with SNI selection, automatic Let's Encrypt certificates (ACME HTTP-01), local certificates or self-signed ones. Port 80 must be reachable for ACME.

## Defaults

* Without a `tls` node the route is served over HTTP and there is no redirect.
* With `tls` (**auto** mode), preference order is: valid local certificate from `certs-dir`, then valid ACME certificate, then expired local certificate (only when ACME is not possible). If nothing is usable, a temporary self-signed certificate is served until issuance completes.
* ACME issuance starts when no certificate stays valid for 30 more days. After a failure the retry delay is 60s, 120s, ... capped at 24h.
* The email comes from `tls email=`, otherwise from the `default-email` of the `gateway` block.
* ACME is possible only with an email and without a wildcard host.
* A `tls` route requires an HTTPS listener (second argument of `listen`).
* HTTP to HTTPS redirect is on by default (`redirect-https #false` turns it off).
* ACME directory: `production` (global `acme-directory`), or Let's Encrypt staging for one route with `tls { staging }`.
* ACME keys and certificates are stored in `storage-path` (SQLite).

## Examples

Common case, a Let's Encrypt certificate:

```kdl
route "app.example.com" {
    tls email="ops@example.com"
    upstream "10.0.0.10:8080"
}
```

Shared global email:

```kdl
gateway { default-email "ops@example.com" }
route "a.example.com" {
    tls
    upstream "10.0.0.10:8080"
}
route "b.example.com" {
    tls
    upstream "10.0.0.11:8080"
}
```

Trying Let's Encrypt staging on a single route:

```kdl
route "test.example.com" {
    tls email="ops@example.com" {
        staging
    }
    upstream "10.0.0.12:8080"
}
```

Certificates you provide (wildcard, internal CA). Every PEM file in the directory is scanned, paired by public key and chosen by SAN:

```kdl
gateway {
    certs-dir "/etc/paasers/certs"
}
route "*.example.com" {
    tls
    upstream "10.0.0.20:8080"
}
```

Without an email and without a local certificate for a host, `paasers check` rejects the configuration. When a local certificate is the only source, `check` prints its expiry date so you remember to renew it.

In-memory self-signed (dev, private network, new on every restart, wildcards allowed):

```kdl
route "dev.internal" {
    tls self-signed=#true
    upstream "10.0.0.30:8080"
}
```

Default certificate for clients without SNI:

```kdl
gateway { default-cert "app.example.com" }
route "app.example.com" {
    tls email="ops@example.com"
    upstream "10.0.0.10:8080"
}
```

`default-cert` must name a host of a route that has `tls`.

HTTPS without redirect (legacy HTTP clients):

```kdl
route "app.example.com" {
    tls email="ops@example.com"
    redirect-https #false
    upstream "10.0.0.10:8080"
}
```

Private ACME CA (for example Pebble, tests):

```kdl
gateway {
    acme-directory "https://acme.internal/dir"
    acme-ca-root "/etc/paasers/acme-root.pem"
}
```
