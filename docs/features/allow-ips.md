# IP allowlist (`allow-ips`) and named IP sets (`ip-set`)

Restricts a route to a list of client networks. Any other client gets a 403. Lists can be named once with `ip-set` and reused by every route and by `trusted-proxies`.

## Defaults

The feature is inactive without the `allow-ips` node: every client reaches the route. There is no implicit `0.0.0.0/0` (which would also forget IPv6).

| Node | Where | Content |
|---|---|---|
| `allow-ips` | inside a `route`, at most once | CIDRs, bare IPs (v4 or v6) and `ip-set` names, at least one |
| `ip-set "<name>"` | top level, any number, before or after use | CIDRs and bare IPs only, at least one |

* One entry per line as a child named `-`, so each range can carry a `//` comment and be disabled with `/-`. Short lists may use arguments instead: `allow-ips "10.0.0.0/8" "staff"`. Both forms can be mixed.
* An entry is a network when it parses as one, otherwise it is the name of an `ip-set`. An unknown name is a load error with its line and column.
* Set names: letters, digits, `-` and `_`. Sets do not nest.
* Overlapping, adjacent and duplicated ranges are merged at load, host bits are cleared (`10.1.2.3/8` is `10.0.0.0/8`).
* Refusal: 403 through the gateway error page (HTML or JSON, with the Incident ID), `ip_blocked` incident in the flight recorder.
* It is the first check of the route: a refused client spends no rate-limit budget, never reaches the gatekeeper or the backend. ACME challenges and the HTTP to HTTPS redirect are answered before it.
* IPv4 clients seen through an IPv6 socket (`::ffff:192.0.2.1`) match IPv4 ranges.
* Lookup is a binary search over sorted ranges, no allocation per request. Thousands of ranges cost nothing measurable.

## Client address and `trusted-proxies`

The address checked is the one used by the rate limit and GeoIP: the TCP peer, or the right-most untrusted `X-Forwarded-For` address when the peer is in `trusted-proxies`.

The default `trusted-proxies` trusts the private ranges, so any machine of the private network can send a forged `X-Forwarded-For`. When `allow-ips` protects something that matters, narrow `trusted-proxies` to the real front load balancer, or empty it if clients connect directly:

```kdl
gateway {
    trusted-proxies {
        - "10.0.0.2"   // front load balancer
    }
}
```

## Examples

An admin back office reachable from the office and the VPN only:

```kdl
ip-set "staff" {
    - "203.0.113.0/24"     // Paris office
    - "2001:db8:42::/48"   // Paris office, IPv6
    - "198.51.100.7"       // VPN exit
}

route "admin.example.com" {
    upstream "10.0.1.20:8080"
    allow-ips {
        - "staff"
        - "192.0.2.10"         // contractor, until 2026-12
        /- - "192.0.2.0/24"    // disabled for now
    }
}
```

The same set on a preview environment, on top of its gatekeeper:

```kdl
route "preview.example.com" {
    tls
    upstream "10.0.1.30:8080"
    allow-ips "staff"
    gatekeeper {
        psk-env "PREVIEW_PSK"
    }
}
```

Short inline list:

```kdl
route "metrics.example.com" {
    upstream "10.0.1.40:9100"
    allow-ips "10.0.0.0/8" "fd00::/8"
}
```
