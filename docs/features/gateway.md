# Global settings (`gateway`)

A single optional block that configures the whole process. Every child node is a singleton.

## Defaults

| Node | Default |
|---|---|
| `listen "<http>" ["<https>"]` | `":80" ":443"` (`":80"` is dual-stack `[::]:80`). One argument means HTTP only. |
| `storage-path` | `/var/lib/gateway/certs.db` |
| `acme-directory` | `production` (`staging` or an `https://` URL) |
| `acme-ca-root` | none (private ACME CA, tests) |
| `default-email` | none |
| `certs-dir` | none |
| `trusted-proxies` | private ranges: `10.0.0.0/8` `172.16.0.0/12` `192.168.0.0/16` `fc00::/7` (loopback excluded). Write `trusted-proxies` with no argument to trust nobody. Same list syntax as [`allow-ips`](allow-ips.md): arguments or one `- "<entry>"` per line, `ip-set` names accepted. |
| `flight-recorder capacity=` | 500 (1 to 100000), `flight-recorder off` keeps nothing |
| `log format= level=` | `text`, `info` (`RUST_LOG` wins) |
| `limits` | `max-connections=10000`, `max-body=100MiB`, `header-read-timeout=30s`, `max-headers-size=64KiB` |
| `worker-threads` | `min(cpus, 4)` |
| `default-cert` | none (served when the client sends no SNI) |
| `shutdown-grace` | 30s |

`listen`, `storage-path`, `mcp-server`, `worker-threads` and `log` need a restart. A reload that changes them keeps the old values and logs a warning.

## Examples

Full defaults (same as writing nothing):

```kdl
gateway {
    listen ":80" ":443"
}
```

HTTP only, behind another TLS terminator:

```kdl
gateway {
    listen "0.0.0.0:8080"
}
```

Behind a cloud load balancer, to recover the real client IP (used by `allow-ips`, GeoIP, rate limit and logs):

```kdl
gateway {
    trusted-proxies "10.0.0.0/8" "172.16.0.0/12"
}
```

`X-Forwarded-For` is read only when the TCP peer is in this list. The right-most address that is not trusted is then used.

Longer lists, one commented entry per line, possibly sharing a named [`ip-set`](allow-ips.md):

```kdl
ip-set "lb" {
    - "10.0.0.2"   // load balancer A
    - "10.0.0.3"   // load balancer B
}

gateway {
    trusted-proxies {
        - "lb"
        - "127.0.0.1"  // local stunnel
    }
}
```

Small machine, JSON logs for a collector:

```kdl
gateway {
    worker-threads 2
    log format="json" level="info,access=debug"
    limits max-connections=2000 max-body="20MiB"
    flight-recorder capacity=2000
}
```

Testing against Let's Encrypt staging:

```kdl
gateway {
    acme-directory "staging"
    default-email "ops@example.com"
}
```

Accepted units: durations `500ms`, `30s`, `15m`, `14d`. Sizes `64KiB`, `256MB` (decimal) or `256MiB` (binary).
