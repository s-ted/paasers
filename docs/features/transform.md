# Header and status transforms (`transform`)

Modifies request and response headers and remaps status codes. Bodies are never rewritten, so streaming stays intact.

## Defaults

Built-in security headers are **on by default** on every route: `X-Content-Type-Options: nosniff` (only if the backend did not set it), and removal of `Server` and `X-Powered-By`. `Strict-Transport-Security` is **not** added by default (hard to undo in a browser), see the example below to opt in. Your own operations run after these, so they can override or remove them. `transform off` disables everything, including the built-in headers. An empty `transform` node keeps only the built-ins.

Operations inside `request { }` and `response { }`:

| Operation | Effect |
|---|---|
| `set "<Header>" "<value>"` | replace or create |
| `add "<Header>" "<value>"` | append an extra value |
| `remove "<Header>"` | delete |
| `replace "<Header>" "<regex>" "<replacement>"` | Rust regex, `$1` for groups |
| `status from=<code> to=<code>` | `response` only, codes 100 to 999 |

* Value templates: `{client_ip}`, `{trace_id}`, `{host}`, `{country}`. Other braces stay literal.
* Forbidden headers: `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`.
* Operations run in the order written.

## Examples

Disable everything, built-in headers included:

```kdl
transform off
```

Identify the gateway and propagate the trace id to the backend:

```kdl
transform {
    request {
        set "X-Request-Source" "paasers"
        set "X-Trace-Id" "{trace_id}"
    }
}
```

Opt in to HSTS (only once HTTPS works for good on this host and its subdomains). `nosniff` and the banner removal already happen by default:

```kdl
transform {
    response {
        set "Strict-Transport-Security" "max-age=31536000; includeSubDomains"
        set "X-Content-Type-Options" "nosniff"
        remove "Server"
        remove "X-Powered-By"
    }
}
```

Regex rewrite and status remapping:

```kdl
transform {
    request {
        replace "X-Env" "^staging-(.*)$" "preview-$1"
    }
    response {
        add "Link" "</app.css>; rel=preload; as=style"
        status from=404 to=200
    }
}
```

Pass the country and IP (with [geoip](geoip.md)):

```kdl
transform {
    request {
        set "X-Visitor" "{client_ip} {country}"
    }
}
```
