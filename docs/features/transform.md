# Header and status transforms (`transform`)

Modifies request and response headers and remaps status codes. Bodies are never rewritten, so streaming stays intact.

## Defaults

No transform without the node. An empty `transform` node is valid.

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

Identify the gateway and propagate the trace id to the backend:

```kdl
transform {
    request {
        set "X-Request-Source" "paasers"
        set "X-Trace-Id" "{trace_id}"
    }
}
```

Security headers on every response, hide the server banner:

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
