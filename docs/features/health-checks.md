# Health checks (`health-check`)

Active probes per backend. An unhealthy backend leaves the rotation and comes back when it answers again. State survives reloads. Connection failures on real traffic also count (passive probe).

## Defaults

Active with nothing written.

| Property | Default | Constraint |
|---|---|---|
| `mode` | `http` | `http` or `tcp` |
| `path` | `/` | starts with `/` |
| `interval` | 5s | at least 1s |
| `timeout` | 2s | strictly lower than `interval` |
| `unhealthy-after` | 2 | at least 1 consecutive failures |
| `healthy-after` | 2 | at least 1 consecutive successes |
| `enabled` | `#true` | |

In `http` mode any status below 500 is healthy (a 401 or 404 counts as alive). In `tcp` mode the connection must open.

## Examples

Dedicated endpoint, faster detection:

```kdl
route "api.example.com" {
    upstream "10.0.0.10:8080"
    health-check path="/healthz" interval="2s" timeout="500ms" unhealthy-after=1
}
```

Non-HTTP backend or no health endpoint:

```kdl
route "app.example.com" {
    upstream "10.0.0.10:5432"
    health-check mode="tcp"
}
```

Disable probes (the backend is always considered healthy):

```kdl
route "app.example.com" {
    upstream "10.0.0.10:8080"
    health-check enabled=#false
}
```

When no backend is healthy, the request fails with the `no_healthy_upstream` incident and the [fallback](fallback.md) page is shown.
