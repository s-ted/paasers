# Rate limiting (`rate-limit`)

Per client IP limiting (token bucket). Several rules are possible: one global rule and rules per path prefix.

## Defaults

A generous global rule is **on by default** on every route: `rps=100 burst=200` per client IP. It stops abuse, not normal traffic. A `rate-limit` node without `path` replaces it, a rule with a `path` is added on top of it, and `rate-limit off` (alone) removes limiting. Behind a load balancer outside the private ranges, set `trusted-proxies`, otherwise all clients share one IP.

| Property | Default |
|---|---|
| `rps` | **required**, at least 1 |
| `burst` | equal to `rps`, at least 1 |
| `path` | none (global rule), must start with `/` |

* At most one rule without `path`, and no two rules with the same `path`.
* For a request, the rule with the longest matching prefix applies, then the global rule. Both must pass.
* When exceeded: 429 with `Retry-After` in seconds and the `rate_limited` incident.
* Counters survive a reload when the rule is unchanged.
* Behind a proxy, set `trusted-proxies`, otherwise all requests appear to come from the same peer.

## Examples

Disable:

```kdl
rate-limit off
```

General limit:

```kdl
rate-limit rps=50 burst=100
```

Public API with a login protected against brute force:

```kdl
rate-limit rps=20 burst=40
rate-limit path="/api/login" rps=1 burst=5
```

Expensive endpoint, tightly restricted:

```kdl
rate-limit rps=100
rate-limit path="/export" rps=1 burst=2
```
