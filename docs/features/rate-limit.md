# Rate limiting (`rate-limit`)

Per client IP limiting (token bucket). Several rules are possible: one global rule and rules per path prefix.

## Defaults

Inactive without a `rate-limit` node.

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
