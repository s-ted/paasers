# MCP server and incident investigation (`mcp-server`)

A built-in MCP server (Streamable HTTP) lets an AI agent investigate from an **Incident ID**, without access to logs or machines.

## Defaults

Disabled without the `mcp-server` block.

| Option | Default |
|---|---|
| `listen` | `127.0.0.1:9090` |
| `token "<s>"` or `token-env "<VAR>"` | none, 16 characters minimum, mutually exclusive |

* Without a token the listener must be on loopback, otherwise the configuration is rejected.
* Authentication: `Authorization: Bearer <token>`. `GET /healthz` needs no token.
* Changing this block requires a restart.

## Tools

| Tool | Purpose |
|---|---|
| `get_route_status` | hosts, upstreams (health, weight, last error), cache, certificates. No argument lists every route. |
| `query_flight_recorder` | latest failures (4xx, 5xx, timeouts) and events (health, acme, config) |
| `inspect_incident` | details of an incident from its ID (32 hex, dashes tolerated), with a diagnostic hint |
| `purge_cache` | purge by `tags`, `host`, `path_prefix` or `all` |

Incident kinds: `upstream_connect`, `upstream_timeout`, `no_healthy_upstream`, `upstream_error`, `rate_limited`, `auth`, `geo_blocked`, `tls_fallback`, `payload_too_large`, `config`.

The flight recorder is an in-memory ring buffer (`gateway { flight-recorder capacity=500 }`).

## Examples

Local only:

```kdl
mcp-server { }
```

Token read from the environment, reachable from a private network:

```kdl
mcp-server {
    listen "10.0.0.5:9090"
    token-env "MCP_TOKEN"
}
```

Client configuration (Claude Desktop, Cursor):

```json
{ "mcpServers": { "paasers": { "url": "http://127.0.0.1:9090/mcp",
    "headers": { "Authorization": "Bearer <your token>" } } } }
```

Remote access without exposing the port:

```bash
ssh -L 9090:127.0.0.1:9090 gateway-vm
```

Typical scenario: a user reports Incident ID `4bf92f35...`. Ask the agent to run `inspect_incident 4bf92f35...`, then `get_route_status` to confirm backend state, then `purge_cache` if needed.
