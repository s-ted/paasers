# Maintenance page and Incident ID (`fallback`)

When the backend fails, the user sees a clean page with an **Incident ID** (the 32 hex digit trace id). Support gives it to an AI agent or a human, who finds the cause through the [MCP server](mcp.md).

## Defaults

Active with nothing written. `fallback off` disables the page: proxy failures then return a plain 502 and backend responses pass through untouched.

| Property | Default |
|---|---|
| `status` | 503 (500 to 599) |
| `show-incident-id` | `#true` |
| `title` | `Service temporarily unavailable` |
| `message` | `We are working on restoring the service. Please try again in a few moments.` |
| `on` | `"502,503,504"` (backend statuses that trigger the page) |

* Triggered by proxy failures (connection refused, timeout, no healthy backend) and by empty responses with a status listed in `on`. A 5xx response with a real body from the backend is left untouched.
* Negotiated format: HTML for a browser, JSON with `Accept: application/json`.
* Responses always carry `traceparent` and `X-Request-Id`.

## Examples

Custom text:

```kdl
route "app.example.com" {
    upstream "10.0.0.10:8080"
    fallback title="Maintenance in progress" message="We will be back in a few minutes."
}
```

Return 502 and only apply it to backend 503 responses:

```kdl
fallback status=502 on="503"
```

Hide the Incident ID (public site without a support desk):

```kdl
fallback show-incident-id=#false
```

Also catch 500 responses:

```kdl
fallback on="500,502,503,504"
```

JSON answer for an API (`Accept: application/json`):

```json
{ "error": { "status": 503, "title": "Service temporarily unavailable",
             "message": "We are working on restoring the service. Please try again in a few moments.",
             "timestamp": "2026-10-03T08:30:52Z",
             "incident_id": "4bf92f3577b34da6a3ce929d0e0e4736" } }
```
