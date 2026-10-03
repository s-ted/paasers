# JWT validation (`jwt-validation`)

Requires a valid token and passes the identity to the backend as trusted headers.

## Defaults

| Option | Default |
|---|---|
| key | **required**: exactly one of `secret-env "<VAR>"` (HMAC) or `public-key-file "<pem>"` (RSA, EC or Ed25519) |
| `algorithms` | `HS256` for HMAC, `RS256` for RSA, `ES256` for EC, `EdDSA` for Ed |
| `issuer` | not checked |
| `audience` | not checked |
| `leeway` | `60s` |
| `inject-headers` | `#true` |
| `cookie` | none (only `Authorization: Bearer`) |

* `exp` is required and checked.
* Listed algorithms must match the key type.
* The token is read from `Authorization: Bearer ...`, otherwise from the cookie named by `cookie`.
* Responses: 401 `token_required` or `invalid_token` with `WWW-Authenticate`.
* Incoming `X-User-Id`, `X-User-Email`, `X-User-Roles` and `X-Jwt-Claims` headers are **always** removed, even when injection is off.
* Injection: `X-User-Id` (claim `sub`), `X-User-Email` (claim `email`), `X-User-Roles` (claim `roles`, an array joined with commas), `X-Jwt-Claims` (all claims as base64url JSON, omitted above 8 KiB).
* A valid [API key](api-keys.md) skips the JWT check.

## Examples

Shared secret HS256:

```kdl
jwt-validation {
    secret-env "JWT_SECRET_KEY"
}
```

Identity provider with an RSA public key, issuer and audience checked:

```kdl
jwt-validation {
    public-key-file "/etc/paasers/idp.pem"
    issuer "https://auth.example.com"
    audience "api.example.com"
    algorithms "RS256"
}
```

EdDSA, token also read from a cookie (web apps):

```kdl
jwt-validation {
    public-key-file "/etc/paasers/ed25519.pub.pem"
    cookie "session_token"
    leeway "10s"
}
```

Validate without passing anything to the backend:

```kdl
jwt-validation {
    secret-env "JWT_SECRET_KEY"
    inject-headers #false
}
```
