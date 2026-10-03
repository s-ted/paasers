# Gatekeeper, protected access for previews (`gatekeeper`)

A login page in front of the whole route. Ideal for preview environments: a shared password (PSK), optional TOTP, and passkeys.

## Defaults

| Option | Default | Constraint |
|---|---|---|
| `psk "<hash>"` or `psk-env "<VAR>"` | **exactly one required** | argon2id hash from `paasers hash-password` |
| `totp-secret` or `totp-secret-env` | none (no second factor) | base32, 16 bytes minimum, from `paasers gen-totp` |
| `title` | `Protected access` | |
| `session-duration` | `14d` | between 1m and 90d |
| `rate-limit attempts= window=` | `5` attempts, `15m` | `attempts` at least 1 |
| `passkey` | `#false` | needs a `tls` route and the `passkey` cargo feature |
| `cookie-name` | `__Host-gate` (TLS) or `__gate` | `[A-Za-z0-9_-]+` |

* The session cookie is HMAC signed, `HttpOnly`, `SameSite=Lax`, and `Secure` with TLS.
* Changing the PSK or the TOTP secret invalidates every session.
* Pages live under `/__gate/` (login, logout, passkey). Cross-origin POST requests are refused (CSRF).
* After a first PSK login, the visitor can register a passkey.
* The gatekeeper runs before API key and JWT.

## Examples

Minimal shared password:

```bash
echo -n 'my-password' | paasers hash-password
```

```kdl
gatekeeper {
    psk "$argon2id$v=19$m=19456,t=2,p=1$ftC9LdPXCcZ6MiQpvWUwXA$haZvTFqngv2fUrBLJTBmAw2Ltxdy9HonzbKTkg4bXhI"
}
```

Secret kept out of the configuration file (recommended), set in `/etc/paasers/env`:

```kdl
gatekeeper {
    title "Client preview"
    psk-env "PREVIEW_PSK_HASH"
}
```

PSK plus TOTP (`paasers gen-totp` prints the secret and the `otpauth://` URL):

```kdl
gatekeeper {
    psk-env "PREVIEW_PSK_HASH"
    totp-secret-env "PREVIEW_TOTP"
    session-duration "8h"
}
```

Passkeys, with stricter brute force protection:

```kdl
route "dev.example.com" {
    tls email="ops@example.com"
    upstream "10.0.1.11:8080"
    gatekeeper {
        psk-env "PREVIEW_PSK_HASH"
        passkey #true
        rate-limit attempts=3 window="30m"
        cookie-name "preview"
    }
}
```
