# API keys (`api-keys`)

Machine to machine authentication. Only SHA-256 digests live in the configuration, never the keys. Comparison walks the whole list in constant time.

## Defaults

| Option | Default |
|---|---|
| `header` | `X-Api-Key` |
| `key "<sha256>" name="<name>"` | at least one, `name` required and unique, digest of 64 hex characters |

* Valid key: the key header is removed, `X-Api-Key-Name: <name>` is added for the backend, and the [JWT](jwt.md) check is skipped.
* Invalid key: 401 `invalid_api_key`.
* Missing key and no `jwt-validation`: 401 `api_key_required`. With `jwt-validation`, the request continues to the JWT check.
* An incoming `X-Api-Key-Name` is always removed.

## Examples

Generate the digest:

```bash
echo -n 'my-long-secret-key' | paasers hash-api-key
```

API reserved to keys:

```kdl
api-keys {
    key "47bd0e2f856fe258ebba4d00930ab811d0c004dafae068c9d72511ca3512cca6" name="ci"
    key "9c1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8" name="partner-acme"
}
```

Custom header:

```kdl
api-keys header="Authorization-Key" {
    key "47bd0e2f856fe258ebba4d00930ab811d0c004dafae068c9d72511ca3512cca6" name="ci"
}
```

Users through JWT, automation through keys (both on the same route):

```kdl
jwt-validation { secret-env "JWT_SECRET_KEY" }
api-keys {
    key "47bd0e2f856fe258ebba4d00930ab811d0c004dafae068c9d72511ca3512cca6" name="ci"
}
```
