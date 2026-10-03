# Compression (`compression`)

Response compression with zstd, brotli and gzip, negotiated through `Accept-Encoding`. It runs above the cache, so the cache stores the uncompressed version.

## Defaults

**Enabled by default** on every route.

| Property | Default |
|---|---|
| `zstd` | `#true` |
| `brotli` | `#true` |
| `gzip` | `#true` |
| `min-size` | `1024` bytes (maximum 16MiB) |

Never compressed: 1xx, 204, 304, 206 and already compressed content types according to the tower-http predicate. At least one algorithm must stay enabled.

## Examples

Nothing to write for the default behavior.

Disable (the backend already compresses):

```kdl
compression off
```

gzip only (old clients, limited CPU):

```kdl
compression zstd=#false brotli=#false
```

Avoid brotli, which is CPU heavy:

```kdl
compression brotli=#false
```

Also compress small API responses:

```kdl
compression min-size="256"
```
