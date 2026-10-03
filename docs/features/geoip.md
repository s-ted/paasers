# Geographic filtering (`geoip`)

Resolves the country of the client IP with a MaxMind database (`.mmdb`, memory mapped and reloaded when the file changes). Blocks or allows by country and passes the country to the backend.

## Defaults

The feature is inactive without the `geoip` node.

| Property | Default |
|---|---|
| `database` | **required**, readable file, checked by `paasers check` |
| `block-countries` | none |
| `allow-countries` | none |
| `inject-header` | `#true` (`X-Country-Code` header) |

* `block-countries` and `allow-countries` are mutually exclusive.
* ISO 3166-1 alpha-2 codes, comma separated, case insensitive (`"cn, ru"`).
* An IP with no result (private network, incomplete database) gets country `XX`. It is never matched by a block list and always refused by an allow list.
* Refusal: 403 with the `geo_blocked` incident.
* An incoming `X-Country-Code` is always removed. The country is also available in [transform](transform.md) as `{country}`.
* The IP comes from the TCP peer, or from `X-Forwarded-For` when the peer is in `trusted-proxies`.

## Examples

Block two countries:

```kdl
geoip database="/var/lib/geoip/GeoLite2-Country.mmdb" block-countries="CN,RU"
```

Restrict to French speaking countries:

```kdl
geoip database="/var/lib/geoip/GeoLite2-Country.mmdb" allow-countries="FR,BE,CH,LU,CA"
```

Only inform the backend, no filtering:

```kdl
geoip database="/var/lib/geoip/GeoLite2-Country.mmdb"
```

Filter without exposing the header:

```kdl
geoip database="/var/lib/geoip/GeoLite2-Country.mmdb" block-countries="KP" inject-header=#false
```
