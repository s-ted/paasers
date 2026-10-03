# Static files (`static`)

A route can serve a directory instead of proxying to an upstream, in the spirit of miniserve. No scripting, no FastCGI, no upload. The static service replaces the reverse proxy at the bottom of the route stack, so every other feature still applies: GeoIP, rate limit, gatekeeper, API keys, JWT, transform and compression.

## Default configuration: serve the current directory

If there is nothing to proxy to, paasers serves the **current working directory**:

* No configuration at all (`paasers run` without `-c` when `/etc/paasers/gateway.kdl` does not exist, or a file without any `route`): an implicit route answers **every host** with the current directory. No TLS, plain HTTP on `:80` unless a `gateway { listen }` block says otherwise. The other `gateway` defaults apply too, notably the database in `/var/lib/gateway`: as a normal user, set `listen` and `storage-path` (see the README).
* A `route` with neither `upstream` nor `static`: it serves the current directory for its hosts, with all `static` defaults below.
* Once at least one route is configured, the implicit route disappears and unknown hosts answer 404.

The directory is the working directory of the process (for a systemd unit, set `WorkingDirectory=`). Keep the SQLite file (`storage-path`) outside of it: it is served like any other file otherwise.

## Defaults

```kdl
route "files.example.com" {
    tls email="ops@example.com"
    static "/srv/www"
}
```

| Property | Default | Meaning |
|---|---|---|
| `index` | `"index.html"` | File served for a directory. `index=""` disables index files. Must be a plain file name. |
| `listing` | `#true` | HTML listing of a directory that has no index file. With `#false` such a directory answers 404. |
| `spa` | `#false` | Single page application mode, see below. |
| `hidden` | `#false` | Serve and list entries whose name starts with `.`. |
| `follow-symlinks` | `#false` | Follow symbolic links. |
| `cache-control` | none | Value of the `Cache-Control` header on file responses. |

**Directory listing is on by default.** Anyone who can reach the route can see the file names of every directory without an index file. Use `listing=#false` for anything you do not want to be browsable, or put a `gatekeeper` in front.

## Behavior

* Only `GET` and `HEAD`. Anything else answers 405.
* `Content-Type` from the file extension, `Range` requests (206), `If-Modified-Since`, `If-None-Match`, `ETag` and `Last-Modified` are handled for you.
* A directory requested without a trailing slash is redirected (301) to the same path with a slash, query string kept.
* A directory with an index file serves it, otherwise the listing (directories first, then files, case-insensitive). Listings show at most 10 000 entries.
* Responses carry `X-Content-Type-Options: nosniff`. Listings also carry a restrictive `Content-Security-Policy`.
* Compression is on by default like any route. Add `compression off` to disable it.
* Memory: nothing is cached by the gateway. Each transfer uses one small read buffer and the operating system page cache does the rest.

## Safety

* `..` in any form (`%2e%2e`, encoded slashes) is refused with 404. NUL bytes, backslashes and invalid UTF-8 give 400.
* Names starting with `.` (`.env`, `.git`) are not served, not listed.
* Symbolic links are not followed and not listed. Enable `follow-symlinks=#true` only for content you control, since a link can then point anywhere on the machine.
* The directory is checked at configuration load (`not a directory` is an error) and the root itself may be a symlink.
* A file replaced between the check and the read is not guarded against (read only server, operator controlled root).

## Single page application mode

With `spa=#true`, a path that matches nothing and whose last segment has no `.` serves the root index file with status 200, so client side routers work on reload. Missing assets such as `/missing.js` still answer 404.

## Examples

Public site with a custom cache header:

```kdl
route "www.example.com" {
    tls email="ops@example.com"
    static "/srv/site" cache-control="public, max-age=3600"
}
```

Single page application:

```kdl
route "app.example.com" {
    tls email="ops@example.com"
    static "/srv/app/dist" spa=#true
}
```

Private download area, listing allowed behind a shared password:

```kdl
route "dl.example.com" {
    tls email="ops@example.com"
    static "/srv/downloads"
    gatekeeper { psk-env "DL_PSK_HASH" }
    rate-limit rps=20 burst=40
}
```

Not browsable, direct links only:

```kdl
route "assets.example.com" {
    static "/srv/assets" listing=#false
}
```

## Rules

* `static` and `upstream` are mutually exclusive. A route with neither serves the current directory.
* `health-check`, `timeouts`, `cache`, `fallback` and `retry` do not apply to a static route and are rejected.
* `static` takes exactly one argument and cannot be repeated.
