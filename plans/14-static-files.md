# P14: static files (`static`)

> Status: **implemented**. Same rule as every phase: `cargo check`, `cargo test` and `cargo clippy --all-targets -- -D warnings`
> green before the commit. Order of work: this plan, then tests, then implementation, then docs and example.
> HTTP/3 was evaluated and **dropped** (memory and complexity, see the discussion that led to this plan).

## 1. Goals and decisions

| # | Decision |
|---|---|
| S1 | A route serves a directory instead of proxying: `static "<dir>"` replaces `upstream`. miniserve-like: no scripting, no FastCGI, no uploads. |
| S2 | The static service is the **terminal service** of the route stack, in place of `ProxyService`. Every other layer (GeoIP, rate limit, gatekeeper, API key, JWT, transform, compression) applies unchanged. |
| S3 | `static` and `upstream` are mutually exclusive. A route has exactly one of them. `health-check`, `timeouts`, `cache` and `fallback` are meaningless for a static route and are **rejected** (strict config, like the rest of the grammar). |
| S4 | **Directory listing is on by default** (`listing=#true`). A directory with an index file serves the index instead. |
| S5 | File serving (MIME type, `Range`, `If-Modified-Since`, `If-None-Match`, `HEAD`) is delegated to `tower-http` `ServeFile` (feature `fs`). Path resolution, dotfile and symlink policy and the listing are written here, because `ServeDir` does none of them. |
| S6 | No new memory at rest. Per request: one read buffer (tower-http stream). No application cache, the OS page cache does the work. Directory listings are capped at 10 000 entries. |
| S7 | Safe by default: no path traversal, dotfiles hidden, symlinks not followed, GET and HEAD only, `X-Content-Type-Options: nosniff`, HTML escaping in listings. |
| S8 | Data model (as built): `RouteCfg.upstreams` stays and is **empty** for static routes, `RouteCfg.static_files: Option<StaticCfg>` is added. This keeps the balancer, health registry, cache registry and MCP untouched (an empty balancer is valid). |

## 2. Grammar

```text
route <host>+ {
    static "<directory>" [index="<file>"] [listing=#true|#false] [spa=#true|#false]
                         [hidden=#true|#false] [follow-symlinks=#true|#false] [cache-control="<value>"]
}
```

| Property | Default | Meaning |
|---|---|---|
| `index` | `"index.html"` | File served for a directory. `index=""` disables index files. A plain file name, no `/`. |
| `listing` | `#true` | HTML listing for a directory without index file. When `#false` such a directory answers 404. |
| `spa` | `#false` | Single page application mode: an unknown path whose last segment has no `.` serves the root index file with 200. |
| `hidden` | `#false` | Serve and list entries whose name starts with `.`. |
| `follow-symlinks` | `#false` | Follow symbolic links. When `#false`, any symlink on the path answers 404 and symlinks are not listed. |
| `cache-control` | none | Value of `Cache-Control` on file responses. |

Rules (config errors):
* `static` needs exactly one string argument. The directory must exist and be a directory at load (`route X: static <dir>: not a directory`).
* A route with `static` and `upstream` ⇒ `route X: static and upstream are mutually exclusive`.
* A route with `static` and any of `health-check`, `timeouts`, `cache`, `fallback` ⇒ `route X: <node> does not apply to a static route`.
* A route with neither ⇒ `route needs at least one upstream or a static directory` (replaces the old message, which tests only match on `upstream`).
* `index` containing `/` or `..` ⇒ error. Duplicate `static` ⇒ `duplicate node`.
* The directory is canonicalized at **runtime build** (symlinked roots are fine).

## 3. Request handling

```text
method not GET/HEAD                      -> 405 + Allow: GET, HEAD
path = percent-decode(uri.path())        -> invalid UTF-8, NUL or '\' -> 400
segments = split '/', drop "" and "."    -> ".." anywhere -> 404 (no information leak)
segment starts with '.' and !hidden      -> 404
walk root + segments with symlink_metadata:
    symlink and !follow-symlinks         -> 404
    follow-symlinks: canonicalize the final path (no containment, the operator opted in)
missing                                  -> spa? root index (200) : 404
directory:
    request path without trailing '/'    -> 301 to path + '/' (query kept)
    index file is a regular file         -> serve it
    listing                              -> 200 HTML
    else                                 -> 404
regular file                             -> ServeFile (Range, conditional, HEAD, MIME)
other (socket, fifo, device)             -> 404
```

Responses carry `X-Content-Type-Options: nosniff`. Listing responses also carry
`Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'` and `Cache-Control: no-cache`.

### Listing

Sorted directories first, then files, case-insensitive by name. Columns: name, size (human readable), modified (UTC).
Names are HTML-escaped in text and percent-encoded in `href`. A `../` link is present except at the root.
More than 10 000 entries ⇒ the listing is truncated and says so. `HEAD` returns the headers only.

## 4. Code layout

```text
src/config/model.rs        + StaticCfg, RouteCfg.static_files
src/config/parse_route.rs  + parse_static, exclusivity rules
src/config/validate.rs     + directory check, skip weight/health checks for static routes
src/staticfiles/mod.rs     StaticService (tower Service<Req>), request flow of §3
src/staticfiles/path.rs    pure path resolution (decode, traversal, dotfiles), unit tests
src/staticfiles/listing.rs HTML rendering, escaping, human sizes, unit tests
src/routing/stack.rs       terminal service choice (static vs proxy)
src/mcp/tools.rs           "static" in the feature list and a `static_dir` field
```

Dependencies: `tower-http` feature `fs` (pulls `mime_guess`, `http-range-header`, `percent-encoding`, already-present
`tokio-util`, `httpdate`) and `percent-encoding` as a direct dependency (already in the tree through `url`).

## 5. Tests (written before the implementation)

Config (`src/config/tests.rs`): defaults, all properties, static + upstream rejected, static + each forbidden node
rejected, route without backend rejected, missing directory rejected, file instead of directory rejected, bad `index`,
duplicate `static`.

Path unit tests (`staticfiles/path.rs`): `..`, `%2e%2e`, `%2f` handling, double slash, NUL, backslash, dotfile segments,
invalid UTF-8.

Listing unit tests: escaping of `<script>`, quotes and `&` in names, href encoding of spaces and `#`, `?`, ordering, parent link.

Integration (`tests/static_files.rs`, real gateway, temp directory):
* GET file: 200, body, `content-type`, `content-length`, `last-modified`, `nosniff`.
* HEAD: headers without body. POST: 405 with `Allow`.
* `Range: bytes=0-3` ⇒ 206 with `content-range`. Conditional `If-Modified-Since` ⇒ 304.
* Directory with index ⇒ index. Directory without trailing slash ⇒ 301.
* Listing on by default, off with `listing=#false` (404), dotfile hidden in the listing, `<script>` file name escaped.
* Traversal: `/../secret`, `/%2e%2e/secret`, `/a/..%2f..%2fsecret` never leak a file outside the root.
* Dotfile 404 by default, 200 with `hidden=#true`.
* Symlink to a file outside the root: 404 by default, 200 with `follow-symlinks=#true`.
* SPA mode: unknown extensionless path ⇒ index 200, unknown `.js` ⇒ 404.
* `cache-control` property applied.
* Layers still apply: `rate-limit` returns 429, and a `gatekeeper` route serves its login page instead of the file.
* Compression: a text file larger than `min-size` with `Accept-Encoding: gzip` is compressed.

## 6. Risks

| # | Risk | Mitigation |
|---|---|---|
| X1 | Symlink and traversal escapes. | Component walk with `symlink_metadata`, `..` never accepted, explicit tests. `follow-symlinks=#true` is opt-in and documented as unsafe for untrusted content. |
| X2 | Listing leaks file names by default (S4 decision). | Documented prominently, `listing=#false` and dotfiles hidden by default. |
| X3 | Large directories exhaust memory. | 10 000 entry cap, entries stream from `read_dir`, only the kept entries are held. |
| X4 | Time-of-check/time-of-use between the walk and the open. | Accepted for a read-only server whose root is operator-controlled. Documented. |
