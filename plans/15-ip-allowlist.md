# P15: per-route IP allowlist (`allow-ips`) and named sets (`ip-set`)

> Status: **implemented**. Same rule as every phase: `cargo check`, `cargo test` and `cargo clippy --all-targets -- -D warnings`
> green before the commit. Order of work: this plan, then tests, then implementation, then docs and example.

## 1. Goals and decisions

| # | Decision |
|---|---|
| A1 | A route may restrict its clients to a list of networks: `allow-ips { ... }`. Absent ⇒ **no filtering** (every client is allowed). There is no implicit `0.0.0.0/0`, which would forget IPv6. |
| A2 | Allow only. No `deny`, no per-path rule, no configurable status (YAGNI). A refused client gets **403** through the gateway error page (`render_error`, Incident ID), incident kind `ip_blocked`. |
| A3 | Lists are written **one entry per line** as KDL children named `-`, so each range can carry a `//` comment and be disabled with `/-`. The positional form (`allow-ips "a" "b"`) is accepted too, for short lists. Both forms may be mixed. |
| A4 | **Named sets** remove duplication: `ip-set "<name>" { - "<cidr>" ... }` at top level, referenced by name inside any list. An entry is a network if it parses as one (CIDR or bare IP), otherwise a set name. No nesting: an `ip-set` contains networks only. |
| A5 | One list parser for every IP list of the grammar: `allow-ips` and `gateway { trusted-proxies }` (which keeps its current syntax and also gains the block form and set references). |
| A6 | Matching: no new crate. At load, networks are resolved, then `ipnet::IpNet::aggregate` merges overlaps, adjacent ranges and duplicates and clears host bits. The layer keeps two sorted vectors (v4, v6) and does a binary search (`partition_point` on the network address, then `contains` on the single candidate). No allocation, no lock per request. A prefix trie is only worth it for hundreds of thousands of ranges (reputation feeds), out of scope. |
| A7 | The client address is the one already computed by `Entry` (`ClientIp`: TCP peer, or right-most untrusted `X-Forwarded-For` when the peer is a trusted proxy), canonical form (`::ffff:a.b.c.d` ⇒ `a.b.c.d`). The matcher canonicalizes again (defensive, tests build requests by hand). |
| A8 | Position: **outermost layer** of the route stack, before GeoIP: cheapest rejection, a refused client consumes no rate-limit budget, no argon2, no backend. Applies to proxied and static routes alike. ACME HTTP-01 and the `redirect-https` 301, handled by `Entry` before the stack, are not filtered (ACME must stay reachable, a redirect discloses nothing). |
| A9 | Hot reload: the list is part of the route config, the layer is rebuilt with the stack (no registry, no state). |

## 2. Grammar

```text
ip-set "<name>" {                 top level, 0..n, name unique
    - "<cidr or ip>"              1..n, networks only
}

route <host>+ {
    allow-ips ["<entry>"...] {    0..1; entry = cidr, bare ip, or ip-set name
        - "<entry>"
    }
}

gateway {
    trusted-proxies ["<entry>"...] { - "<entry>" }   same list syntax, may be empty
}
```

Example:

```kdl
ip-set "staff" {
    - "203.0.113.0/24"     // Paris office
    - "2001:db8:42::/48"   // Paris office, IPv6
    - "198.51.100.7"       // VPN exit
}

route "admin.client.com" {
    upstream "10.0.1.20:8080"
    allow-ips {
        - "staff"
        - "192.0.2.10"         // contractor, until 2026-12
        /- - "192.0.2.0/24"    // disabled
    }
}
```

Rules (config errors, positioned on the offending node):
* `ip-set` needs exactly one string argument and no property. Name: `[A-Za-z0-9_-]+`, must not parse as a network (`invalid ip-set name`). Two sets with the same name ⇒ `duplicate ip-set \`<name>\``. A set with no entry ⇒ `ip-set \`<name>\` is empty`.
* List children: only nodes named `-`, each with exactly one string argument, no property, no children.
* An entry that is neither a network nor a known set ⇒ `unknown ip-set \`<name>\``. Inside an `ip-set`, a non-network entry ⇒ `invalid network \`<entry>\``.
* `allow-ips` resolving to no entry ⇒ `allow-ips needs at least one entry`. `trusted-proxies` may be empty (= trust nobody, unchanged).
* `ip-set` declarations may appear anywhere at top level (before or after their use).

## 3. Data model

* `RouteCfg.allow_ips: Option<Vec<IpNet>>`: resolved and aggregated; `None` when the node is absent.
* `GatewayCfg.trusted_proxies: Vec<IpNet>`: unchanged type, now resolved through the same parser.
* Sets are a parse-time concept only: they are not kept in `Config`.
* `src/config/parse_ipset.rs`: `parse_ip_sets(&Scope) -> Result<IpSets, ConfigError>` and `ip_list(&NodeCtx, &IpSets) -> Result<Vec<IpNet>, ConfigError>` (aggregated). `parse_gateway` and `parse_route` receive `&IpSets`.
* `src/layers/ipallow.rs`: `IpAllow { v4: Vec<Ipv4Net>, v6: Vec<Ipv6Net> }` with `from_nets(&[IpNet])` and `contains(IpAddr) -> bool`; `IpAllowLayer` / `IpAllowSvc` following the concrete Tower pattern (plans/00 §5). Missing `ClientIp` extension ⇒ refused (fail closed).
* MCP `get_route_status`: feature `allow-ips` listed when configured.

## 4. Tests

`config` (`src/config/tests_ipset.rs`):
* `allow_ips_absent_is_none`, `allow_ips_block_and_positional_mixed`, `allow_ips_resolves_set_and_aggregates` (set + duplicate + adjacent ranges ⇒ merged), `allow_ips_host_bits_cleared`.
* `ip_set_declared_after_use`, `ip_set_reused_by_two_routes`, `trusted_proxies_block_form_and_set`.
* Errors: `allow_ips_empty`, `allow_ips_unknown_set`, `ip_set_duplicate`, `ip_set_empty`, `ip_set_nested_rejected`, `ip_set_invalid_name`, `list_child_not_dash`, `list_child_with_property`, `duplicate_allow_ips`.
* `comments_and_slashdash_ignored`.
* `allow_ips_example_parses` (`examples/allow-ips.kdl`), `allow_ips_doc_snippets_parse` (every `kdl` block of `docs/features/allow-ips.md`).

`layers::ipallow`:
* `matcher_v4_v6_edges` (first/last address of a range, just outside, mixed families), `matcher_ipv4_mapped`, `matcher_many_ranges` (10 000 random ranges cross-checked against a linear scan).
* `allowed_passes`, `refused_403_ip_blocked` (status, `IncidentKind`), `missing_client_ip_refused`.

Integration (`tests/layers.rs`): `allow_ips_refuses_then_allows_through_xff` (gateway with `trusted-proxies "127.0.0.1"`: `X-Forwarded-For` outside the list ⇒ 403, inside ⇒ 200, backend never reached on refusal).

## 5. Docs

* `docs/features/allow-ips.md` (new), `docs/features/gateway.md` (`trusted-proxies` block form, sets), `docs/features/defaults.md` (absent = everyone), README feature list, `docs/features/mcp.md` (incident kind), `examples/allow-ips.kdl` (`examples/gateway.kdl` stays the SPECS example).
* Spoofing note: behind the default `trusted-proxies` (private ranges), any host of the private network can forge `X-Forwarded-For`. Narrow `trusted-proxies` to the real front load balancer when `allow-ips` matters.

## 6. DoD P15
- [x] §4 tests green (`cargo test config::`, `cargo test layers::ipallow`, `cargo test --test layers allow_ips`).
- [x] `scripts/ci.sh` green (fmt, clippy, ≤ 250 lines).
- [x] Docs and example updated, `paasers check -c examples/allow-ips.kdl` OK.
