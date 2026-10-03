# Security policy

paasers is an edge gateway exposed to the Internet, so security reports are taken seriously and handled first.

## Supported versions

Only the latest release receives security fixes. Fixes are published as a new patch release; please upgrade
rather than patching an older version.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Report it privately through GitHub:
[Security > Report a vulnerability](https://github.com/s-ted/paasers/security/advisories/new).
The report is visible only to the maintainer until an advisory is published.

A useful report contains:

* the affected version (`paasers version`) and platform;
* the relevant part of the configuration, with secrets removed;
* the steps or requests to reproduce, and the observed impact.

This is a single-maintainer project: reports are acknowledged on a best-effort basis, usually within a week.
Once a fix is released, a GitHub security advisory is published, crediting the reporter unless they prefer
otherwise.

## In scope

Anything that lets a remote client bypass what the configuration promises, for example: request smuggling,
path traversal out of a `static` root, authentication bypass (gatekeeper, JWT, API keys), access to the local
MCP server from outside, TLS or ACME issues, or a crash or resource exhaustion triggered by a single client.

Out of scope: issues that require control of the configuration file, the host, or the upstream backends.

## Verifying a release

Release archives are signed with minisign. The public key is pinned in `Cargo.toml`
(`[package.metadata.binstall.signing]`), and `cargo binstall --only-signed paasers` checks it automatically.
By hand:

```bash
minisign -Vm paasers-<version>-<target>.tar.gz -P RWSejPf058zYfUwKUqoKW+2SIIY7g4Ahz7Ku6o0pzoiscLGHyr1bxaD1
gh attestation verify paasers-<version>-<target>.tar.gz -R s-ted/paasers   # build provenance
```
