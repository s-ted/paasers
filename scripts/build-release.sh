#!/usr/bin/env bash
# Release builds via cargo-zigbuild (zig is the C compiler and linker), packaged the way cargo-binstall expects.
# Usage: scripts/build-release.sh [target...]   (default: all targets)
# Output, per target (layout declared in [package.metadata.binstall] of Cargo.toml):
#   dist/paasers-<version>-<target>.tar.gz   (Windows: .zip)
#     └── paasers-<version>-<target>/paasers[.exe], README.md, LICENSE-*
# plus dist/SHA256SUMS over every archive present in dist/. Signing is a separate step: scripts/sign-release.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

ALL_TARGETS=(
  x86_64-unknown-linux-musl   # amd64 servers (also served to glibc hosts by binstall)
  aarch64-unknown-linux-musl  # Raspberry Pi 4/5 (64 bit OS), ARM servers
  x86_64-pc-windows-gnu       # Windows (also served to msvc hosts by binstall)
)
TARGETS=("${@:-${ALL_TARGETS[@]}}")
VERSION=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "paasers") | .version')

mkdir -p dist
for t in "${TARGETS[@]}"; do
  echo "==> $t"
  cargo zigbuild --release --locked --target "$t"
  ext=""; [[ "$t" == *windows* ]] && ext=".exe"
  bin="target/$t/release/paasers${ext}"
  if [[ "$t" == *linux-musl ]]; then
    file "$bin" | grep -qE 'statically linked|static-pie linked' || { echo "not static: $bin" >&2; exit 1; }
  fi
  name="paasers-${VERSION}-${t}"
  stage=$(mktemp -d)
  mkdir "$stage/$name"
  cp "$bin" README.md LICENSE-MIT LICENSE-APACHE "$stage/$name/"
  rm -f "dist/$name".*
  if [[ "$t" == *windows* ]]; then
    (cd "$stage" && zip -qr -X "$OLDPWD/dist/$name.zip" "$name")
  else
    # Reproducible-ish tarball: fixed owner, mtime from the last commit, sorted entries.
    mtime=$(git log -1 --format=%ct 2>/dev/null || echo 0)
    tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$mtime" -czf "dist/$name.tar.gz" "$name"
  fi
  rm -rf "$stage"
  echo "    $(du -h "$bin" | cut -f1) binary -> $(ls dist/"$name".*)"
done
# nullglob: a single-target build (CI matrix) has no .zip or no .tar.gz, which must not fail the script.
(cd dist && shopt -s nullglob && sha256sum paasers-*.tar.gz paasers-*.zip > SHA256SUMS)
