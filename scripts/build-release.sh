#!/usr/bin/env bash
# Release builds for every supported target, via cargo-zigbuild (zig is the C compiler and linker).
# Usage: scripts/build-release.sh [target...]   (default: all targets)
# Output: dist/paasers-<version>-<target>[.exe] and dist/SHA256SUMS
set -euo pipefail
cd "$(dirname "$0")/.."

ALL_TARGETS=(
  x86_64-unknown-linux-musl   # amd64 servers
  aarch64-unknown-linux-musl  # Raspberry Pi 4/5 (64 bit OS), ARM servers
  x86_64-pc-windows-gnu       # Windows
)
TARGETS=("${@:-${ALL_TARGETS[@]}}")
VERSION=$(cargo metadata --no-deps --format-version 1 | sed -n 's/.*"version":"\([^"]*\)".*/\1/p' | head -1)

mkdir -p dist
for t in "${TARGETS[@]}"; do
  echo "==> $t"
  cargo zigbuild --release --locked --target "$t"
  ext=""; [[ "$t" == *windows* ]] && ext=".exe"
  out="dist/paasers-${VERSION}-${t}${ext}"
  cp "target/$t/release/paasers${ext}" "$out"
  echo "    $(du -h "$out" | cut -f1)  $out"
  if [[ "$t" == *linux-musl ]]; then
    file "$out" | grep -qE 'statically linked|static-pie linked' || { echo "not static: $out" >&2; exit 1; }
  fi
done
(cd dist && sha256sum paasers-* > SHA256SUMS)
