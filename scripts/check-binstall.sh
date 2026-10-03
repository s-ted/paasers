#!/usr/bin/env bash
# Checks the cargo-binstall contract: for every host target binstall may resolve, the URL and the in-archive path
# rendered from [package.metadata.binstall] (Cargo.toml) must match a file in dist/, its .sig, and an archive entry.
# Run after scripts/build-release.sh and scripts/sign-release.sh (CI release job, or locally).
# REQUIRE_SIG=0 skips the .sig check (CI dry runs on pull requests have no signing key).
set -euo pipefail
cd "$(dirname "$0")/.."

meta=$(cargo metadata --no-deps --format-version 1 | jq '.packages[] | select(.name == "paasers")')
version=$(jq -r .version <<<"$meta")
repo=$(jq -r .repository <<<"$meta")
HOSTS=(
  x86_64-unknown-linux-musl x86_64-unknown-linux-gnu
  aarch64-unknown-linux-musl aarch64-unknown-linux-gnu
  x86_64-pc-windows-gnu x86_64-pc-windows-msvc
)
render() { # template target suffix binext
  local s="$1"
  s="${s//\{ repo \}/$repo}"; s="${s//\{ name \}/paasers}"; s="${s//\{ version \}/$version}"
  s="${s//\{ target \}/$2}"; s="${s//\{ archive-suffix \}/$3}"; s="${s//\{ bin \}/paasers}"; s="${s//\{ binary-ext \}/$4}"
  printf '%s' "$s"
}

fail=0
for t in "${HOSTS[@]}"; do
  get() { jq -r --arg t "$t" --arg k "$1" '.metadata.binstall.overrides[$t][$k] // .metadata.binstall[$k]' <<<"$meta"; }
  fmt=$(get pkg-fmt)
  case "$fmt" in tgz) suffix=".tar.gz" ;; zip) suffix=".zip" ;; *) echo "unexpected pkg-fmt $fmt" >&2; exit 1 ;; esac
  ext=""; [[ "$t" == *windows* ]] && ext=".exe"
  url=$(render "$(get pkg-url)" "$t" "$suffix" "$ext")
  inner=$(render "$(get bin-dir)" "$t" "$suffix" "$ext")
  prefix="$repo/releases/download/v$version/"
  [[ "$url" == "$prefix"* ]] || { echo "FAIL $t: $url is not under $prefix" >&2; fail=1; continue; }
  file="dist/${url#"$prefix"}"
  [[ -f "$file" ]] || { echo "FAIL $t: missing $file" >&2; fail=1; continue; }
  if [[ "${REQUIRE_SIG:-1}" == 1 && ! -f "$file.sig" ]]; then echo "FAIL $t: missing $file.sig" >&2; fail=1; continue; fi
  if [[ "$fmt" == zip ]]; then list=$(unzip -Z1 "$file"); else list=$(tar tzf "$file"); fi
  grep -qxF "$inner" <<<"$list" || { echo "FAIL $t: $inner not in $file" >&2; fail=1; continue; }
  echo "ok   $t -> ${file#dist/} : $inner"
done
exit "$fail"
