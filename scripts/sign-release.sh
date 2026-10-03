#!/usr/bin/env bash
# Signs every release archive in dist/ with minisign, as cargo-binstall expects: <archive>.sig next to <archive>.
# The secret key comes from $MINISIGN_KEY (file content, CI secret) or $MINISIGN_KEY_FILE (path).
# The key has no password (minisign -G -W): it is protected by the CI secret store instead.
# Then checks each signature against the public key pinned in Cargo.toml, so a key mismatch fails the release.
set -euo pipefail
cd "$(dirname "$0")/.."

key_file="${MINISIGN_KEY_FILE:-}"
if [[ -z "$key_file" ]]; then
  [[ -n "${MINISIGN_KEY:-}" ]] || { echo "set MINISIGN_KEY or MINISIGN_KEY_FILE" >&2; exit 1; }
  key_file=$(mktemp)
  trap 'rm -f "$key_file"' EXIT
  # Tolerate copy-paste artefacts: CRLF line ends, surrounding blank lines, or the base64 line alone.
  key=$(printf '%s\n' "$MINISIGN_KEY" | tr -d '\r' | sed '/^[[:space:]]*$/d')
  b64=$(printf '%s\n' "$key" | grep -v '^untrusted comment:' | head -1 | tr -d '[:space:]')
  if [[ ${#b64} -lt 100 ]]; then
    # A minisign public key is 56 base64 chars, an unencrypted secret key is about 212.
    echo "MINISIGN_KEY does not hold a secret key (${#b64} base64 chars): did you paste minisign.pub instead of minisign.key?" >&2
    exit 1
  fi
  printf 'untrusted comment: minisign secret key\n%s\n' "$b64" > "$key_file"
fi
pubkey=$(cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[] | select(.name == "paasers") | .metadata.binstall.signing.pubkey')
version=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "paasers") | .version')

shopt -s nullglob
archives=(dist/paasers-*.tar.gz dist/paasers-*.zip)
[[ ${#archives[@]} -gt 0 ]] || { echo "no archive in dist/" >&2; exit 1; }
for a in "${archives[@]}"; do
  minisign -S -W -s "$key_file" -x "$a.sig" -m "$a" -t "paasers $version $(basename "$a")" >/dev/null
  minisign -V -q -P "$pubkey" -x "$a.sig" -m "$a"
  echo "signed $a"
done
