#!/usr/bin/env bash
# Starts a local pebble ACME test server (CI). Usage: scripts/pebble.sh && PEBBLE_DIR=target/pebble cargo test --test acme -- --ignored
set -euo pipefail
V=v2.10.1
D="${PEBBLE_DIR:-$PWD/target/pebble}"; mkdir -p "$D"; cd "$D"
[ -x pebble ] || {
  curl -sSL "https://github.com/letsencrypt/pebble/releases/download/$V/pebble-linux-amd64.tar.gz" | tar xz -C .
  # The archive unpacks to a versioned or platform directory: locate the binary wherever it landed.
  cp "$(find . -type f -name pebble | head -1)" ./pebble && chmod +x ./pebble
}
curl -sSL -o pebble.minica.pem https://raw.githubusercontent.com/letsencrypt/pebble/main/test/certs/pebble.minica.pem
mkdir -p certs/localhost
curl -sSL -o certs/localhost/cert.pem https://raw.githubusercontent.com/letsencrypt/pebble/main/test/certs/localhost/cert.pem
curl -sSL -o certs/localhost/key.pem  https://raw.githubusercontent.com/letsencrypt/pebble/main/test/certs/localhost/key.pem
cat > pebble.json <<JSON
{"pebble":{"listenAddress":"127.0.0.1:14000","managementListenAddress":"127.0.0.1:15000",
 "certificate":"certs/localhost/cert.pem","privateKey":"certs/localhost/key.pem",
 "httpPort":${PEBBLE_HTTP_PORT:-5002},"tlsPort":5001,"ocspResponderURL":"","externalAccountBindingRequired":false}}
JSON
# Detached from this shell so that callers piping our output do not wait for pebble to exit.
PEBBLE_VA_NOSLEEP=1 PEBBLE_VA_ALWAYS_VALID=0 nohup ./pebble -config pebble.json >pebble.log 2>&1 &
echo $! > pebble.pid
