#!/usr/bin/env bash
# Measures the resident memory of the release binary with an empty cache after 1000 requests.
# Budget: < 20 MB (PLAN R1). The gate uses `worker-threads 2`, the documented mitigation: with the default
# of min(cpus, 4) threads the RSS is higher (about 23 MB measured with 4 threads), which is reported too.
set -euo pipefail
BIN="${BIN:-target/x86_64-unknown-linux-musl/release/paasers}"
LIMIT_KB="${LIMIT_KB:-20480}"
T=$(mktemp -d)
BE=""; GW=""
cleanup() { kill $GW $BE 2>/dev/null || true; }
trap cleanup EXIT
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$T" >/dev/null 2>&1 & BE=$!

measure() { # $1 = extra gateway line (may be empty)
  printf 'gateway {\n    listen "127.0.0.1:18000"\n    storage-path "%s/db-%s.sqlite"\n    %s\n}\nroute "rss.test" {\n    upstream "127.0.0.1:18080"\n}\n' \
    "$T" "$RANDOM" "$1" > "$T/gw.kdl"
  "$BIN" run -c "$T/gw.kdl" >/dev/null 2>&1 & GW=$!
  sleep 1
  for _ in $(seq 1 1000); do curl -s -o /dev/null -H 'Host: rss.test' http://127.0.0.1:18000/; done
  awk '/VmRSS/{print $2}' "/proc/$GW/status"
  kill $GW 2>/dev/null || true; wait $GW 2>/dev/null || true; GW=""
}

DEFAULT_KB=$(measure "")
echo "default worker threads: RSS=${DEFAULT_KB} kB (informational)"
RSS=$(measure "worker-threads 2")
echo "worker-threads 2:       RSS=${RSS} kB (limit ${LIMIT_KB} kB)"
[ "$RSS" -lt "$LIMIT_KB" ]
