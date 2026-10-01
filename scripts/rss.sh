#!/usr/bin/env bash
# Measures the resident memory of the release binary with an empty cache after 1000 requests.
# Budget: < 32 MB (raised from 20 MB). The gate runs the default configuration (up to 4 worker threads);
# `worker-threads 2` is also reported, since it is the knob to turn on small machines.
set -euo pipefail
BIN="${BIN:-target/x86_64-unknown-linux-musl/release/paasers}"
LIMIT_KB="${LIMIT_KB:-32768}"
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

TWO_KB=$(measure "worker-threads 2")
echo "worker-threads 2:       RSS=${TWO_KB} kB (informational)"
RSS=$(measure "")
echo "default worker threads: RSS=${RSS} kB (limit ${LIMIT_KB} kB)"
[ "$RSS" -lt "$LIMIT_KB" ]
