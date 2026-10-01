#!/usr/bin/env bash
# Local CI. Steps 1-6 are the acceptance gate of every phase. Set FULL=1 to add the musl build and the memory budget.
set -euo pipefail
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
# files <= 250 lines excluding tests (test-only files are exempt)
fail=0
for f in $(git ls-files 'src/*.rs' 'src/**/*.rs' | grep -v -E "/(tests|[a-z_]+_tests).rs$"); do
  n=$(awk '/^#\[cfg\(test\)\]/{exit} {c++} END{print c+0}' "$f")
  if [ "$n" -gt 250 ]; then echo "TOO LONG: $f ($n)"; fail=1; fi
done
[ "$fail" -eq 0 ] || exit 1
if [ "${FULL:-0}" = "1" ]; then
  cargo test
  cargo test --no-default-features
  cargo zigbuild --release --target x86_64-unknown-linux-musl
  file target/x86_64-unknown-linux-musl/release/paasers | grep -q 'statically linked'
  scripts/rss.sh
fi
