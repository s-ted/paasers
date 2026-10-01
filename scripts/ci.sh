#!/usr/bin/env bash
set -euo pipefail
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
# files <= 250 lines excluding tests
fail=0
for f in $(git ls-files 'src/*.rs' 'src/**/*.rs' | grep -v "/tests.rs$"); do
  n=$(awk '/^#\[cfg\(test\)\]/{exit} {c++} END{print c+0}' "$f")
  if [ "$n" -gt 250 ]; then echo "TOO LONG: $f ($n)"; fail=1; fi
done
exit $fail
