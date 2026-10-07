#!/usr/bin/env bash
set -euo pipefail
shopt -s globstar

cd "$(dirname "$0")"

echo "=== Running OmniScan Test Suite ==="
exec node --experimental-strip-types --test tests/**/*.test.ts
