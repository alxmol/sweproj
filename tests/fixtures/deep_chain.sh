#!/usr/bin/env bash
set -euo pipefail

# This fixture drives the stack-safety ancestry integration test with a
# configurable deep chain. The Rust harness builds a synthetic `/proc` tree and
# verifies iterative truncation behavior, which is the closest non-privileged
# equivalent to the eventual daemon-level deep-recursion validation contract.

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <depth>" >&2
  exit 64
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPTH="$1"

cd "$ROOT_DIR"
MINI_EDR_TEST_CHAIN_DEPTH="$DEPTH" cargo test \
  -p mini-edr-pipeline \
  --test ancestry \
  ancestry_deep_chain_stack_safety_fixture_matches_requested_depth \
  -- --exact --nocapture
