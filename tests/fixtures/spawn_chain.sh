#!/usr/bin/env bash
set -euo pipefail

# This fixture drives the pipeline ancestry integration test with a configurable
# linear chain depth. The Rust test builds an isolated `/proc` fixture tree so
# the ancestry walk can be validated deterministically without requiring a live
# daemon or privileged probe attachment.

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
  ancestry_spawn_chain_fixture_matches_requested_depth \
  -- --exact --nocapture
