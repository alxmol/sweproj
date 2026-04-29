#!/usr/bin/env bash
set -euo pipefail

# This fixture wraps the privileged sensor harness that injects repeated
# `-EINVAL` helper faults into only the connect probe and verifies the other
# three probes keep producing events. A separate target directory keeps sudo
# builds from contaminating the normal workspace artifacts.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export CARGO_HOME="${CARGO_HOME:-/home/directory/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/home/directory/.rustup}"
export PATH="$CARGO_HOME/bin:$PATH"

cd "$ROOT_DIR"
CARGO_TARGET_DIR=/tmp/mini-edr-priv-target "$CARGO_HOME/bin/cargo" test \
  -p mini-edr-sensor \
  --test bpf_programs \
  privileged_harness_isolates_connect_runtime_faults \
  -- --ignored --nocapture --test-threads=1
