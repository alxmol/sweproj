#!/usr/bin/env bash
set -euo pipefail

# This fixture wraps the privileged sensor harness that forces a 500k `openat`
# burst against the ring buffer and asserts that kernel-side drop accounting
# increments without crashing the probes. It uses a dedicated target directory
# so sudo runs do not leave root-owned artifacts in the workspace `target/`.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export CARGO_HOME="${CARGO_HOME:-/home/directory/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/home/directory/.rustup}"
export PATH="$CARGO_HOME/bin:$PATH"

cd "$ROOT_DIR"
CARGO_TARGET_DIR=/tmp/mini-edr-priv-target "$CARGO_HOME/bin/cargo" test \
  -p mini-edr-sensor \
  --test bpf_programs \
  privileged_harness_counts_ringbuf_overflow_without_crashing_kernel \
  -- --ignored --nocapture --test-threads=1
