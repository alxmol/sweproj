#!/usr/bin/env bash
# Drive the fork-storm fixture while exercising the daemon's SIGHUP path.
#
# This script is intentionally environment-driven because the full daemon wiring
# arrives in a later milestone. Pipeline workers can still syntax-check it and
# run `--dry-run`, while the future daemon/system validators can provide a live
# PID, log path, and bpftool path without rewriting the harness.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORK_STORM_FIXTURE="${SCRIPT_DIR}/fork_storm"
BPFT_TOOL_DEFAULT="/usr/lib/linux-tools/6.8.0-110-generic/bpftool"
FORK_STORM_RATE="${MINI_EDR_FORK_STORM_RATE:-50000}"
FORK_STORM_DURATION="${MINI_EDR_FORK_STORM_DURATION:-10s}"
FORK_STORM_CHILD_HOLD_MS="${MINI_EDR_FORK_STORM_CHILD_HOLD_MS:-0}"
BPFT_TOOL="${MINI_EDR_BPFTool:-${BPFT_TOOL_DEFAULT}}"
DRY_RUN=0

if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
  shift
fi

DAEMON_PID="${MINI_EDR_DAEMON_PID:-}"
DAEMON_LOG="${MINI_EDR_DAEMON_LOG:-}"

duration_interval_seconds() {
  python3 - "$FORK_STORM_DURATION" <<'PY'
import re
import sys

value = sys.argv[1]
match = re.fullmatch(r"(\d+)(ms|s|m)?", value)
if not match:
    raise SystemExit(f"unsupported duration syntax: {value}")
quantity = int(match.group(1))
unit = match.group(2) or "s"
seconds = {
    "ms": quantity / 1000.0,
    "s": float(quantity),
    "m": float(quantity * 60),
}[unit]
print(seconds / 6.0)
PY
}

run_fixture() {
  "${FORK_STORM_FIXTURE}" \
    --rate "${FORK_STORM_RATE}" \
    --duration "${FORK_STORM_DURATION}" \
    --child-hold-ms "${FORK_STORM_CHILD_HOLD_MS}"
}

if [[ "${DRY_RUN}" -eq 1 ]]; then
  run_fixture
  printf 'dry_run=1\n'
  printf 'planned_sighup_interval_seconds=%s\n' "$(duration_interval_seconds)"
  exit 0
fi

if [[ -z "${DAEMON_PID}" ]]; then
  printf 'error: MINI_EDR_DAEMON_PID is required unless --dry-run is used\n' >&2
  exit 64
fi

if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
  printf 'error: daemon pid %s is not running\n' "${DAEMON_PID}" >&2
  exit 64
fi

storm_log="$(mktemp "/tmp/mini-edr-fork-storm.XXXXXX.log")"
bpftool_prefix="$(mktemp -u "/tmp/mini-edr-bpftool.XXXXXX")"
interval_seconds="$(duration_interval_seconds)"

# Race-window note: a SIGHUP can land after the kernel has published a clone
# event for a fresh child PID but before userspace has drained the matching
# follow-up events or refreshed every procfs cache entry. That means a small
# amount of partial enrichment is expected, but duplicate probe attachments,
# cyclic ancestry chains, or daemon panics are not. The harness therefore
# snapshots the probe inventory after every reload and leaves ancestry/partial
# analysis to the daemon log parser used by later milestones.
run_fixture >"${storm_log}" 2>&1 &
storm_pid=$!
cleanup() {
  kill "${storm_pid}" 2>/dev/null || true
  wait "${storm_pid}" 2>/dev/null || true
}
trap cleanup EXIT

for reload_index in 1 2 3 4 5; do
  sleep "${interval_seconds}"
  kill -HUP "${DAEMON_PID}"
  if [[ -x "${BPFT_TOOL}" ]]; then
    "${BPFT_TOOL}" prog list >"${bpftool_prefix}.${reload_index}.txt" 2>&1 || true
  fi
done

wait "${storm_pid}"
trap - EXIT

if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
  printf 'error: daemon pid %s exited during fork storm\n' "${DAEMON_PID}" >&2
  exit 1
fi

if [[ -n "${DAEMON_LOG}" && -f "${DAEMON_LOG}" ]]; then
  if rg -n "panic" "${DAEMON_LOG}" >/dev/null; then
    printf 'error: panic found in daemon log %s\n' "${DAEMON_LOG}" >&2
    exit 1
  fi
fi

printf 'daemon_pid=%s\n' "${DAEMON_PID}"
printf 'fork_storm_rate=%s\n' "${FORK_STORM_RATE}"
printf 'fork_storm_duration=%s\n' "${FORK_STORM_DURATION}"
printf 'fork_storm_child_hold_ms=%s\n' "${FORK_STORM_CHILD_HOLD_MS}"
printf 'storm_log=%s\n' "${storm_log}"
printf 'bpftool_snapshot_prefix=%s\n' "${bpftool_prefix}"
