#!/usr/bin/env bash
# Drive the fork-storm fixture while exercising the daemon's SIGHUP path.
#
# This script is intentionally environment-driven because the full daemon wiring
# arrives in a later milestone. Pipeline workers can still syntax-check it and
# run `--dry-run`, while the future daemon/system validators can provide a live
# PID, log path, and bpftool path without rewriting the harness.
#
# Parsed output requirement for the future daemon log:
# - The daemon may emit general NDJSON logs, but lines intended for this
#   validator MUST use `record_type="fork_storm_enrichment"`.
# - Each validator line MUST contain `pid`, `ancestry_truncated`,
#   `enrichment_partial`, and `ancestry_chain`.
# - `ancestry_chain` MUST be ordered leaf-to-root so complete chains end at
#   PID 1 (or the explicit `[kthreadd]` allow-list terminator) and so the
#   parser can prove there are no cycles or `ppid == 0` gaps mid-chain.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORK_STORM_FIXTURE="${SCRIPT_DIR}/fork_storm"
LOG_CHECKER="${SCRIPT_DIR}/check_fork_storm_log.sh"
GOOD_DAEMON_FIXTURE="${SCRIPT_DIR}/fork_storm_synthetic_daemon.ndjson"
BPFT_TOOL_DEFAULT="/usr/lib/linux-tools/6.8.0-110-generic/bpftool"
FORK_STORM_RATE="${MINI_EDR_FORK_STORM_RATE:-50000}"
FORK_STORM_DURATION="${MINI_EDR_FORK_STORM_DURATION:-10s}"
FORK_STORM_CHILD_HOLD_MS="${MINI_EDR_FORK_STORM_CHILD_HOLD_MS:-0}"
BPFT_TOOL="${MINI_EDR_BPFTOOL:-${MINI_EDR_BPFTool:-${BPFT_TOOL_DEFAULT}}}"
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

parse_daemon_log() {
  local log_path="$1"
  "${LOG_CHECKER}" "${log_path}"
}

require_bpftool() {
  if [[ -x "${BPFT_TOOL}" ]]; then
    return 0
  fi

  if command -v bpftool >/dev/null 2>&1; then
    BPFT_TOOL="$(command -v bpftool)"
    return 0
  fi

  printf 'FAIL: bpftool not on PATH and MINI_EDR_BPFTOOL=%s is not executable\n' "${BPFT_TOOL}" >&2
  exit 2
}

snapshot_probes() {
  "${BPFT_TOOL}" prog list 2>&1 \
    | rg -i 'mini.edr|sched_process_(fork|exit)' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+/ /g' \
    | sort
}

if [[ "${DRY_RUN}" -eq 1 ]]; then
  parse_daemon_log "${DAEMON_LOG:-${GOOD_DAEMON_FIXTURE}}"
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

if [[ -z "${DAEMON_LOG}" ]]; then
  printf 'error: MINI_EDR_DAEMON_LOG is required unless --dry-run is used\n' >&2
  exit 64
fi

if [[ ! -f "${DAEMON_LOG}" ]]; then
  printf 'error: daemon log %s does not exist\n' "${DAEMON_LOG}" >&2
  exit 64
fi

require_bpftool

storm_log="$(mktemp "/tmp/mini-edr-fork-storm.XXXXXX.log")"
bpftool_prefix="$(mktemp -u "/tmp/mini-edr-bpftool.XXXXXX")"
baseline_snapshot="/tmp/mini-edr-fork-storm-baseline.txt"
interval_seconds="$(duration_interval_seconds)"

# Race-window note: a SIGHUP can land after the kernel has published a clone
# event for a fresh child PID but before userspace has drained the matching
# follow-up events or refreshed every procfs cache entry. That means a small
# amount of partial enrichment is expected, but duplicate probe attachments,
# cyclic ancestry chains, and daemon panics are not. We therefore lock the
# probe set before the storm starts and delegate ancestry/partial analysis to
# the parser that enforces the documented NDJSON schema above.
baseline="$(snapshot_probes)"
printf '%s\n' "${baseline}" >"${baseline_snapshot}"
expected_count=6
baseline_count="$(printf '%s\n' "${baseline}" | sed '/^$/d' | wc -l | tr -d ' ')"
if [[ "${baseline_count}" -ne "${expected_count}" ]]; then
  printf 'FAIL: baseline probe count = %s != %s\n' "${baseline_count}" "${expected_count}" >&2
  exit 3
fi

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
  sleep 0.5
  current="$(snapshot_probes)"
  printf '%s\n' "${current}" >"${bpftool_prefix}.${reload_index}.txt"
  if [[ "${current}" != "${baseline}" ]]; then
    diff <(printf '%s\n' "${baseline}") <(printf '%s\n' "${current}") || true
    printf 'FAIL: probe set changed after SIGHUP #%s\n' "${reload_index}" >&2
    exit 4
  fi
done

wait "${storm_pid}"
trap - EXIT

if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
  printf 'error: daemon pid %s exited during fork storm\n' "${DAEMON_PID}" >&2
  exit 1
fi

parse_daemon_log "${DAEMON_LOG}"

if rg -in '\bpanic\b' "${DAEMON_LOG}" >/dev/null; then
  printf 'error: panic found in daemon log %s\n' "${DAEMON_LOG}" >&2
  exit 7
fi

printf 'daemon_pid=%s\n' "${DAEMON_PID}"
printf 'fork_storm_rate=%s\n' "${FORK_STORM_RATE}"
printf 'fork_storm_duration=%s\n' "${FORK_STORM_DURATION}"
printf 'fork_storm_child_hold_ms=%s\n' "${FORK_STORM_CHILD_HOLD_MS}"
printf 'storm_log=%s\n' "${storm_log}"
printf 'bpftool_snapshot_prefix=%s\n' "${bpftool_prefix}"
printf 'bpftool_baseline_snapshot=%s\n' "${baseline_snapshot}"
