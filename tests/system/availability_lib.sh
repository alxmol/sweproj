#!/usr/bin/env bash
# availability_lib.sh — shared helpers for availability-oriented system tests.
#
# Purpose:
# - start isolated localhost daemon instances in deterministic test mode
# - normalize duration parsing so short smoke runs and explicit long gates share one path
# - centralize cleanup/report helpers for soak, probe-reload, and memory-pressure scripts
#
# Cleanup contract:
# - callers own the trap that invokes `availability_stop_daemon`
# - every daemon/log/socket lives under a caller-provided mktemp directory
set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/fixture_runtime_lib.sh"

availability_parse_duration_seconds() {
  "${FIXTURE_PYTHON_BIN}" - "$1" <<'PY'
import re
import sys

value = sys.argv[1].strip().lower()
match = re.fullmatch(r"(\d+)([smhd]?)", value)
if not match:
    raise SystemExit(f"unsupported duration: {value}")
number = int(match.group(1))
unit = match.group(2) or "s"
scale = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
print(number * scale)
PY
}

availability_start_test_daemon() {
  local temp_dir="$1"
  local threshold="${2:-0.7}"
  local chosen_port="${3:-$(fixture_find_free_port)}"
  local config_path="${temp_dir}/config.toml"
  local stdout_path="${temp_dir}/stdout.log"
  local log_path="${temp_dir}/logs/daemon.log"
  local socket_path="${temp_dir}/api.sock"

  cargo build --release -p mini-edr-daemon --manifest-path "${FIXTURE_REPO_ROOT}/Cargo.toml" >/dev/null
  write_config "${config_path}" "${FIXTURE_DEFAULT_MODEL}" "${threshold}" "${chosen_port}"
  local daemon_pid
  daemon_pid="$(
    MINI_EDR_API_SOCKET="${socket_path}" \
    MINI_EDR_TEST_MODE=1 \
    start_daemon "${config_path}" "${stdout_path}"
  )"
  wait_for_health "${chosen_port}"
  printf '%s %s %s %s %s\n' "${daemon_pid}" "${chosen_port}" "${config_path}" "${log_path}" "${socket_path}"
}

availability_stop_daemon() {
  local daemon_pid="$1"
  if [[ -n "${daemon_pid}" ]]; then
    cleanup_daemon "${daemon_pid}"
  fi
}

availability_health_json() {
  local daemon_port="$1"
  curl -fsS "http://127.0.0.1:${daemon_port}/api/health"
}

availability_events_json() {
  local daemon_port="$1"
  local limit="${2:-200}"
  curl -fsS "http://127.0.0.1:${daemon_port}/api/events?limit=${limit}"
}

availability_sample_rss_bytes() {
  local pid="$1"
  awk '/^VmRSS:/ {print $2 * 1024}' "/proc/${pid}/status"
}
