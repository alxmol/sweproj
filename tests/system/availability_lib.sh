#!/usr/bin/env bash
# availability_lib.sh — shared helpers for availability-oriented system tests.
#
# Purpose:
# - keep the duration / cleanup plumbing for the three availability harnesses in
#   one place so soak, probe-reload, and memory-pressure runs stay consistent
# - start either the deterministic synthetic daemon path or the real
#   capability-backed release daemon without duplicating temp-dir setup
# - reuse the performance harness helpers for daemon sweeps, cgroup-safe temp
#   cleanup, and the tiny live-connect workload binaries used by the real gates
#
# Cleanup contract:
# - callers own the EXIT trap that invokes `availability_stop_daemon`
# - privileged callers must use `availability_cleanup_temp_dir` so root does not
#   `rm -rf` the mission-owned `/tmp/mini-edr-*` directories while that cleanup
#   restriction is in effect
set -euo pipefail

source "/home/directory/mini-edr/tests/fixtures/fixture_runtime_lib.sh"
source "/home/directory/mini-edr/tests/perf/perf_lib.sh"

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

availability_cleanup_temp_dir() {
  local temp_dir="$1"
  perf_cleanup_temp_dir "${temp_dir}"
}

availability_sweep_daemons() {
  perf_sweep_daemons
}

availability_ensure_release_daemon() {
  fixture_require_model_artifact
  if [[ -x "${FIXTURE_DAEMON_BIN}" ]]; then
    return 0
  fi
  if [[ ${EUID} -eq 0 ]]; then
    echo "missing ${FIXTURE_DAEMON_BIN}; build the release daemon as the calling user before running this privileged harness" >&2
    return 1
  fi
  cargo build --release -p mini-edr-daemon --manifest-path "${FIXTURE_REPO_ROOT}/Cargo.toml" >/dev/null
  fixture_require_release_daemon
}

availability_require_live_probe_mode() {
  availability_ensure_release_daemon
  if ! perf_live_probe_mode_available; then
    echo "this availability harness requires root or a release daemon binary with cap_bpf,cap_perfmon,cap_sys_admin,cap_dac_read_search" >&2
    return 1
  fi
}

availability_toml_array_from_csv() {
  python3 - "$1" <<'PY'
import json
import sys

values = [item.strip() for item in sys.argv[1].split(",") if item.strip()]
if not values:
    raise SystemExit("at least one monitored syscall is required")
print(json.dumps(values))
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
  local alert_log_path="${temp_dir}/logs/alerts.jsonl"

  availability_ensure_release_daemon
  write_config "${config_path}" "${FIXTURE_DEFAULT_MODEL}" "${threshold}" "${chosen_port}"
  cat >>"${config_path}" <<'EOF'
enable_tui = false
enable_web = true
EOF
  local daemon_pid
  daemon_pid="$(
    MINI_EDR_API_SOCKET="${socket_path}" \
    MINI_EDR_TEST_MODE=1 \
    start_daemon "${config_path}" "${stdout_path}"
  )"
  wait_for_health "${chosen_port}"
  printf '%s %s %s %s %s %s\n' "${daemon_pid}" "${chosen_port}" "${config_path}" "${log_path}" "${socket_path}" "${alert_log_path}"
}

availability_start_live_daemon() {
  local temp_dir="$1"
  local threshold="${2:-0.7}"
  local monitored_syscalls_csv="${3:-connect}"
  local ring_buffer_pages="${4:-256}"
  local window_duration_secs="${5:-30}"
  local chosen_port="${6:-$(fixture_find_free_port)}"
  local config_path="${temp_dir}/config.toml"
  local stdout_path="${temp_dir}/stdout.log"
  local log_path="${temp_dir}/logs/daemon.log"
  local socket_path="${temp_dir}/api.sock"
  local alert_log_path="${temp_dir}/logs/alerts.jsonl"
  local monitored_syscalls_toml

  availability_require_live_probe_mode
  monitored_syscalls_toml="$(availability_toml_array_from_csv "${monitored_syscalls_csv}")"
  write_config "${config_path}" "${FIXTURE_DEFAULT_MODEL}" "${threshold}" "${chosen_port}"
  cat >>"${config_path}" <<EOF
monitored_syscalls = ${monitored_syscalls_toml}
ring_buffer_size_pages = ${ring_buffer_pages}
window_duration_secs = ${window_duration_secs}
enable_tui = false
enable_web = true
EOF
  local daemon_pid
  daemon_pid="$(
    MINI_EDR_API_SOCKET="${socket_path}" \
    start_daemon "${config_path}" "${stdout_path}"
  )"
  wait_for_health "${chosen_port}"
  printf '%s %s %s %s %s %s\n' "${daemon_pid}" "${chosen_port}" "${config_path}" "${log_path}" "${socket_path}" "${alert_log_path}"
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

availability_health_json_socket() {
  local socket_path="$1"
  curl --unix-socket "${socket_path}" -fsS "http://localhost/health"
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

availability_compile_connect_helper() {
  local output_path="$1"
  rustc --edition=2024 "${PERF_CONNECT_LATENCY_SOURCE}" -O -o "${output_path}"
}

availability_compile_connect_load_helper() {
  local output_path="$1"
  rustc --edition=2024 "${PERF_CONNECT_LOAD_SOURCE}" -O -o "${output_path}"
}
