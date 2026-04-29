#!/usr/bin/env bash
# perf_lib.sh — shared helpers for system-integration performance harnesses.
#
# The performance gate now has two distinct responsibilities:
# 1. keep the historical `perf_harness` synthetic path available for the
#    criterion-style microbenchmarks that still matter for offline profiling, and
# 2. provide reusable primitives for the real-daemon privileged harnesses that
#    exercise live eBPF probes, the userspace pairer, the pipeline, and the
#    detection runtime end-to-end.
#
# The helpers below therefore separate "build the synthetic harness" from
# "prepare a live daemon run" so each shell wrapper can honestly report which
# contract path it exercised.

set -euo pipefail

PERF_REPO_ROOT="/home/directory/mini-edr"
PERF_HARNESS_BIN="${PERF_REPO_ROOT}/target/release/examples/perf_harness"
PERF_DAEMON_BIN="${PERF_REPO_ROOT}/target/release/mini-edr-daemon"
PERF_BPFTOOL_BIN="${BPFTOOL_BIN:-/usr/lib/linux-tools/6.8.0-110-generic/bpftool}"
PERF_CONNECT_LATENCY_SOURCE="${PERF_REPO_ROOT}/tests/perf/live_connect_latency.rs"
PERF_CONNECT_LOAD_SOURCE="${PERF_REPO_ROOT}/tests/perf/live_connect_load.rs"

perf_build_release_artifacts() {
  cargo build --release -p mini-edr-daemon --example perf_harness --manifest-path "${PERF_REPO_ROOT}/Cargo.toml" >/dev/null
  cargo build --release -p mini-edr-daemon --manifest-path "${PERF_REPO_ROOT}/Cargo.toml" >/dev/null
}

perf_require_release_daemon() {
  if [[ ! -x "${PERF_DAEMON_BIN}" ]]; then
    cargo build --release -p mini-edr-daemon --manifest-path "${PERF_REPO_ROOT}/Cargo.toml" >/dev/null
  fi
}

perf_require_harness() {
  if [[ ! -x "${PERF_HARNESS_BIN}" ]]; then
    perf_build_release_artifacts
  fi
}

perf_compile_helper() {
  local source_path="$1"
  local output_path="$2"
  rustc --edition=2024 "${source_path}" -O -o "${output_path}"
}

perf_live_probe_mode_available() {
  if [[ ${EUID} -eq 0 ]]; then
    return 0
  fi
  local caps_line
  caps_line="$(getcap "${PERF_DAEMON_BIN}" 2>/dev/null || true)"
  [[ -n "${caps_line}" ]] \
    && echo "${caps_line}" | grep -q 'cap_bpf' \
    && echo "${caps_line}" | grep -q 'cap_perfmon' \
    && echo "${caps_line}" | grep -q 'cap_sys_admin' \
    && echo "${caps_line}" | grep -q 'cap_dac_read_search'
}

perf_count_lines() {
  local file_path="$1"
  if [[ ! -f "${file_path}" ]]; then
    echo 0
    return 0
  fi
  wc -l <"${file_path}" | tr -d '[:space:]'
}

perf_cleanup_temp_dir() {
  local temp_dir="$1"
  if [[ ! -d "${temp_dir}" ]]; then
    return 0
  fi

  # The mission currently forbids `sudo rm -rf`, so privileged harnesses leave
  # their `/tmp/mini-edr-*` workdirs behind as user-owned artifacts for the
  # orchestrator to sweep later. Non-privileged development runs can still
  # remove their own temporary directories normally.
  if [[ ${EUID} -eq 0 ]]; then
    if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
      chown -R "${SUDO_UID}:${SUDO_GID}" "${temp_dir}" 2>/dev/null || true
    fi
    echo "leaving ${temp_dir} on disk because privileged rm -rf is temporarily disallowed" >&2
  else
    rm -rf "${temp_dir}"
  fi
}

perf_stop_pid() {
  local pid="${1:-}"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    kill -TERM "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
  fi
}

perf_sweep_daemons() {
  if pgrep -x mini-edr-daemon >/dev/null 2>&1; then
    if [[ ${EUID} -eq 0 ]]; then
      pgrep -x mini-edr-daemon | xargs -r kill -TERM >/dev/null 2>&1 || true
    else
      pgrep -x mini-edr-daemon | xargs -r sudo kill -TERM >/dev/null 2>&1 || true
    fi
    sleep 3
  fi

  if pgrep -x mini-edr-daemon >/dev/null 2>&1; then
    if [[ ${EUID} -eq 0 ]]; then
      pgrep -x mini-edr-daemon | xargs -r kill -KILL >/dev/null 2>&1 || true
    else
      pgrep -x mini-edr-daemon | xargs -r sudo kill -KILL >/dev/null 2>&1 || true
    fi
    sleep 1
  fi
}

perf_health_json() {
  local socket_path="$1"
  curl --unix-socket "${socket_path}" -fsS http://localhost/health
}

perf_wait_for_alert_by_pid() {
  local alert_log_path="$1"
  local expected_pid="$2"
  local start_line="$3"
  local timeout_seconds="$4"
  local output_path="$5"
  python3 - "${alert_log_path}" "${expected_pid}" "${start_line}" "${timeout_seconds}" "${output_path}" <<'PY'
import json
import sys
import time
from pathlib import Path

alert_log_path = Path(sys.argv[1])
expected_pid = int(sys.argv[2])
start_line = int(sys.argv[3])
timeout_seconds = float(sys.argv[4])
output_path = Path(sys.argv[5])
deadline = time.time() + timeout_seconds

while time.time() < deadline:
    if alert_log_path.exists():
        lines = alert_log_path.read_text(encoding="utf-8").splitlines()
        for line_number, line in enumerate(lines[start_line:], start=start_line + 1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                # Live alert streams can leave a trailing partial write while
                # the daemon is still flushing the current line. Poll again
                # instead of treating an incomplete final line as a failure.
                continue
            if payload.get("pid") == expected_pid:
                payload["line_number"] = line_number
                output_path.write_text(
                    json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                raise SystemExit(0)
    time.sleep(0.05)

raise SystemExit(1)
PY
}

perf_read_cpu_ticks() {
  local pid="$1"
  awk '{print $14 + $15}' "/proc/${pid}/stat"
}

perf_find_free_port() {
  python3 - <<'PY'
import socket

for port in range(8081, 8100):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            continue
        print(port)
        break
else:
    raise SystemExit("no free localhost port in 8081-8099")
PY
}

perf_wait_for_health_socket() {
  local socket_path="$1"
  for _ in $(seq 1 100); do
    if curl --unix-socket "${socket_path}" -fsS http://localhost/health >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "daemon health endpoint never became ready on ${socket_path}" >&2
  return 1
}

perf_write_live_config() {
  local config_path="$1"
  local state_dir="$2"
  local port="$3"
  local threshold="${4:-0.7}"
  # The daemon validates `log_file_path` to live under <config_parent>/logs/
  # (per parse_startup_config in mini-edr-daemon::lib::parse_startup_config). The
  # perf harnesses pass an arbitrary state_dir, so we materialize the matching
  # logs/ sibling next to the config and place alerts.jsonl there. state_dir is
  # used for the alert_id sequence file and other runtime state per the daemon's
  # config schema.
  mkdir -p "${state_dir}"
  local config_parent
  config_parent="$(dirname "${config_path}")"
  local log_dir="${config_parent}/logs"
  mkdir -p "${log_dir}"
  cat >"${config_path}" <<EOF
alert_threshold = ${threshold}
web_port = ${port}
model_path = "${PERF_REPO_ROOT}/training/output/model.onnx"
log_file_path = "${log_dir}/alerts.jsonl"
state_dir = "${state_dir}"
enable_tui = false
enable_web = false
EOF
}

perf_average_top_cpu() {
  local pid="$1"
  local samples="$2"
  top -b -d 1 -n "${samples}" -p "${pid}" \
    | awk -v pid="${pid}" '$1 == pid {sum += $9; count += 1} END {if (count == 0) {print 0} else {printf "%.6f\n", sum / count}}'
}

perf_sample_rss_bytes() {
  local pid="$1"
  awk '/^VmRSS:/ {print $2 * 1024}' "/proc/${pid}/status"
}

perf_write_json() {
  local output_path="$1"
  local payload="$2"
  mkdir -p "$(dirname "${output_path}")"
  printf '%s\n' "${payload}" >"${output_path}"
}
