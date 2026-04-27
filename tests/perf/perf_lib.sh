#!/usr/bin/env bash
# perf_lib.sh — shared helpers for system-integration performance harnesses.
#
# These helpers intentionally support two execution modes:
# 1. unprivileged synthetic mode via the Rust `perf_harness` example, and
# 2. privileged live-probe mode when the caller has root or the daemon binary
#    already carries CAP_BPF + CAP_PERFMON.
#
# The shell wrappers record which mode they used in their JSON summaries so the
# evidence stays honest about whether the measurement exercised the live sensor
# path or the synthetic userland fallback.

set -euo pipefail

PERF_REPO_ROOT="/home/alexm/mini-edr"
PERF_HARNESS_BIN="${PERF_REPO_ROOT}/target/release/examples/perf_harness"
PERF_DAEMON_BIN="${PERF_REPO_ROOT}/target/release/mini-edr-daemon"
PERF_BPFTOOL_BIN="${BPFTOOL_BIN:-/usr/lib/linux-tools/6.8.0-110-generic/bpftool}"

perf_build_release_artifacts() {
  cargo build --release -p mini-edr-daemon --example perf_harness --manifest-path "${PERF_REPO_ROOT}/Cargo.toml" >/dev/null
  cargo build --release -p mini-edr-daemon --manifest-path "${PERF_REPO_ROOT}/Cargo.toml" >/dev/null
}

perf_require_harness() {
  if [[ ! -x "${PERF_HARNESS_BIN}" ]]; then
    perf_build_release_artifacts
  fi
}

perf_live_probe_mode_available() {
  if [[ ${EUID} -eq 0 ]]; then
    return 0
  fi
  local caps_line
  caps_line="$(getcap "${PERF_DAEMON_BIN}" 2>/dev/null || true)"
  [[ -n "${caps_line}" ]] \
    && echo "${caps_line}" | grep -q 'cap_bpf' \
    && echo "${caps_line}" | grep -q 'cap_perfmon'
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
  mkdir -p "${state_dir}"
  cat >"${config_path}" <<EOF
alert_threshold = 0.7
web_port = ${port}
model_path = "${PERF_REPO_ROOT}/training/output/model.onnx"
log_file_path = "${state_dir}/alerts.jsonl"
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
