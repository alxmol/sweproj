#!/usr/bin/env bash
# Shared helpers for the detection hot-reload integration fixtures.
#
# The scripts in this directory intentionally exercise the daemon as an
# operator would: write a config, launch the release binary, mutate the model
# on disk, send `SIGHUP`, and inspect the localhost JSON surfaces.

set -euo pipefail

REPO_ROOT="/home/directory/mini-edr"
DAEMON_BIN="${REPO_ROOT}/target/release/mini-edr-daemon"
PYTHON_BIN="${REPO_ROOT}/crates/mini-edr-detection/training/.venv/bin/python"
MODEL_SOURCE="${REPO_ROOT}/training/output/model.onnx"

write_config() {
  local config_path="$1"
  local model_path="$2"
  local threshold="$3"
  local port="$4"
  local log_directory
  local log_file_path
  local state_directory
  # Keep the daemon's append-only JSON sinks beside the per-run temp config so
  # hot-reload fixture throughput is measured against isolated temporary files
  # instead of the repository root. The alert-id sequence file lives in a
  # sibling `state/` directory so SIGUSR1 reopen failures on the alert target
  # do not block alert-ID persistence.
  log_directory="$(dirname "${config_path}")/logs"
  state_directory="$(dirname "${config_path}")/state"
  mkdir -p "${log_directory}"
  mkdir -p "${state_directory}"
  log_file_path="${log_directory}/alerts.jsonl"
  cat >"${config_path}" <<EOF
alert_threshold = ${threshold}
web_port = ${port}
model_path = "${model_path}"
log_file_path = "${log_file_path}"
state_dir = "${state_directory}"
EOF
}

mutate_model_v2() {
  local source_path="$1"
  local destination_path="$2"
  "${PYTHON_BIN}" - "$source_path" "$destination_path" <<'PY'
import sys
import onnx

source_path, destination_path = sys.argv[1:3]
model = onnx.load(source_path)
model.producer_name = "mini-edr-hot-reload-v2"
onnx.save(model, destination_path)
PY
}

wait_for_health() {
  local port="$1"
  local url="http://127.0.0.1:${port}/api/health"
  for _ in $(seq 1 100); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.05
  done
  echo "daemon health endpoint never became ready on :${port}" >&2
  return 1
}

health_json() {
  local port="$1"
  curl -fsS "http://127.0.0.1:${port}/api/health"
}

predict_json() {
  local port="$1"
  curl -fsS \
    -H 'content-type: application/json' \
    -d @- \
    "http://127.0.0.1:${port}/internal/predict"
}

sample_feature_vector_json() {
  cat <<'EOF'
{"pid":4242,"window_start_ns":1713000000000000000,"window_end_ns":1713000005000000000,"total_syscalls":128,"execve_count":1,"openat_count":100,"connect_count":3,"clone_count":2,"execve_ratio":0.0078125,"openat_ratio":0.78125,"connect_ratio":0.0234375,"clone_ratio":0.015625,"bigrams":{"__process_positive_rate__":0.65,"__event_positive_rate__":0.15},"trigrams":{"__path_positive_rate__":0.35},"path_entropy":1.5,"unique_ips":2,"unique_files":12,"child_spawn_count":2,"avg_inter_syscall_time_ns":1500000.0,"min_inter_syscall_time_ns":10000.0,"max_inter_syscall_time_ns":9000000.0,"stddev_inter_syscall_time_ns":500000.0,"wrote_etc":true,"wrote_tmp":true,"wrote_dev":false,"read_sensitive_file_count":4,"write_sensitive_file_count":2,"outbound_connection_count":3,"loopback_connection_count":1,"distinct_ports":2,"failed_syscall_count":1,"short_lived":false,"window_duration_ns":5000000000,"events_per_second":25.6}
EOF
}

start_daemon() {
  local config_path="$1"
  local log_path="$2"
  "${DAEMON_BIN}" --config "${config_path}" >"${log_path}" 2>&1 &
  echo $!
}

cleanup_daemon() {
  local pid="$1"
  if kill -0 "${pid}" >/dev/null 2>&1; then
    kill -TERM "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
  fi
}
