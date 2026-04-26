#!/usr/bin/env bash
# Shared helpers for the daemon JSON-log integration fixtures.
#
# These scripts exercise the release daemon as an operator would: write a temp
# config, launch the binary on a localhost test port, drive `/internal/predict`,
# and inspect the append-only alert, inference, and operational logs.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/fixture_runtime_lib.sh"

JSON_LOG_REPO_ROOT="/home/alexm/mini-edr"
JSON_LOG_DAEMON_BIN="${JSON_LOG_REPO_ROOT}/target/release/mini-edr-daemon"
JSON_LOG_MODEL_PATH="${JSON_LOG_REPO_ROOT}/training/output/model.onnx"

json_log_write_config() {
  local config_path="$1"
  local port="$2"
  local threshold="${3:-0.0}"
  cat >"${config_path}" <<EOF
alert_threshold = ${threshold}
web_port = ${port}
model_path = "${JSON_LOG_MODEL_PATH}"
log_file_path = "alerts.jsonl"
EOF
}

json_log_start_daemon() {
  local temp_dir="$1"
  local threshold="${2:-0.0}"
  local port="${3:-$(fixture_find_free_port)}"
  local config_path="${temp_dir}/config.toml"
  local daemon_stdout="${temp_dir}/daemon.stdout.log"

  fixture_require_release_daemon
  fixture_require_model_artifact
  json_log_write_config "${config_path}" "${port}" "${threshold}"
  local daemon_pid
  daemon_pid="$(start_daemon "${config_path}" "${daemon_stdout}")"
  wait_for_health "${port}"
  printf '%s %s %s %s\n' "${daemon_pid}" "${port}" "${config_path}" "${daemon_stdout}"
}

json_log_predict_n() {
  local port="$1"
  local count="$2"
  for _ in $(seq 1 "${count}"); do
    sample_feature_vector_json | predict_json "${port}" >/dev/null
  done
}
