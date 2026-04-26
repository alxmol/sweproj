#!/usr/bin/env bash
# fixture_runtime_lib.sh — shared helpers for the malicious/benign fixture
# suites that exercise the detection daemon through its localhost predict
# surface.
#
# The current milestone daemon exposes `/internal/predict` before the later
# alert-stream API exists. These helpers therefore:
#   1. launch an isolated localhost daemon instance against the trained ONNX,
#   2. materialize synthetic FeatureVector JSON for each named workload, and
#   3. score those vectors through the daemon so the suites can record
#      alert/no-alert outcomes in a stable JSONL format.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/hot_reload_lib.sh"

FIXTURE_REPO_ROOT="/home/alexm/mini-edr"
FIXTURE_DAEMON_BIN="${FIXTURE_REPO_ROOT}/target/release/mini-edr-daemon"
FIXTURE_VECTOR_HELPER="${FIXTURE_REPO_ROOT}/tests/fixtures/feature_vectors.py"
FIXTURE_DEFAULT_MODEL="${FIXTURE_REPO_ROOT}/training/output/model.onnx"
FIXTURE_PYTHON_BIN="${FIXTURE_REPO_ROOT}/crates/mini-edr-detection/training/.venv/bin/python"

fixture_require_release_daemon() {
  if [[ ! -x "${FIXTURE_DAEMON_BIN}" ]]; then
    echo "missing release daemon binary at ${FIXTURE_DAEMON_BIN}; run cargo build --release first" >&2
    return 1
  fi
}

fixture_require_model_artifact() {
  if [[ ! -f "${FIXTURE_DEFAULT_MODEL}" ]]; then
    echo "missing trained ONNX model at ${FIXTURE_DEFAULT_MODEL}; run make train first" >&2
    return 1
  fi
}

fixture_find_free_port() {
  "${FIXTURE_PYTHON_BIN}" - <<'PY'
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

fixture_vector_json() {
  local fixture_name="$1"
  local pid="$2"
  local window_hours="${3:-6}"
  "${FIXTURE_PYTHON_BIN}" "${FIXTURE_VECTOR_HELPER}" "${fixture_name}" --pid "${pid}" --window-hours "${window_hours}"
}

fixture_submit_vector() {
  local fixture_name="$1"
  local daemon_port="$2"
  local pid="$3"
  local window_hours="${4:-6}"
  fixture_vector_json "${fixture_name}" "${pid}" "${window_hours}" | predict_json "${daemon_port}"
}

fixture_json_get() {
  local json_payload="$1"
  local key="$2"
  "${FIXTURE_PYTHON_BIN}" - "${json_payload}" "${key}" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
value = payload
for segment in sys.argv[2].split('.'):
    value = value[segment]
if isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

fixture_pretty_print_summary() {
  local summary_path="$1"
  "${FIXTURE_PYTHON_BIN}" - "${summary_path}" <<'PY'
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(json.dumps(summary, indent=2, sort_keys=True))
PY
}

fixture_start_isolated_daemon() {
  local temp_dir="$1"
  local threshold="${2:-0.7}"
  local port="${3:-}"
  local chosen_port="${port:-$(fixture_find_free_port)}"
  local config_path="${temp_dir}/config.toml"
  local log_path="${temp_dir}/daemon.log"

  fixture_require_release_daemon
  fixture_require_model_artifact
  write_config "${config_path}" "${FIXTURE_DEFAULT_MODEL}" "${threshold}" "${chosen_port}"
  local daemon_pid
  daemon_pid="$(start_daemon "${config_path}" "${log_path}")"
  wait_for_health "${chosen_port}"
  printf '%s %s %s %s\n' "${daemon_pid}" "${chosen_port}" "${config_path}" "${log_path}"
}
