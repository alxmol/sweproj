#!/usr/bin/env bash
# fixture_runtime_lib.sh — shared helpers for the malicious/benign fixture
# suites that exercise the detection daemon through its localhost predict and
# alert-stream surfaces.
#
# These helpers therefore:
#   1. launch an isolated localhost daemon instance against the trained ONNX,
#   2. materialize synthetic FeatureVector JSON for each named workload, and
#   3. subscribe to `/alerts/stream` so the suites can correlate real emitted
#      alerts by PID ancestry or fixture binary path instead of treating
#      `/internal/predict.would_alert` as a proxy.

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

fixture_start_alert_stream() {
  local socket_path="$1"
  local capture_path="$2"
  : >"${capture_path}"
  curl --unix-socket "${socket_path}" -N "http://localhost/alerts/stream" >"${capture_path}" 2>/dev/null &
  local stream_pid="$!"
  # The harness subscribes before issuing a prediction so the capture reflects
  # live NDJSON delivery, not a later replay of already-persisted alerts.
  sleep 0.1
  printf '%s\n' "${stream_pid}"
}

fixture_stop_alert_stream() {
  local stream_pid="$1"
  if kill -0 "${stream_pid}" >/dev/null 2>&1; then
    kill -TERM "${stream_pid}" >/dev/null 2>&1 || true
    wait "${stream_pid}" >/dev/null 2>&1 || true
  fi
}

fixture_stream_line_count() {
  local capture_path="$1"
  if [[ ! -f "${capture_path}" ]]; then
    echo 0
    return 0
  fi
  wc -l <"${capture_path}" | tr -d '[:space:]'
}

fixture_correlated_alerts_since() {
  local capture_path="$1"
  local expected_binary_path="$2"
  local expected_pid="$3"
  local start_line="$4"
  "${FIXTURE_PYTHON_BIN}" - "${capture_path}" "${expected_binary_path}" "${expected_pid}" "${start_line}" <<'PY'
import json
import sys
from pathlib import Path

capture_path = Path(sys.argv[1])
expected_binary_path = sys.argv[2]
expected_pid = int(sys.argv[3])
start_line = int(sys.argv[4])
lines = capture_path.read_text(encoding="utf-8").splitlines() if capture_path.exists() else []
matches = []
for line_number, line in enumerate(lines[start_line:], start=start_line + 1):
    if not line.strip():
        continue
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        # The stream file is written by a live curl process, so the last line
        # can be mid-write when the harness polls. Ignore partial JSON until
        # the next pass instead of treating it as a failed correlation.
        continue
    ancestry_chain = payload.get("ancestry_chain") or []
    ancestry_pids = {
        entry.get("pid")
        for entry in ancestry_chain
        if isinstance(entry, dict) and isinstance(entry.get("pid"), int)
    }
    correlation_modes = []
    if payload.get("pid") == expected_pid or expected_pid in ancestry_pids:
        correlation_modes.append("pid_ancestry")
    if payload.get("binary_path") == expected_binary_path:
        correlation_modes.append("binary_path")
    if correlation_modes:
        matches.append(
            {
                "line_number": line_number,
                "correlation_modes": correlation_modes,
                "alert": payload,
            }
        )
print(json.dumps(matches, separators=(",", ":")))
PY
}

fixture_wait_for_correlated_alerts() {
  local capture_path="$1"
  local expected_binary_path="$2"
  local expected_pid="$3"
  local start_line="$4"
  local timeout_seconds="${5:-2}"
  local deadline
  deadline="$("${FIXTURE_PYTHON_BIN}" - "${timeout_seconds}" <<'PY'
import sys
import time
print(time.time() + float(sys.argv[1]))
PY
)"

  while true; do
    local matches_json
    matches_json="$(fixture_correlated_alerts_since "${capture_path}" "${expected_binary_path}" "${expected_pid}" "${start_line}")"
    if "${FIXTURE_PYTHON_BIN}" - "${matches_json}" <<'PY'
import json
import sys

raise SystemExit(0 if len(json.loads(sys.argv[1])) > 0 else 1)
PY
    then
      printf '%s\n' "${matches_json}"
      return 0
    fi
    local now
    now="$("${FIXTURE_PYTHON_BIN}" - <<'PY'
import time
print(time.time())
PY
)"
    if "${FIXTURE_PYTHON_BIN}" - "${now}" "${deadline}" <<'PY'
import sys
raise SystemExit(0 if float(sys.argv[1]) < float(sys.argv[2]) else 1)
PY
    then
      sleep 0.05
    else
      printf '[]\n'
      return 1
    fi
  done
}

fixture_start_isolated_daemon() {
  local temp_dir="$1"
  local threshold="${2:-0.7}"
  local port="${3:-}"
  local chosen_port="${port:-$(fixture_find_free_port)}"
  local config_path="${temp_dir}/config.toml"
  local log_path="${temp_dir}/daemon.log"
  local socket_path="${temp_dir}/api.sock"

  fixture_require_release_daemon
  fixture_require_model_artifact
  write_config "${config_path}" "${FIXTURE_DEFAULT_MODEL}" "${threshold}" "${chosen_port}"
  local daemon_pid
  daemon_pid="$(MINI_EDR_API_SOCKET="${socket_path}" start_daemon "${config_path}" "${log_path}")"
  wait_for_health "${chosen_port}"
  printf '%s %s %s %s %s\n' "${daemon_pid}" "${chosen_port}" "${config_path}" "${log_path}" "${socket_path}"
}
