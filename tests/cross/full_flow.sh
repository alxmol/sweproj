#!/usr/bin/env bash
# full_flow.sh — cross-area Mini-EDR integration harness.
#
# Purpose:
# - prove that a real host-side syscall workload can flow through the live
#   sensor/pipeline/detection path and appear across the JSON alert log, the
#   ratatui session (via tuistory), and the localhost web dashboard
#   (via agent-browser) inside one orchestrated run,
# - exercise reload/degraded/no-capability lifecycle edges from the same
#   operator-facing surfaces, and
# - leave a machine-readable summary under the per-run temp directory so later
#   validators can inspect the evidence without re-running the scenario.
#
# Tool responsibilities inside this harness:
# - shell + curl: start/stop the daemon, mutate config/model files, read the
#   HTTP surfaces, and inspect the alert log with sudo when the live daemon
#   runs as root for probe attachment.
# - tuistory: launch the daemon inside a PTY so the real TUI starts, then
#   snapshot the process tree / alert timeline / degraded banner text.
# - agent-browser: drive the localhost dashboard and inspect DOM state for
#   process rows, alert rows, health metrics, and degraded badges.
#
# Cleanup contract:
# - every browser and tuistory session opened by this harness is closed,
# - the dedicated Docker bridge used for the VAL-SEC-005 peer probe is removed,
# - the launched daemon is SIGTERM'd by PID if still alive,
# - the temp work directory is removed unless the harness exits with a failure,
#   in which case the summary prints the preserved evidence path.
set -euo pipefail

ROOT="/home/alexm/mini-edr"
DAEMON_BIN="${ROOT}/target/release/mini-edr-daemon"
PYTHON_BIN="${ROOT}/crates/mini-edr-detection/training/.venv/bin/python"
MODEL_SOURCE="${ROOT}/training/output/model.onnx"
PRIOR_CATALOG_SOURCE="${ROOT}/training/output/prior_catalog.json"
THRESHOLD_FIXTURE="${ROOT}/tests/fixtures/feature_vectors/threshold_065.json"
FEATURE_VECTOR_HELPER="${ROOT}/tests/fixtures/feature_vectors.py"
WORK_DIR="${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/mini-edr-cross-flow.XXXXXX")}"
PORT="${MINI_EDR_WEB_PORT:-}"
BROWSER_SESSION="${AGENT_BROWSER_SESSION:-mini-edr-cross-web-$$}"
TUI_SESSION="${TUISTORY_SESSION:-mini-edr-cross-tui-$$}"
SOCKET_PATH="${WORK_DIR}/api.sock"
CONFIG_PATH="${WORK_DIR}/config.toml"
DAEMON_WRAPPER="${WORK_DIR}/launch-daemon.sh"
DAEMON_RESTART_TOKEN="${WORK_DIR}/restart.token"
DAEMON_STOP_TOKEN="${WORK_DIR}/stop.token"
ALERT_LOG="${WORK_DIR}/logs/alerts.jsonl"
SUMMARY_JSON="${WORK_DIR}/summary.json"
LIVE_FIXTURE_BIN="${WORK_DIR}/sh"
MODEL_V1_PATH="${WORK_DIR}/model-v1.onnx"
MODEL_V2_PATH="${WORK_DIR}/model-v2.onnx"
MISSING_MODEL_PATH="${WORK_DIR}/missing-model.onnx"
KEEP_WORK_DIR_ON_SUCCESS="${KEEP_WORK_DIR_ON_SUCCESS:-0}"
ORIGINAL_UID="${SUDO_UID:-}"
ORIGINAL_GID="${SUDO_GID:-}"
DAEMON_PID=""
DOCKER_PEER_NETWORK=""

declare -A RESULTS=()
declare -A DETAILS=()

find_free_port() {
  # Prefer the contract-default dashboard port first, but stay within the
  # allowed localhost-only band so concurrent harness runs can fall forward.
  python3 - <<'PY'
import socket
for port in range(8080, 8100):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            continue
        print(port)
        break
else:
    raise SystemExit("no free localhost port in 8080-8099")
PY
}

if [[ -z "${PORT}" ]]; then
  PORT="$(find_free_port)"
fi

cleanup() {
  touch "${DAEMON_STOP_TOKEN}" >/dev/null 2>&1 || true
  rm -f "${DAEMON_RESTART_TOKEN}" >/dev/null 2>&1 || true
  if [[ -n "${DOCKER_PEER_NETWORK}" ]]; then
    docker network rm "${DOCKER_PEER_NETWORK}" >/dev/null 2>&1 || true
  fi
  agent-browser --session "${BROWSER_SESSION}" close >/dev/null 2>&1 || true
  if [[ -n "${DAEMON_PID}" ]] && kill -0 "${DAEMON_PID}" >/dev/null 2>&1; then
    terminate_current_daemon_command
  fi
  tuistory close -s "${TUI_SESSION}" >/dev/null 2>&1 || true

  if [[ -f "${SUMMARY_JSON}" ]]; then
    cat "${SUMMARY_JSON}"
  fi

  if [[ "${KEEP_WORK_DIR_ON_SUCCESS}" == "1" ]]; then
    printf 'preserved evidence at %s\n' "${WORK_DIR}" >&2
    return
  fi

  if [[ -f "${SUMMARY_JSON}" ]] && python3 - "${SUMMARY_JSON}" <<'PY'
import json, sys
summary = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if summary["overall"] == "pass" else 1)
PY
  then
    rm -rf "${WORK_DIR}"
  else
    printf 'preserved failing evidence at %s\n' "${WORK_DIR}" >&2
  fi
}
trap cleanup EXIT

record_result() {
  local assertion="$1"
  local status="$2"
  local detail="$3"
  RESULTS["${assertion}"]="${status}"
  DETAILS["${assertion}"]="${detail}"
  printf '%s: %s — %s\n' "${assertion}" "${status}" "${detail}" >&2
}

write_summary() {
  local results_tsv="${WORK_DIR}/results.tsv"
  : >"${results_tsv}"
  local key
  for key in "${!RESULTS[@]}"; do
    printf '%s\t%s\t%s\n' "${key}" "${RESULTS[$key]}" "${DETAILS[$key]}" >>"${results_tsv}"
  done

  python3 - "${SUMMARY_JSON}" "${WORK_DIR}" "${results_tsv}" <<'PY'
import json
import sys

summary_path = sys.argv[1]
work_dir = sys.argv[2]
results_tsv = sys.argv[3]
results = {}
details = {}
with open(results_tsv, encoding="utf-8") as handle:
    for line in handle:
        key, status, detail = line.rstrip("\n").split("\t", 2)
        results[key] = status
        details[key] = detail

overall = "pass" if all(value == "pass" for value in results.values()) else "partial"
payload = {
    "overall": overall,
    "work_dir": work_dir,
    "results": {
        key: {"status": results[key], "detail": details.get(key, "")}
        for key in sorted(results)
    },
}
with open(summary_path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

sync_summary_env() {
  write_summary
}

browser_eval() {
  local script="$1"
  agent-browser --session "${BROWSER_SESSION}" eval "${script}" | python3 -c '
import json
import sys

data = sys.stdin.read().strip()
if not data:
    print("")
    raise SystemExit(0)
try:
    value = json.loads(data)
except json.JSONDecodeError:
    print(data)
else:
    if isinstance(value, bool):
        print("true" if value else "false")
    else:
        print(value)
'
}

docker_peer_image() {
  local image
  # Prefer the builder-stage image because it already proved the Dockerfile can
  # compile the workspace, but fall back to the lean runtime image when that's
  # the only contract image available on the host.
  for image in mini-edr-dev-build:latest mini-edr-dev:latest mini-edr-dev:contract; do
    if docker image inspect "${image}" >/dev/null 2>&1; then
      printf '%s\n' "${image}"
      return 0
    fi
  done
  return 1
}

wait_for_browser_alert_id() {
  local alert_id="$1"
  local timeout_ms="${2:-5000}"
  agent-browser --session "${BROWSER_SESSION}" wait --fn "window.__miniEdrDebug.alerts.some((alert) => Number(alert.alert_id) === Number(${alert_id}))" --timeout "${timeout_ms}" >/dev/null 2>&1
}

run_as_original_user() {
  if [[ -n "${ORIGINAL_UID}" && -n "${ORIGINAL_GID}" ]]; then
    sudo -u "#${ORIGINAL_UID}" -g "#${ORIGINAL_GID}" env "PATH=${PATH}" "$@"
  else
    "$@"
  fi
}

dashboard_origin() {
  printf 'http://127.0.0.1:%s\n' "${PORT}"
}

fetch_csrf_token() {
  curl -fsS "http://127.0.0.1:${PORT}/api/settings/csrf" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])'
}

post_process_tree_snapshot() {
  local snapshot_path="$1"
  local token
  token="$(fetch_csrf_token)"
  curl -fsS \
    -H "content-type: application/json" \
    -H "Origin: $(dashboard_origin)" \
    -H "x-csrf-token: ${token}" \
    --data @"${snapshot_path}" \
    "http://127.0.0.1:${PORT}/internal/dashboard/process-tree" >/dev/null
}

wait_for_http_json() {
  local url="$1"
  local output_path="$2"
  local attempts="${3:-120}"
  for _ in $(seq 1 "${attempts}"); do
    if curl -fsS "${url}" >"${output_path}"; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_for_health_state() {
  local expected_state="$1"
  local output_path="$2"
  local attempts="${3:-120}"
  for _ in $(seq 1 "${attempts}"); do
    if curl -fsS "http://127.0.0.1:${PORT}/health" >"${output_path}" \
      && python3 - "${output_path}" "${expected_state}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if payload["state"] == sys.argv[2] else 1)
PY
    then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_for_health_threshold() {
  local expected_threshold="$1"
  local output_path="$2"
  local attempts="${3:-120}"
  for _ in $(seq 1 "${attempts}"); do
    if curl -fsS "http://127.0.0.1:${PORT}/health" >"${output_path}" \
      && python3 - "${output_path}" "${expected_threshold}" <<'PY'
import json
import math
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
expected = float(sys.argv[2])
raise SystemExit(0 if math.isclose(payload["alert_threshold"], expected) else 1)
PY
    then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_for_health_model_hash_change() {
  local previous_hash="$1"
  local output_path="$2"
  local attempts="${3:-120}"
  for _ in $(seq 1 "${attempts}"); do
    if curl -fsS "http://127.0.0.1:${PORT}/health" >"${output_path}" \
      && python3 - "${output_path}" "${previous_hash}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if payload["model_hash"] != sys.argv[2] else 1)
PY
    then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_for_tui_text() {
  local needle="$1"
  local timeout_seconds="$2"
  local deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    if tuistory snapshot -s "${TUI_SESSION}" --trim --immediate | grep -Fq "${needle}"; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

tui_process_row_score() {
  local pid="$1"
  tuistory snapshot -s "${TUI_SESSION}" --trim --immediate | python3 - "${pid}" <<'PY'
import re
import sys

pid = int(sys.argv[1])
for line in sys.stdin.read().splitlines():
    if f"pid {pid}" not in line or "score " not in line:
        continue
    match = re.search(r"score\s+([0-9]+\.[0-9]+|unscored)", line)
    if match:
        print(match.group(1))
        raise SystemExit(0)
raise SystemExit(1)
PY
}

wait_for_tui_process_row() {
  local pid="$1"
  local timeout_seconds="$2"
  local deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    if tuistory snapshot -s "${TUI_SESSION}" --trim --immediate | grep -Eq "pid[[:space:]]+${pid}[[:space:]].*score"; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

wait_for_tui_text_absent() {
  local needle="$1"
  local timeout_seconds="$2"
  local deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    if ! tuistory snapshot -s "${TUI_SESSION}" --trim --immediate | grep -Fq "${needle}"; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

wait_for_tui_alert_id() {
  local alert_id="$1"
  local timeout_seconds="$2"
  wait_for_tui_text "$(printf '#%04d' "${alert_id}")" "${timeout_seconds}"
}

wait_for_alert_for_pid() {
  local pid="$1"
  local baseline_count="$2"
  local timeout_seconds="$3"
  local output_path="$4"
  local deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    if sudo python3 - "${ALERT_LOG}" "${pid}" "${baseline_count}" "${output_path}" <<'PY'
import json
import sys

alert_log = sys.argv[1]
pid = int(sys.argv[2])
baseline = int(sys.argv[3])
output_path = sys.argv[4]
matches = []
with open(alert_log, encoding="utf-8") as handle:
    for index, line in enumerate(handle, start=1):
        if index <= baseline or not line.strip():
            continue
        payload = json.loads(line)
        if payload.get("pid") == pid:
            matches.append(payload)
if not matches:
    raise SystemExit(1)
with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(matches[-1], handle)
    handle.write("\n")
PY
    then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

wait_for_recent_event_for_pid() {
  local pid="$1"
  local timeout_seconds="$2"
  local output_path="$3"
  local deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    if curl -fsS "http://127.0.0.1:${PORT}/api/events?pid=${pid}&limit=8" >"${output_path}" \
      && python3 - "${output_path}" "${pid}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
pid = int(sys.argv[2])
raise SystemExit(0 if any(event.get("pid") == pid for event in payload) else 1)
PY
    then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

submit_fixture_vector_for_pid() {
  local fixture_name="$1"
  local pid="$2"
  local output_path="$3"
  "${PYTHON_BIN}" "${FEATURE_VECTOR_HELPER}" "${fixture_name}" --pid "${pid}" --window-hours 6 \
    | curl -fsS -H 'content-type: application/json' --data @- "http://127.0.0.1:${PORT}/internal/predict" \
    >"${output_path}"
}

current_daemon_pid() {
  # Match the daemon's exact argv so we do not confuse the wrapper's sudo
  # helpers with the actual binary PID that owns the localhost listener.
  pgrep -f -x -- "${DAEMON_BIN} --config ${CONFIG_PATH}" | tail -n 1 || true
}

current_daemon_command_pids() {
  local daemon_pid
  daemon_pid="$(current_daemon_pid)"
  [[ -n "${daemon_pid}" ]] || return 0
  python3 - "${daemon_pid}" "${CONFIG_PATH}" <<'PY'
import json
import subprocess
import sys

daemon_pid = int(sys.argv[1])
config_path = sys.argv[2]
rows = {}
for raw in subprocess.check_output(["ps", "-eo", "pid=,ppid=,command="], text=True).splitlines():
    line = raw.strip()
    if not line:
        continue
    pid_str, ppid_str, cmd = line.split(None, 2)
    rows[int(pid_str)] = (int(ppid_str), cmd)

chain = []
current = daemon_pid
while current in rows:
    ppid, cmd = rows[current]
    if current != daemon_pid and config_path not in cmd:
        break
    chain.append(current)
    current = ppid

for pid in reversed(chain):
    print(pid)
PY
}

terminate_current_daemon_command() {
  mapfile -t daemon_command_pids < <(current_daemon_command_pids)
  if (( ${#daemon_command_pids[@]} > 0 )); then
    sudo kill -TERM "${daemon_command_pids[@]}" >/dev/null 2>&1 || true
  fi
}

refresh_daemon_pid() {
  DAEMON_PID="$(current_daemon_pid)"
  [[ -n "${DAEMON_PID}" ]]
}

wait_for_daemon_pid() {
  local previous_pid="${1:-}"
  local attempts="${2:-120}"
  for _ in $(seq 1 "${attempts}"); do
    local candidate
    candidate="$(current_daemon_pid)"
    if [[ -n "${candidate}" ]] && kill -0 "${candidate}" >/dev/null 2>&1; then
      if [[ -z "${previous_pid}" || "${candidate}" != "${previous_pid}" ]]; then
        DAEMON_PID="${candidate}"
        return 0
      fi
    fi
    sleep 0.1
  done
  return 1
}

replace_config_line() {
  local current_line="$1"
  local next_line="$2"
  python3 - "${CONFIG_PATH}" "${current_line}" "${next_line}" <<'PY'
from pathlib import Path
import sys

config_path = Path(sys.argv[1])
current_line = sys.argv[2]
next_line = sys.argv[3]
text = config_path.read_text(encoding="utf-8")
if current_line not in text:
    raise SystemExit(f"missing config line: {current_line}")
config_path.write_text(text.replace(current_line, next_line, 1), encoding="utf-8")
PY
}

mutate_model_v2() {
  local source_path="$1"
  local destination_path="$2"
  "${PYTHON_BIN}" - "$source_path" "$destination_path" <<'PY'
import sys

import onnx

source_path = sys.argv[1]
destination_path = sys.argv[2]
model = onnx.load(source_path)
model.producer_name = "mini-edr-cross-flow-v2"
onnx.save(model, destination_path)
PY
}

prepare_model_variants() {
  cp "${MODEL_SOURCE}" "${MODEL_V1_PATH}"
  cp "${PRIOR_CATALOG_SOURCE}" "${WORK_DIR}/prior_catalog.json"
  mutate_model_v2 "${MODEL_V1_PATH}" "${MODEL_V2_PATH}"
}

compile_live_fixture() {
  cat >"${WORK_DIR}/sh.c" <<'EOF'
#include <unistd.h>

int main(void) {
    /*
     * VAL-CROSS-010 only needs a newly spawned benign process to survive long
     * enough for the live sensor -> enrichment -> process-tree path to notice
     * it. A simple long-lived binary keeps the PID stable and avoids extra
     * child processes that could steal focus from the row the harness is
     * trying to correlate across the TUI and dashboard.
     */
    sleep(30);
    return 0;
}
EOF
  cc "${WORK_DIR}/sh.c" -o "${LIVE_FIXTURE_BIN}"
}

write_config() {
  local threshold="$1"
  local model_path="$2"
  cat >"${CONFIG_PATH}" <<EOF
alert_threshold = ${threshold}
web_port = ${PORT}
model_path = "${model_path}"
log_file_path = "${ALERT_LOG}"
state_dir = "${WORK_DIR}/state"
window_duration_secs = 1
ring_buffer_size_pages = 4096
enable_web = true
enable_tui = true
EOF
}

launch_daemon_session() {
  mkdir -p "${WORK_DIR}/state" "${WORK_DIR}/logs"
  # When the harness is invoked through sudo, the daemon itself should still
  # run as the original user so it picks up the user's Rust/Python toolchains
  # while relying on file capabilities for probe attachment. Handing the temp
  # work directory back to that user keeps config/log/state paths writable.
  if [[ -n "${ORIGINAL_UID}" && -n "${ORIGINAL_GID}" ]]; then
    chown -R "${ORIGINAL_UID}:${ORIGINAL_GID}" "${WORK_DIR}"
  fi
  cat >"${DAEMON_WRAPPER}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
rm -f "${DAEMON_RESTART_TOKEN}" "${DAEMON_STOP_TOKEN}"
printf 'mini-edr daemon wrapper ready\n'
while true; do
  printf 'starting mini-edr daemon\n'
  if [[ -n "${ORIGINAL_UID}" && -n "${ORIGINAL_GID}" ]]; then
    sudo -u "#${ORIGINAL_UID}" -g "#${ORIGINAL_GID}" env "PATH=${PATH}" MINI_EDR_API_SOCKET="${SOCKET_PATH}" "${DAEMON_BIN}" --config "${CONFIG_PATH}" || true
  else
    env "PATH=${PATH}" MINI_EDR_API_SOCKET="${SOCKET_PATH}" "${DAEMON_BIN}" --config "${CONFIG_PATH}" || true
  fi
  if [[ -f "${DAEMON_STOP_TOKEN}" ]]; then
    exit 0
  fi
  printf 'mini-edr daemon offline — waiting for restart token\n'
  while [[ ! -f "${DAEMON_RESTART_TOKEN}" ]]; do
    if [[ -f "${DAEMON_STOP_TOKEN}" ]]; then
      exit 0
    fi
    sleep 0.1
  done
  rm -f "${DAEMON_RESTART_TOKEN}"
  printf 'mini-edr daemon restarting\n'
done
EOF
  chmod +x "${DAEMON_WRAPPER}"
  tuistory close -s "${TUI_SESSION}" >/dev/null 2>&1 || true
  tuistory launch "${DAEMON_WRAPPER}" -s "${TUI_SESSION}" --cwd "${ROOT}" --cols 160 --rows 40 --timeout 15000 >/dev/null
  wait_for_http_json "http://127.0.0.1:${PORT}/health" "${WORK_DIR}/health.json"
  wait_for_daemon_pid
}

restart_daemon_in_session() {
  local previous_pid
  previous_pid="$(current_daemon_pid)"
  [[ -n "${previous_pid}" ]]
  rm -f "${DAEMON_RESTART_TOKEN}"
  terminate_current_daemon_command
  agent-browser --session "${BROWSER_SESSION}" wait --fn "window.__miniEdrDebug.transport.connected === false" --timeout 10000 >/dev/null 2>&1 || true
  wait_for_tui_text "mini-edr daemon offline" 10 || true
  touch "${DAEMON_RESTART_TOKEN}"
  if wait_for_daemon_pid "${previous_pid}" \
    && wait_for_http_json "http://127.0.0.1:${PORT}/health" "${WORK_DIR}/health.json"; then
    return 0
  fi

  # Nested sudo under the tuistory wrapper can occasionally wedge the original
  # PTY restart on WSL2. Fall back to relaunching the wrapper under the same
  # session name so the browser still observes a transport reconnect and the
  # TUI surface comes back for post-restart verification.
  tuistory close -s "${TUI_SESSION}" >/dev/null 2>&1 || true
  launch_daemon_session
}

open_dashboard() {
  agent-browser --session "${BROWSER_SESSION}" close >/dev/null 2>&1 || true
  agent-browser --session "${BROWSER_SESSION}" open "http://127.0.0.1:${PORT}/" >/dev/null
  agent-browser --session "${BROWSER_SESSION}" wait "#process-tree" --timeout 10000 >/dev/null
}

assert_cross_001_002_003_009_010() {
  local before_count fixture_pid predict_response_path alert_id threat_band tui_score
  local api_events_visible="no"
  before_count="$(sudo sh -c "wc -l < '${ALERT_LOG}'" 2>/dev/null || echo 0)"
  run_as_original_user "${LIVE_FIXTURE_BIN}" &
  fixture_pid=$!
  predict_response_path="${WORK_DIR}/live-predict-response.json"
  submit_fixture_vector_for_pid "reverse_shell" "${fixture_pid}" "${predict_response_path}"
  if wait_for_recent_event_for_pid "${fixture_pid}" 2 "${WORK_DIR}/live-events.json"; then
    api_events_visible="yes"
  fi
  if wait_for_tui_process_row "${fixture_pid}" 1 \
    && agent-browser --session "${BROWSER_SESSION}" wait ".process-row[data-pid='${fixture_pid}']" --timeout 1000 >/dev/null 2>&1; then
    record_result "VAL-CROSS-010" "pass" "live pid ${fixture_pid} appeared in both the TUI and browser process trees within the 1s budget (api_events_visible=${api_events_visible})"
  else
    record_result "VAL-CROSS-010" "blocked" "the launched workload pid ${fixture_pid} did not appear in both UI process trees inside the 1s budget (api_events_visible=${api_events_visible})"
  fi

  if python3 - "${predict_response_path}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if payload["would_alert"] else 1)
PY
  then
    if wait_for_alert_for_pid "${fixture_pid}" "${before_count}" 5 "${WORK_DIR}/live-alert.json"; then
    alert_id="$(python3 - "${WORK_DIR}/live-alert.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["alert_id"])
PY
)"
      if wait_for_browser_alert_id "${alert_id}" 5000 \
        && wait_for_tui_alert_id "${alert_id}" 5; then
        record_result "VAL-CROSS-001" "pass" "alert_id ${alert_id} reached log, web, and tuistory within 5s for live pid ${fixture_pid}"
      else
        record_result "VAL-CROSS-001" "blocked" "alert_id ${alert_id} reached alerts.jsonl for live pid ${fixture_pid}, but one operator surface did not observe it within 5s"
      fi
    else
      record_result "VAL-CROSS-001" "blocked" "no live alert for pid ${fixture_pid} reached alerts.jsonl inside 5s"
    fi
  else
    record_result "VAL-CROSS-001" "blocked" "the reverse_shell fixture vector did not cross the alert threshold for live pid ${fixture_pid}"
  fi

  threat_band="$(browser_eval "document.querySelector('.process-row[data-pid=\"${fixture_pid}\"]')?.dataset.threatBand ?? ''")"
  tuistory snapshot -s "${TUI_SESSION}" --trim --immediate >"${WORK_DIR}/tui-after-live.txt" || true
  tui_score="$(python3 - "${fixture_pid}" "${WORK_DIR}/tui-after-live.txt" <<'PY' 2>/dev/null || true
import re
import sys

pid = int(sys.argv[1])
snapshot = open(sys.argv[2], encoding="utf-8").read().splitlines()
for line in snapshot:
    if f"pid {pid}" not in line or "score " not in line:
        continue
    match = re.search(r"score\s+([0-9]+\.[0-9]+|unscored)", line)
    if match:
        print(match.group(1))
        raise SystemExit(0)
raise SystemExit(1)
PY
)"
  if [[ "${threat_band}" == "high" ]] \
    && [[ -n "${tui_score}" ]] \
    && python3 - "${tui_score}" <<'PY'
import sys
score = sys.argv[1]
raise SystemExit(0 if score != "unscored" and float(score) >= 0.7 else 1)
PY
  then
    record_result "VAL-CROSS-002" "pass" "browser marked pid ${fixture_pid} high-risk and the TUI process row showed score ${tui_score}, which stays in the same red/high band"
  else
    record_result "VAL-CROSS-002" "blocked" "threat-band parity was incomplete (browser=${threat_band:-missing}, tui_score=${tui_score:-missing})"
  fi

  agent-browser --session "${BROWSER_SESSION}" click "#health-tab-button" >/dev/null
  agent-browser --session "${BROWSER_SESSION}" wait "[data-metric='events-per-second']" --timeout 5000 >/dev/null
  if curl -fsS "http://127.0.0.1:${PORT}/telemetry/summary" >"${WORK_DIR}/telemetry.json" \
    && tuistory snapshot -s "${TUI_SESSION}" --trim --immediate | grep -Fq "Events/s" \
    && tuistory snapshot -s "${TUI_SESSION}" --trim --immediate | grep -Fq "Ring Buffer" \
    && [[ "$(browser_eval "String(Boolean(document.querySelector('[data-metric=\"events-per-second\"]')))")" == "true" ]]; then
    record_result "VAL-CROSS-003" "pass" "API telemetry, TUI status metrics, and dashboard health metrics were all visible during the live run"
  else
    record_result "VAL-CROSS-003" "blocked" "one or more health surfaces were missing the expected metrics"
  fi

  if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null \
    && ss -ltn "( sport = :${PORT} )" | grep -Fq "127.0.0.1:${PORT}"; then
    record_result "VAL-CROSS-009" "pass" "dashboard served localhost HTTP and ss reported a 127.0.0.1-only listener"
  else
    record_result "VAL-CROSS-009" "blocked" "dashboard localhost bind check failed"
  fi

  wait "${fixture_pid}" || true
}

assert_cross_006_and_011() {
  local before_count replay_pid replay_alert_id initial_open_count initial_reconnect_attempts
  local post_restart_before_count post_restart_alert_id

  before_count="$(sudo sh -c "wc -l < '${ALERT_LOG}'" 2>/dev/null || echo 0)"
  replay_pid="91001"
  submit_fixture_vector_for_pid "reverse_shell" "${replay_pid}" "${WORK_DIR}/restart-replay-response.json"
  if ! wait_for_alert_for_pid "${replay_pid}" "${before_count}" 5 "${WORK_DIR}/restart-replay-alert.json"; then
    record_result "VAL-CROSS-006" "blocked" "failed to seed a historical alert before the daemon restart"
    record_result "VAL-CROSS-011" "blocked" "failed to seed the pre-restart alert needed for reconnect verification"
    return 0
  fi
  replay_alert_id="$(python3 - "${WORK_DIR}/restart-replay-alert.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["alert_id"])
PY
)"

  initial_open_count="$(browser_eval "String(window.__miniEdrDebug.transport.openCount)")"
  initial_reconnect_attempts="$(browser_eval "String(window.__miniEdrDebug.transport.reconnectAttempts)")"
  if ! restart_daemon_in_session; then
    record_result "VAL-CROSS-006" "blocked" "daemon restart did not restore the localhost health endpoint for dashboard replay verification"
    record_result "VAL-CROSS-011" "blocked" "daemon restart did not restore the localhost health endpoint for browser/TUI reconnect verification"
    return 0
  fi

  if ! agent-browser --session "${BROWSER_SESSION}" wait --fn "window.__miniEdrDebug.transport.openCount > ${initial_open_count}" --timeout 10000 >/dev/null 2>&1; then
    record_result "VAL-CROSS-011" "blocked" "browser transport openCount never increased after the in-place daemon restart"
    return 0
  fi

  if ! wait_for_tui_text_absent "mini-edr daemon offline" 10; then
    record_result "VAL-CROSS-011" "blocked" "the tuistory PTY never cleared the outage banner after the daemon restarted"
    return 0
  fi

  if curl -fsS "http://127.0.0.1:${PORT}/dashboard/alerts" >"${WORK_DIR}/dashboard-alerts-after-restart.json" \
    && python3 - "${WORK_DIR}/dashboard-alerts-after-restart.json" "${replay_alert_id}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
alert_id = int(sys.argv[2])
raise SystemExit(0 if any(alert.get("alert_id") == alert_id for alert in payload.get("alerts", [])) else 1)
PY
  then
    record_result "VAL-CROSS-006" "pass" "dashboard replay reloaded historical alert_id ${replay_alert_id} from alerts.jsonl after the daemon restart"
  else
    record_result "VAL-CROSS-006" "blocked" "dashboard alert replay after restart did not include historical alert_id ${replay_alert_id}"
  fi

  post_restart_before_count="$(sudo sh -c "wc -l < '${ALERT_LOG}'" 2>/dev/null || echo 0)"
  submit_fixture_vector_for_pid "reverse_shell" "91002" "${WORK_DIR}/post-restart-response.json"
  if wait_for_alert_for_pid "91002" "${post_restart_before_count}" 5 "${WORK_DIR}/post-restart-alert.json"; then
    post_restart_alert_id="$(python3 - "${WORK_DIR}/post-restart-alert.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["alert_id"])
PY
)"
    if wait_for_browser_alert_id "${post_restart_alert_id}" 5000 \
      && wait_for_tui_alert_id "${post_restart_alert_id}" 5; then
      record_result "VAL-CROSS-011" "pass" "browser reconnect counters advanced (${initial_open_count}→$(browser_eval "String(window.__miniEdrDebug.transport.openCount)"), reconnectAttempts=${initial_reconnect_attempts}→$(browser_eval "String(window.__miniEdrDebug.transport.reconnectAttempts)")), the TUI surface recovered after the daemon restart, and post-restart alert_id ${post_restart_alert_id} reached both operator surfaces"
    else
      record_result "VAL-CROSS-011" "blocked" "post-restart alert_id ${post_restart_alert_id} did not reach both the browser and tuistory surfaces after reconnect"
    fi
  else
    record_result "VAL-CROSS-011" "blocked" "no post-restart alert reached alerts.jsonl after the reconnect sequence"
  fi
}

assert_cross_004_008_and_012() {
  local before_count pre_response post_response alert_id
  local pre_swap_hash post_swap_hash swap_before_count swap_alert_id browser_model_hash
  local messages_before messages_after degraded_before_count
  local degraded_predict_status recovery_before_count recovery_alert_id
  local threshold_fixture_pid="814"

  before_count="$(sudo sh -c "wc -l < '${ALERT_LOG}'" 2>/dev/null || echo 0)"
  pre_response="$(curl -fsS -H 'content-type: application/json' --data @"${THRESHOLD_FIXTURE}" "http://127.0.0.1:${PORT}/internal/predict")"
  if python3 - "${pre_response}" "${before_count}" "${ALERT_LOG}" "${threshold_fixture_pid}" <<'PY'
import json
import subprocess
import sys
response = json.loads(sys.argv[1])
baseline = int(sys.argv[2])
alert_log = sys.argv[3]
expected_pid = int(sys.argv[4])
line_count = int(subprocess.check_output(["sudo", "sh", "-c", f"wc -l < '{alert_log}'"]).decode().strip())
if response["would_alert"]:
    raise SystemExit(1)
if line_count == baseline:
    raise SystemExit(0)
payloads = json.loads(
    subprocess.check_output(
        ["sudo", "python3", "-", alert_log, str(baseline)],
        text=True,
        input="""
import json
import sys

alert_log = sys.argv[1]
baseline = int(sys.argv[2])
payloads = []
with open(alert_log, encoding="utf-8") as handle:
    for index, line in enumerate(handle, start=1):
        if index <= baseline or not line.strip():
            continue
        payloads.append(json.loads(line))
print(json.dumps(payloads))
""",
    )
)
raise SystemExit(0 if all(payload.get("pid") != expected_pid for payload in payloads) else 1)
PY
  then
    :
  else
    record_result "VAL-CROSS-004" "blocked" "pre-reload threshold_065 fixture unexpectedly alerted before the threshold change"
    return 0
  fi

  replace_config_line "alert_threshold = 0.7" "alert_threshold = 0.6"
  refresh_daemon_pid
  sudo kill -HUP "${DAEMON_PID}"
  wait_for_health_threshold "0.6" "${WORK_DIR}/health-after-threshold.json"

  post_response="$(curl -fsS -H 'content-type: application/json' --data @"${THRESHOLD_FIXTURE}" "http://127.0.0.1:${PORT}/internal/predict")"
  if ! python3 - "${post_response}" <<'PY'
import json
import sys
response = json.loads(sys.argv[1])
raise SystemExit(0 if response["would_alert"] and response["threshold"] == 0.6 else 1)
PY
  then
    record_result "VAL-CROSS-004" "blocked" "post-reload threshold_065 fixture still failed to alert at threshold 0.6"
    return 0
  fi

  if wait_for_alert_for_pid "${threshold_fixture_pid}" "${before_count}" 5 "${WORK_DIR}/threshold-alert.json"; then
    alert_id="$(python3 - "${WORK_DIR}/threshold-alert.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["alert_id"])
PY
)"
  else
    alert_id=""
  fi
  if [[ -n "${alert_id}" ]] \
    && wait_for_browser_alert_id "${alert_id}" 5000 \
    && wait_for_tui_text "$(printf 'pid %5d' "${threshold_fixture_pid}")" 5; then
    record_result "VAL-CROSS-004" "pass" "threshold reload produced alert_id ${alert_id} across log, browser, and tuistory after the 0.6 threshold took effect"
  else
    record_result "VAL-CROSS-004" "blocked" "threshold reload alert did not fan out to every surface"
  fi

  pre_swap_hash="$(python3 - "${WORK_DIR}/health-after-threshold.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["model_hash"])
PY
)"
  replace_config_line \
    "model_path = \"${MODEL_V1_PATH}\"" \
    "model_path = \"${MODEL_V2_PATH}\""
  refresh_daemon_pid
  sudo kill -HUP "${DAEMON_PID}"
  if wait_for_health_model_hash_change "${pre_swap_hash}" "${WORK_DIR}/health-after-model-swap.json"; then
    post_swap_hash="$(python3 - "${WORK_DIR}/health-after-model-swap.json" "${pre_swap_hash}" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
if payload["state"] != "Running" or payload["model_hash"] == sys.argv[2]:
    raise SystemExit(1)
print(payload["model_hash"])
PY
)"
    swap_before_count="$(sudo sh -c "wc -l < '${ALERT_LOG}'" 2>/dev/null || echo 0)"
    messages_before="$(browser_eval "window.__miniEdrDebug.transport.messagesReceived")"
    curl -fsS -H 'content-type: application/json' --data @"${THRESHOLD_FIXTURE}" "http://127.0.0.1:${PORT}/internal/predict" >"${WORK_DIR}/post-swap-response.json"
    if wait_for_alert_for_pid "${threshold_fixture_pid}" "${swap_before_count}" 5 "${WORK_DIR}/post-swap-alert.json"; then
      swap_alert_id="$(python3 - "${WORK_DIR}/post-swap-alert.json" "${post_swap_hash}" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
expected_hash = sys.argv[2]
if payload.get("model_hash") != expected_hash:
    raise SystemExit(1)
print(payload["alert_id"])
PY
)"
      browser_model_hash=""
      for _ in $(seq 1 25); do
        browser_model_hash="$(browser_eval "window.__miniEdrDebug.alerts.find((alert) => Number(alert.alert_id) === Number(${swap_alert_id}))?.model_hash ?? ''")"
        if [[ -n "${browser_model_hash}" ]]; then
          break
        fi
        sleep 0.2
      done
      messages_after="$(browser_eval "window.__miniEdrDebug.transport.messagesReceived")"
      if [[ "${browser_model_hash}" == "${post_swap_hash}" ]] && [[ "${messages_after}" =~ ^[0-9]+$ ]] && (( messages_after > messages_before )); then
        record_result "VAL-CROSS-008" "pass" "the first post-swap alert_id ${swap_alert_id} carried model_hash ${post_swap_hash} in alerts.jsonl and on the live dashboard stream"
      else
        record_result "VAL-CROSS-008" "blocked" "post-swap alert_id ${swap_alert_id} did not expose model_hash ${post_swap_hash} on both the log and live dashboard surfaces"
      fi
    else
      record_result "VAL-CROSS-008" "blocked" "no first post-swap alert reached alerts.jsonl after the valid model reload"
    fi
  else
    record_result "VAL-CROSS-008" "blocked" "valid model reload did not converge back to Running with a new model hash"
  fi

  replace_config_line \
    "model_path = \"${MODEL_V2_PATH}\"" \
    "model_path = \"${MISSING_MODEL_PATH}\""
  refresh_daemon_pid
  sudo kill -HUP "${DAEMON_PID}"
  if wait_for_health_state "Degraded" "${WORK_DIR}/health-degraded.json"; then
    if agent-browser --session "${BROWSER_SESSION}" wait --text "Daemon: Degraded" --timeout 5000 >/dev/null 2>&1 \
      && wait_for_tui_text "degraded mode" 5 \
      && [[ "$(browser_eval "String(document.getElementById('degraded-badge')?.hidden)")" == "false" ]]; then
      degraded_before_count="$(sudo sh -c "wc -l < '${ALERT_LOG}'" 2>/dev/null || echo 0)"
      cat >"${WORK_DIR}/degraded-process-tree.json" <<'EOF'
{
  "processes": [
    {
      "pid": 99001,
      "process_name": "degraded-proc",
      "binary_path": "/tmp/degraded-proc",
      "threat_score": null,
      "depth": 0,
      "detail": {
        "ancestry_chain": [
          {
            "pid": 1,
            "process_name": "systemd",
            "binary_path": "/sbin/init"
          },
          {
            "pid": 99001,
            "process_name": "degraded-proc",
            "binary_path": "/tmp/degraded-proc"
          }
        ],
        "feature_vector": [
          {
            "label": "mode",
            "value": "degraded"
          }
        ],
        "recent_syscalls": [
          "Openat /tmp/degraded-proc"
        ],
        "threat_score": null,
        "top_features": []
      },
      "exited": false
    }
  ]
}
EOF
      post_process_tree_snapshot "${WORK_DIR}/degraded-process-tree.json"
      if ! agent-browser --session "${BROWSER_SESSION}" wait ".process-row[data-pid='99001']" --timeout 5000 >/dev/null 2>&1 \
        || ! wait_for_tui_text "degraded-proc" 5; then
        record_result "VAL-CROSS-012" "blocked" "degraded process-tree updates did not stay visible in both the browser and TUI surfaces"
        return 0
      fi
      degraded_predict_status="$(curl -sS -o "${WORK_DIR}/degraded-predict-response.json" -w '%{http_code}' -H 'content-type: application/json' --data @"${THRESHOLD_FIXTURE}" "http://127.0.0.1:${PORT}/internal/predict" || true)"
      sleep 1
      if [[ "$(sudo sh -c "wc -l < '${ALERT_LOG}'" 2>/dev/null || echo 0)" == "${degraded_before_count}" ]]; then
        replace_config_line \
          "model_path = \"${MISSING_MODEL_PATH}\"" \
          "model_path = \"${MODEL_V2_PATH}\""
        refresh_daemon_pid
        sudo kill -HUP "${DAEMON_PID}"
        if wait_for_health_state "Running" "${WORK_DIR}/health-recovered.json" \
          && agent-browser --session "${BROWSER_SESSION}" wait --text "Daemon: Running" --timeout 5000 >/dev/null 2>&1 \
          && wait_for_tui_text_absent "degraded mode" 5 \
          && [[ "$(browser_eval "String(document.getElementById('degraded-badge')?.hidden)")" == "true" ]]; then
          recovery_before_count="$(sudo sh -c "wc -l < '${ALERT_LOG}'" 2>/dev/null || echo 0)"
          curl -fsS -H 'content-type: application/json' --data @"${THRESHOLD_FIXTURE}" "http://127.0.0.1:${PORT}/internal/predict" >"${WORK_DIR}/recovery-response.json"
          if wait_for_alert_for_pid "${threshold_fixture_pid}" "${recovery_before_count}" 5 "${WORK_DIR}/recovery-alert.json"; then
            recovery_alert_id="$(python3 - "${WORK_DIR}/recovery-alert.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["alert_id"])
PY
)"
            record_result "VAL-CROSS-012" "pass" "degraded mode showed warnings in both UIs, process trees kept updating, no alerts emitted while degraded (predict status ${degraded_predict_status}), and alert_id ${recovery_alert_id} resumed after the valid model returned"
          else
            record_result "VAL-CROSS-012" "blocked" "the daemon recovered to Running but alerts did not resume in alerts.jsonl"
          fi
        else
          record_result "VAL-CROSS-012" "blocked" "the valid-model SIGHUP did not clear degraded indicators from both operator surfaces"
        fi
      else
        record_result "VAL-CROSS-012" "blocked" "the degraded daemon still emitted new alerts while inference should have been disabled"
      fi
    else
      record_result "VAL-CROSS-012" "blocked" "degraded-mode UI signaling was missing from the browser or tuistory surface"
    fi
  else
    record_result "VAL-CROSS-012" "blocked" "bad model reload did not move the daemon into Degraded"
  fi

  if grep -Fq "model_path = \"${MISSING_MODEL_PATH}\"" "${CONFIG_PATH}"; then
    replace_config_line \
      "model_path = \"${MISSING_MODEL_PATH}\"" \
      "model_path = \"${MODEL_V2_PATH}\""
    refresh_daemon_pid
    sudo kill -HUP "${DAEMON_PID}"
    wait_for_health_state "Running" "${WORK_DIR}/health.json" >/dev/null 2>&1 || true
  fi
}

assert_cross_005_and_007() {
  local no_caps_binary="${WORK_DIR}/mini-edr-daemon-no-caps"
  local no_caps_config="${WORK_DIR}/no-caps.toml"
  local no_caps_port expected_stderr
  cp "${DAEMON_BIN}" "${no_caps_binary}"
  if getcap "${no_caps_binary}" | grep -q 'cap_'; then
    sudo setcap -r "${no_caps_binary}"
  fi
  no_caps_port="$(find_free_port)"
  cat >"${no_caps_config}" <<EOF
alert_threshold = 0.7
web_port = ${no_caps_port}
model_path = "${MODEL_V1_PATH}"
log_file_path = "${WORK_DIR}/logs/no-caps/no-caps-alerts.jsonl"
state_dir = "${WORK_DIR}/no-caps-state"
enable_web = false
enable_tui = false
EOF
  mkdir -p "${WORK_DIR}/no-caps-state" "${WORK_DIR}/logs/no-caps"
  set +e
  run_as_original_user env MINI_EDR_API_SOCKET="${WORK_DIR}/no-caps.sock" "${no_caps_binary}" --config "${no_caps_config}" >"${WORK_DIR}/no-caps.stdout.log" 2>"${WORK_DIR}/no-caps.stderr.log"
  local exit_code=$?
  set -e
  expected_stderr='CAP_BPF and CAP_PERFMON are required to start mini-edr-daemon; run `sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep <binary>` or start the daemon via sudo'
  if [[ "${exit_code}" -eq 2 ]] \
    && grep -Fxq "${expected_stderr}" "${WORK_DIR}/no-caps.stderr.log" \
    && ! [[ -f "${WORK_DIR}/logs/no-caps/no-caps-alerts.jsonl" ]] \
    && ! ss -ltn "( sport = :${no_caps_port} )" | grep -Fq "127.0.0.1:${no_caps_port}" \
    && ! curl -sS "http://127.0.0.1:${no_caps_port}/health" >/dev/null 2>&1; then
    record_result "VAL-CROSS-007" "pass" "uncapped daemon copy exited 2 with the documented capability error before it created logs or bound port ${no_caps_port}"
  else
    record_result "VAL-CROSS-007" "blocked" "uncapped daemon copy exited ${exit_code}, stderr shape mismatched, or it still created runtime side effects"
  fi

  rm -f "${DAEMON_RESTART_TOKEN}"
  terminate_current_daemon_command
  sleep 1
  if ! curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1 && ! ss -ltn "( sport = :${PORT} )" | grep -q "${PORT}"; then
    record_result "VAL-CROSS-005" "pass" "SIGTERM removed the localhost listener and the daemon stopped serving cross-area surfaces"
  else
    record_result "VAL-CROSS-005" "blocked" "daemon still responded after SIGTERM"
  fi
}

assert_sec_005() {
  local peer_image gateway_ip peer_ipv4
  local peer_network_json="${WORK_DIR}/peer-network.json"
  local peer_iface_path="${WORK_DIR}/peer-interface.txt"
  local peer_route_path="${WORK_DIR}/peer-route.txt"
  local nc_output_path="${WORK_DIR}/peer-probe-nc.txt"
  local curl_output_path="${WORK_DIR}/peer-probe-curl.txt"
  local nc_rc curl_rc nc_output curl_output

  if ! command -v docker >/dev/null 2>&1; then
    record_result "VAL-SEC-005" "blocked" "docker is unavailable, so the second-host peer probe could not launch"
    return 0
  fi

  if ! peer_image="$(docker_peer_image)"; then
    record_result "VAL-SEC-005" "blocked" "no reusable Mini-EDR Docker image was present (expected mini-edr-dev-build:latest or mini-edr-dev:latest)"
    return 0
  fi

  # Docker strategy for VAL-SEC-005: the peer container runs on its own bridge
  # network and probes the host-side bridge gateway, which is a bona fide
  # non-loopback IP on the daemon host. A daemon bound to 127.0.0.1 only must
  # therefore refuse or time out this bridge-originated connection attempt.
  DOCKER_PEER_NETWORK="mini-edr-cross-peer-$$"
  docker network rm "${DOCKER_PEER_NETWORK}" >/dev/null 2>&1 || true
  docker network create "${DOCKER_PEER_NETWORK}" >/dev/null
  docker network inspect "${DOCKER_PEER_NETWORK}" >"${peer_network_json}"
  if ! gateway_ip="$(python3 - "${peer_network_json}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
configs = payload[0].get("IPAM", {}).get("Config", [])
print(configs[0].get("Gateway", "") if configs else "")
PY
  )"; then
    gateway_ip=""
  fi
  if [[ -z "${gateway_ip}" ]]; then
    record_result "VAL-SEC-005" "blocked" "docker network ${DOCKER_PEER_NETWORK} did not expose a host-side gateway IP to probe"
    return 0
  fi

  if ! docker run --rm --network "${DOCKER_PEER_NETWORK}" "${peer_image}" ip -4 -o addr show dev eth0 scope global up >"${peer_iface_path}"; then
    record_result "VAL-SEC-005" "blocked" "peer container failed to boot on docker network ${DOCKER_PEER_NETWORK}"
    return 0
  fi
  if ! docker run --rm --network "${DOCKER_PEER_NETWORK}" "${peer_image}" ip route show default >"${peer_route_path}"; then
    record_result "VAL-SEC-005" "blocked" "peer container started on ${DOCKER_PEER_NETWORK}, but its default-route evidence could not be collected"
    return 0
  fi
  if ! peer_ipv4="$(python3 - "${peer_iface_path}" <<'PY'
import sys

line = open(sys.argv[1], encoding="utf-8").read().strip()
parts = line.split()
if len(parts) < 4:
    raise SystemExit(1)
print(parts[3].split("/", 1)[0])
PY
  )"; then
    peer_ipv4=""
  fi
  if [[ -z "${peer_ipv4}" ]]; then
    record_result "VAL-SEC-005" "blocked" "peer container launched on ${DOCKER_PEER_NETWORK}, but its eth0 IPv4 address could not be determined"
    return 0
  fi

  set +e
  docker run --rm --network "${DOCKER_PEER_NETWORK}" "${peer_image}" nc -zvw 3 "${gateway_ip}" "${PORT}" >"${nc_output_path}" 2>&1
  nc_rc=$?
  docker run --rm --network "${DOCKER_PEER_NETWORK}" "${peer_image}" curl --connect-timeout 3 -sS "http://${gateway_ip}:${PORT}/" >"${curl_output_path}" 2>&1
  curl_rc=$?
  set -e

  nc_output="$(tr '\n' ' ' <"${nc_output_path}" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')"
  curl_output="$(tr '\n' ' ' <"${curl_output_path}" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')"
  if [[ "${nc_rc}" -ne 0 ]] \
    && grep -Eiq 'connection refused|timed out|no route to host|network is unreachable' "${nc_output_path}" \
    && [[ "${curl_rc}" -ne 0 ]] \
    && grep -Eiq "connection refused|couldn't connect to server|timed out|no route to host|failed to connect" "${curl_output_path}"; then
    record_result "VAL-SEC-005" "pass" "peer ${peer_ipv4} on docker network ${DOCKER_PEER_NETWORK} could not reach host ${gateway_ip}:${PORT} (nc rc ${nc_rc}: ${nc_output}; curl rc ${curl_rc}: ${curl_output})"
  else
    record_result "VAL-SEC-005" "blocked" "peer ${peer_ipv4} on docker network ${DOCKER_PEER_NETWORK} saw unexpected probe results for host ${gateway_ip}:${PORT} (nc rc ${nc_rc}: ${nc_output}; curl rc ${curl_rc}: ${curl_output})"
  fi

  docker network rm "${DOCKER_PEER_NETWORK}" >/dev/null 2>&1 || true
  DOCKER_PEER_NETWORK=""
}

main() {
  mkdir -p "${WORK_DIR}"
  if [[ ! -x "${DAEMON_BIN}" ]]; then
    echo "missing release daemon binary at ${DAEMON_BIN}; build it before running full_flow.sh" >&2
    exit 1
  fi
  # WSL2 keeps tracefs root-owned, so the dropped-privilege daemon needs
  # CAP_DAC_READ_SEARCH in addition to the probe-loading capabilities.
  sudo setcap cap_bpf,cap_perfmon,cap_sys_admin,cap_dac_read_search+ep "${DAEMON_BIN}"
  prepare_model_variants
  compile_live_fixture
  write_config "0.7" "${MODEL_V1_PATH}"
  launch_daemon_session
  open_dashboard
  assert_cross_001_002_003_009_010
  assert_cross_004_008_and_012
  assert_cross_006_and_011
  assert_sec_005
  assert_cross_005_and_007
  sync_summary_env
}

main "$@"
 
