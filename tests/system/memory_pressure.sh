#!/usr/bin/env bash
# memory_pressure.sh — exercise graceful shedding under synthetic near-cap load.
#
# Purpose:
# - drive the daemon's deterministic test-mode sensor stream at a high enough
#   rate and PID cardinality to trigger queue drops and active-window evictions
# - require `/api/health.state` to report `BackPressure` once shedding starts
# - prove the daemon keeps serving schema-valid alerts while under pressure
#
# Expected result:
# - daemon stays alive for the requested duration
# - `ring_events_dropped_total` and `windows_evicted_total` both become non-zero
# - `/api/health.state` reaches `BackPressure`
# - at least one pressure-time alert remains valid JSON in the alert log
#
# Cleanup contract:
# - an EXIT trap stops the daemon and alert-stream subscriber
# - all temp evidence lives under one mktemp directory
set -euo pipefail

source "/home/alexm/mini-edr/tests/system/availability_lib.sh"

duration_arg="15s"
report_path=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration)
      duration_arg="$2"
      shift 2
      ;;
    --report-path)
      report_path="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

duration_seconds="$(availability_parse_duration_seconds "${duration_arg}")"
temp_dir="$(mktemp -d /tmp/mini-edr-memory-pressure-XXXXXX)"
stream_capture_path="${temp_dir}/alerts-stream.jsonl"
snapshots_path="${temp_dir}/health-snapshots.jsonl"
summary_path="${report_path:-${temp_dir}/summary.json}"

cleanup() {
  if [[ -n "${stream_pid:-}" ]]; then
    fixture_stop_alert_stream "${stream_pid}"
  fi
  if [[ -n "${daemon_pid:-}" ]]; then
    availability_stop_daemon "${daemon_pid}"
  fi
  if [[ -z "${report_path}" ]]; then
    rm -rf "${temp_dir}"
  fi
}
trap cleanup EXIT

export MINI_EDR_TEST_SENSOR_RATE="${MINI_EDR_TEST_SENSOR_RATE:-100000}"
export MINI_EDR_TEST_SENSOR_PID_COUNT="${MINI_EDR_TEST_SENSOR_PID_COUNT:-10000}"
export MINI_EDR_TEST_MAX_ACTIVE_WINDOWS="${MINI_EDR_TEST_MAX_ACTIVE_WINDOWS:-128}"

read -r daemon_pid daemon_port daemon_config_path daemon_log_path daemon_socket < <(
  availability_start_test_daemon "${temp_dir}" "0.7"
)
stream_pid="$(fixture_start_alert_stream "${daemon_socket}" "${stream_capture_path}")"

fixture_script="/home/alexm/mini-edr/tests/fixtures/malware/reverse_shell.sh"
start_line="$(fixture_stream_line_count "${stream_capture_path}")"
fixture_result_json="$("${fixture_script}" --daemon-port "${daemon_port}" --trial 0)"
expected_binary_path="$(fixture_json_get "${fixture_result_json}" "expected_binary_path")"
expected_pid="$(fixture_json_get "${fixture_result_json}" "pid")"

started_at="$(date +%s)"
backpressure_seen="false"
while true; do
  now="$(date +%s)"
  elapsed="$((now - started_at))"
  health_json="$(availability_health_json "${daemon_port}")"
  printf '%s\n' "${health_json}" >>"${snapshots_path}"
  if [[ "$("${FIXTURE_PYTHON_BIN}" - "${health_json}" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
print("true" if payload["state"] == "BackPressure" else "false")
PY
)" == "true" ]]; then
    backpressure_seen="true"
  fi
  if (( elapsed >= duration_seconds )); then
    break
  fi
  if ! kill -0 "${daemon_pid}" >/dev/null 2>&1; then
    echo "daemon exited during memory-pressure run" >&2
    cat "${daemon_log_path}" >&2
    exit 1
  fi
  sleep 1
done

if correlated_alerts_json="$(fixture_wait_for_correlated_alerts "${stream_capture_path}" "${expected_binary_path}" "${expected_pid}" "${start_line}" 5)"; then
  :
else
  correlated_alerts_json="[]"
fi

fixture_stop_alert_stream "${stream_pid}"
stream_pid=""
availability_stop_daemon "${daemon_pid}"
daemon_pid=""

"${FIXTURE_PYTHON_BIN}" - "${snapshots_path}" "${fixture_result_json}" "${correlated_alerts_json}" "${summary_path}" "${daemon_log_path}" "${daemon_config_path}" "${backpressure_seen}" <<'PY'
import json
import sys
from pathlib import Path

snapshots = [
    json.loads(line)
    for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
    if line.strip()
]
fixture_result = json.loads(sys.argv[2])
correlated_alerts = json.loads(sys.argv[3])
summary_path = Path(sys.argv[4])
daemon_log_path = sys.argv[5]
daemon_config_path = sys.argv[6]
backpressure_seen = sys.argv[7] == "true"

if not snapshots:
    raise SystemExit("no health snapshots collected")

last_snapshot = snapshots[-1]
ring_drops = [snapshot["ring_events_dropped_total"] for snapshot in snapshots]
window_evictions = [snapshot["windows_evicted_total"] for snapshot in snapshots]
alert_valid = all(
    isinstance(alert["alert"], dict)
    and "alert_id" in alert["alert"]
    and "timestamp" in alert["alert"]
    and isinstance(alert["alert"].get("threat_score"), (int, float))
    and isinstance(alert["alert"].get("top_features"), list)
    for alert in correlated_alerts
) if correlated_alerts else False

summary = {
    "mode": "memory_pressure",
    "daemon_log_path": daemon_log_path,
    "daemon_config_path": daemon_config_path,
    "final_health": last_snapshot,
    "max_ring_events_dropped_total": max(ring_drops),
    "max_windows_evicted_total": max(window_evictions),
    "backpressure_seen": backpressure_seen,
    "fixture_result": fixture_result,
    "correlated_alerts": correlated_alerts,
    "alert_schema_valid": alert_valid,
    "pass": backpressure_seen
    and max(ring_drops) > 0
    and max(window_evictions) > 0
    and alert_valid,
}

summary_path.parent.mkdir(parents=True, exist_ok=True)
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
if not summary["pass"]:
    raise SystemExit("memory-pressure contract was not satisfied")
PY

echo "PASS: pressure shedding raised BackPressure and preserved alert schema validity"
