#!/usr/bin/env bash
# run_all.sh — execute every benign workload fixture against the daemon.
#
# The harness launches an isolated localhost daemon unless an external port is
# supplied, runs each benign workload ten times, and treats each scored vector
# as a six-hour observation window by default. It then reports the observed
# alert count and derived alerts-per-hour rate for each workload.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/fixture_runtime_lib.sh"

trials=10
window_hours="${MINI_EDR_BENIGN_HOURS:-6}"
output_path=""
external_port=""
threshold="0.7"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --trials)
      trials="$2"
      shift 2
      ;;
    --hours)
      window_hours="$2"
      shift 2
      ;;
    --output)
      output_path="$2"
      shift 2
      ;;
    --daemon-port)
      external_port="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

benign_alert_cap="$("${FIXTURE_PYTHON_BIN}" - "${window_hours}" <<'PY'
import math
import sys

print(max(1, math.ceil(float(sys.argv[1]))))
PY
)"

printf 'benign suite: trials_per_fixture=%s hours_per_trial=%s per_workload_alert_cap=%s\n' \
  "${trials}" "${window_hours}" "${benign_alert_cap}"

temp_dir="$(mktemp -d /tmp/mini-edr-benign-suite-XXXXXX)"
results_path="${temp_dir}/results.jsonl"
summary_path="${output_path:-${temp_dir}/summary.json}"
stream_capture_path="${temp_dir}/alerts-stream.jsonl"

cleanup() {
  if [[ -n "${stream_pid:-}" ]]; then
    fixture_stop_alert_stream "${stream_pid}"
  fi
  if [[ -n "${daemon_pid:-}" ]]; then
    cleanup_daemon "${daemon_pid}"
  fi
}
trap cleanup EXIT

if [[ -n "${external_port}" ]]; then
  daemon_port="${external_port}"
  echo "--daemon-port requires the caller to manage the matching Unix socket stream separately" >&2
  exit 2
else
  read -r daemon_pid daemon_port daemon_config_path daemon_log_path daemon_socket < <(fixture_start_isolated_daemon "${temp_dir}" "${threshold}")
fi
stream_pid="$(fixture_start_alert_stream "${daemon_socket}" "${stream_capture_path}")"

fixtures=(
  "kernel_compile"
  "nginx_serving"
  "idle_desktop"
)

for fixture_name in "${fixtures[@]}"; do
  fixture_script="/home/alexm/mini-edr/tests/fixtures/benign/${fixture_name}.sh"
  for trial in $(seq 1 "${trials}"); do
    start_line="$(fixture_stream_line_count "${stream_capture_path}")"
    result_json="$("${fixture_script}" --daemon-port "${daemon_port}" --trial "${trial}" --hours "${window_hours}")"
    expected_binary_path="$(fixture_json_get "${result_json}" "expected_binary_path")"
    expected_pid="$(fixture_json_get "${result_json}" "pid")"
    if correlated_alerts_json="$(fixture_wait_for_correlated_alerts "${stream_capture_path}" "${expected_binary_path}" "${expected_pid}" "${start_line}" 1)"; then
      :
    else
      correlated_alerts_json="[]"
    fi
    "${FIXTURE_PYTHON_BIN}" - "${result_json}" "${correlated_alerts_json}" "${threshold}" >>"${results_path}" <<'PY'
import json
import sys

result = json.loads(sys.argv[1])
correlated_alerts = json.loads(sys.argv[2])
threshold = float(sys.argv[3])
matched_alerts = [match["alert"] for match in correlated_alerts]
matched_scores = [alert["threat_score"] for alert in matched_alerts]
correlation_modes = sorted(
    {mode for match in correlated_alerts for mode in match["correlation_modes"]}
)
result["alert_count"] = len(matched_alerts)
result["stream_correlated"] = result["alert_count"] > 0
result["correlation_modes"] = correlation_modes
result["matched_alert_ids"] = [alert["alert_id"] for alert in matched_alerts]
result["matched_scores"] = matched_scores
result["matched_alerts"] = matched_alerts
result["max_stream_threat_score"] = max(matched_scores) if matched_scores else None
result["stream_threshold"] = threshold
result["false_positive"] = bool(matched_scores)
print(json.dumps(result, separators=(",", ":")))
PY
  done
done

"${FIXTURE_PYTHON_BIN}" - "${results_path}" "${summary_path}" "${trials}" "${window_hours}" "${threshold}" "${daemon_log_path}" "${daemon_config_path}" "${benign_alert_cap}" <<'PY'
import json
import math
import statistics
import sys
from pathlib import Path

results_path = Path(sys.argv[1])
summary_path = Path(sys.argv[2])
trials = int(sys.argv[3])
window_hours = float(sys.argv[4])
threshold = float(sys.argv[5])
daemon_log_path = sys.argv[6]
daemon_config_path = sys.argv[7]
alert_cap = int(sys.argv[8])
expected_alert_cap = max(1, math.ceil(window_hours))
if alert_cap != expected_alert_cap:
    raise SystemExit(
        f"alert cap mismatch: shell computed {alert_cap}, expected {expected_alert_cap}"
    )
results = [json.loads(line) for line in results_path.read_text(encoding="utf-8").splitlines() if line.strip()]

fixtures = {}
for result in results:
    fixtures.setdefault(result["fixture"], []).append(result)

per_fixture = {}
all_scores = []
all_matched_scores = []
total_alerts = 0
false_positive_trials = 0
pass_state = True
for fixture_name, fixture_results in fixtures.items():
    scores = [item["score"] for item in fixture_results]
    alerts = sum(item["alert_count"] for item in fixture_results)
    fixture_false_positive_trials = sum(
        1 for item in fixture_results if item["stream_correlated"]
    )
    observed_hours = len(fixture_results) * window_hours
    alerts_per_hour = alerts / max(observed_hours, 1.0)
    all_scores.extend(scores)
    matched_scores = [
        score
        for item in fixture_results
        for score in item.get("matched_scores", [])
    ]
    all_matched_scores.extend(matched_scores)
    total_alerts += alerts
    false_positive_trials += fixture_false_positive_trials
    fixture_false_positive_rate = fixture_false_positive_trials / max(len(fixture_results), 1)
    fixture_pass = alerts < alert_cap
    pass_state = pass_state and fixture_pass
    per_fixture[fixture_name] = {
        "trials": len(fixture_results),
        "observed_hours": observed_hours,
        "per_workload_alert_cap": alert_cap,
        "alerts": alerts,
        "false_positive_trials": fixture_false_positive_trials,
        "false_positive_rate": fixture_false_positive_rate,
        "alerts_per_hour": alerts_per_hour,
        "mean_score": statistics.fmean(scores),
        "max_score": max(scores),
        "max_stream_threat_score": max(matched_scores) if matched_scores else None,
        "pass": fixture_pass,
    }

aggregate_false_positive_rate = false_positive_trials / max(len(results), 1)
summary = {
    "category": "benign",
    "validation_targets": ["VAL-DETECT-013"],
    "trials_per_fixture": trials,
    "hours_per_trial": window_hours,
    "per_workload_alert_cap": alert_cap,
    "fixtures": per_fixture,
    "total_trials": len(results),
    "observed_hours_total": len(results) * window_hours,
    "total_alerts": total_alerts,
    "false_positive_trials": false_positive_trials,
    "aggregate_false_positive_rate": aggregate_false_positive_rate,
    "mean_score": statistics.fmean(all_scores),
    "max_score": max(all_scores),
    "max_stream_threat_score": max(all_matched_scores) if all_matched_scores else None,
    "stream_threshold": threshold,
    "results_path": str(results_path),
    "stream_capture_path": str(results_path.parent / "alerts-stream.jsonl"),
    "daemon_log_path": daemon_log_path,
    "daemon_config_path": daemon_config_path,
    "pass": pass_state and aggregate_false_positive_rate < 0.05,
}

summary_path.parent.mkdir(parents=True, exist_ok=True)
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

fixture_pretty_print_summary "${summary_path}"
