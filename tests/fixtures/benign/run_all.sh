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
window_hours=6
output_path=""
external_port=""

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

temp_dir="$(mktemp -d /tmp/mini-edr-benign-suite-XXXXXX)"
results_path="${temp_dir}/results.jsonl"
summary_path="${output_path:-${temp_dir}/summary.json}"

cleanup() {
  if [[ -n "${daemon_pid:-}" ]]; then
    cleanup_daemon "${daemon_pid}"
  fi
}
trap cleanup EXIT

if [[ -n "${external_port}" ]]; then
  daemon_port="${external_port}"
else
  read -r daemon_pid daemon_port _config_path _log_path < <(fixture_start_isolated_daemon "${temp_dir}" 0.7)
fi

fixtures=(
  "kernel_compile"
  "nginx_serving"
  "idle_desktop"
)

for fixture_name in "${fixtures[@]}"; do
  fixture_script="/home/alexm/mini-edr/tests/fixtures/benign/${fixture_name}.sh"
  for trial in $(seq 1 "${trials}"); do
    "${fixture_script}" --daemon-port "${daemon_port}" --trial "${trial}" --hours "${window_hours}" >>"${results_path}"
  done
done

"${FIXTURE_PYTHON_BIN}" - "${results_path}" "${summary_path}" "${trials}" "${window_hours}" <<'PY'
import json
import statistics
import sys
from pathlib import Path

results_path = Path(sys.argv[1])
summary_path = Path(sys.argv[2])
trials = int(sys.argv[3])
window_hours = float(sys.argv[4])
results = [json.loads(line) for line in results_path.read_text(encoding="utf-8").splitlines() if line.strip()]

fixtures = {}
for result in results:
    fixtures.setdefault(result["fixture"], []).append(result)

per_fixture = {}
all_scores = []
pass_state = True
for fixture_name, fixture_results in fixtures.items():
    scores = [item["score"] for item in fixture_results]
    alerts = sum(item["alert_count"] for item in fixture_results)
    observed_hours = len(fixture_results) * window_hours
    alerts_per_hour = alerts / max(observed_hours, 1.0)
    all_scores.extend(scores)
    fixture_pass = alerts_per_hour < 1.0
    pass_state = pass_state and fixture_pass
    per_fixture[fixture_name] = {
        "trials": len(fixture_results),
        "observed_hours": observed_hours,
        "alerts": alerts,
        "alerts_per_hour": alerts_per_hour,
        "mean_score": statistics.fmean(scores),
        "max_score": max(scores),
        "pass": fixture_pass,
    }

summary = {
    "category": "benign",
    "trials_per_fixture": trials,
    "hours_per_trial": window_hours,
    "fixtures": per_fixture,
    "total_trials": len(results),
    "observed_hours_total": len(results) * window_hours,
    "mean_score": statistics.fmean(all_scores),
    "max_score": max(all_scores),
    "pass": pass_state,
}

summary_path.parent.mkdir(parents=True, exist_ok=True)
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

fixture_pretty_print_summary "${summary_path}"
