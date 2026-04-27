#!/usr/bin/env bash
# e2e_latency.sh — measure reverse-shell fixture-vector to alert latency.
#
# Purpose:
# - replay the checked-in reverse_shell feature-vector fixture through HotReloadDaemon::predict
# - capture p50 / p99 / max latency for the full threshold + alert-generation + alert-log path
# - keep the run unprivileged so it can execute on hosts that lack CAP_BPF for the live sensor
#
# Expected result:
# - p99 latency < 5000 ms
# - max latency < 5000 ms
# - alert_count_total == requested trial count
#
# Cleanup contract:
# - the Rust harness exits on its own
# - the temp report directory is removed by the EXIT trap
set -euo pipefail

source "/home/alexm/mini-edr/tests/perf/perf_lib.sh"

trials="${MINI_EDR_PERF_LATENCY_TRIALS:-50}"
fixture_path="${MINI_EDR_PERF_LATENCY_FIXTURE:-/home/alexm/mini-edr/tests/fixtures/feature_vectors/reverse_shell.json}"
temp_dir="$(mktemp -d /tmp/mini-edr-perf-latency-XXXXXX)"
report_path="${temp_dir}/latency.json"

cleanup() {
  rm -rf "${temp_dir}"
}
trap cleanup EXIT

perf_require_harness
"${PERF_HARNESS_BIN}" latency \
  --trials "${trials}" \
  --fixture "${fixture_path}" \
  --report-path "${report_path}" >/dev/null

python3 - <<'PY' "${report_path}" "${trials}"
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
expected_trials = int(sys.argv[2])
assert report["alert_count_total"] == expected_trials, report
assert report["p99_ms"] < 5000.0, report
assert report["max_ms"] < 5000.0, report
print(json.dumps(report, indent=2, sort_keys=True))
PY

echo "PASS: reverse-shell alert-path latency stayed inside the 5 s budget"
