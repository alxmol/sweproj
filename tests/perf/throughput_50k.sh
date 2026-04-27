#!/usr/bin/env bash
# throughput_50k.sh — verify synthetic pipeline throughput against the 50k eps floor.
#
# Purpose:
# - drive the Rust perf_harness through a 60-second-equivalent synthetic event stream
# - prove feature extraction + inference capacity without depending on privileged probe startup
# - record observed events/sec, emitted feature-vector count, and drop count in JSON
#
# Expected result:
# - observed_events_per_second >= 50000
# - dropped_events_total == 0
#
# Cleanup contract:
# - the harness is foreground-only and exits on its own
# - the report file lives under a mktemp directory removed by the EXIT trap
set -euo pipefail

source "/home/alexm/mini-edr/tests/perf/perf_lib.sh"

duration_seconds="${MINI_EDR_PERF_DURATION_SECONDS:-60}"
target_eps="${MINI_EDR_PERF_TARGET_EPS:-60000}"
min_observed_eps="${MINI_EDR_PERF_MIN_OBSERVED_EPS:-50000}"
temp_dir="$(mktemp -d /tmp/mini-edr-perf-throughput-XXXXXX)"
report_path="${temp_dir}/throughput.json"

cleanup() {
  rm -rf "${temp_dir}"
}
trap cleanup EXIT

perf_require_harness
"${PERF_HARNESS_BIN}" throughput \
  --duration-seconds "${duration_seconds}" \
  --target-eps "${target_eps}" \
  --report-path "${report_path}" >/dev/null

python3 - <<'PY' "${report_path}" "${min_observed_eps}"
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
floor = float(sys.argv[2])
assert report["observed_events_per_second"] >= floor, report
assert report["dropped_events_total"] == 0, report
print(json.dumps(report, indent=2, sort_keys=True))
PY

echo "PASS: throughput floor and zero-drop synthetic replay verified"
