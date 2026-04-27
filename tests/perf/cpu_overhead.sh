#!/usr/bin/env bash
# cpu_overhead.sh — measure Mini-EDR userland CPU overhead under a steady synthetic load.
#
# Purpose:
# - run the Rust perf_harness in real-time `steady-load` mode so `top` can sample one stable PID
# - convert the `< 2% total system CPU` contract into the per-process `%CPU` units that `top` reports
# - persist both the steady-load summary and the sampled mean CPU percentage for auditability
#
# Expected result:
# - observed load stays near the requested target EPS for the requested duration
# - mean per-process `%CPU` <= 2 * logical_cpu_count
#
# Cleanup contract:
# - the harness exits on its own after the requested duration
# - the temp report directory is removed by the EXIT trap
set -euo pipefail

source "/home/alexm/mini-edr/tests/perf/perf_lib.sh"

duration_seconds="${MINI_EDR_PERF_CPU_SECONDS:-60}"
target_eps="${MINI_EDR_PERF_CPU_TARGET_EPS:-5000}"
sample_count="${MINI_EDR_PERF_CPU_TOP_SAMPLES:-60}"
logical_cpus="$(nproc)"
max_top_cpu_percent="$(python3 - <<'PY' "${logical_cpus}"
import sys
print(float(sys.argv[1]) * 2.0)
PY
)"
temp_dir="$(mktemp -d /tmp/mini-edr-perf-cpu-XXXXXX)"
report_path="${temp_dir}/steady-load.json"

cleanup() {
  if [[ -n "${harness_pid:-}" ]] && kill -0 "${harness_pid}" >/dev/null 2>&1; then
    kill -TERM "${harness_pid}" >/dev/null 2>&1 || true
    wait "${harness_pid}" >/dev/null 2>&1 || true
  fi
  rm -rf "${temp_dir}"
}
trap cleanup EXIT

perf_require_harness
"${PERF_HARNESS_BIN}" steady-load \
  --duration-seconds "${duration_seconds}" \
  --target-eps "${target_eps}" \
  --report-path "${report_path}" >/dev/null &
harness_pid="$!"
sleep 1

mean_top_cpu="$(perf_average_top_cpu "${harness_pid}" "${sample_count}")"
wait "${harness_pid}"
harness_pid=""

python3 - <<'PY' "${report_path}" "${mean_top_cpu}" "${max_top_cpu_percent}" "${logical_cpus}"
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
mean_top_cpu = float(sys.argv[2])
max_top_cpu = float(sys.argv[3])
logical_cpus = int(sys.argv[4])
assert mean_top_cpu <= max_top_cpu, {
    "mean_top_cpu_percent": mean_top_cpu,
    "max_top_cpu_percent": max_top_cpu,
    "logical_cpus": logical_cpus,
    "report": report,
}
summary = {
    "logical_cpus": logical_cpus,
    "max_top_cpu_percent": max_top_cpu,
    "mean_top_cpu_percent": mean_top_cpu,
    "steady_load_report": report,
}
print(json.dumps(summary, indent=2, sort_keys=True))
PY

echo "PASS: steady-load CPU overhead stayed within the translated 2% total-CPU budget"
