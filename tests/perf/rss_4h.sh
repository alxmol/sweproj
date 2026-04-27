#!/usr/bin/env bash
# rss_4h.sh — sample resident memory and growth slope during a steady synthetic load.
#
# Purpose:
# - run the Rust perf_harness in real-time `steady-load` mode for a configurable duration
# - sample `/proc/<pid>/status` VmRSS on a fixed cadence
# - report peak RSS and linear-regression slope so long-run validators can extend the same mechanism
#
# Expected result:
# - peak_rss_bytes < 268435456 (256 MiB)
# - rss slope < 1 MiB/minute (and therefore also below the stricter 1 MiB/hour contract)
#
# Cleanup contract:
# - the harness exits on its own after the requested duration
# - the temp report directory is removed by the EXIT trap
set -euo pipefail

source "/home/alexm/mini-edr/tests/perf/perf_lib.sh"

duration_seconds="${MINI_EDR_PERF_RSS_SECONDS:-120}"
target_eps="${MINI_EDR_PERF_RSS_TARGET_EPS:-5000}"
sample_interval_seconds="${MINI_EDR_PERF_RSS_SAMPLE_INTERVAL_SECONDS:-30}"
max_peak_bytes="${MINI_EDR_PERF_RSS_MAX_BYTES:-268435456}"
max_slope_mb_per_minute="${MINI_EDR_PERF_MAX_SLOPE_MB_PER_MINUTE:-1}"
temp_dir="$(mktemp -d /tmp/mini-edr-perf-rss-XXXXXX)"
report_path="${temp_dir}/steady-load.json"
samples_path="${temp_dir}/rss-samples.csv"

cleanup() {
  if [[ -n "${harness_pid:-}" ]] && kill -0 "${harness_pid}" >/dev/null 2>&1; then
    kill -TERM "${harness_pid}" >/dev/null 2>&1 || true
    wait "${harness_pid}" >/dev/null 2>&1 || true
  fi
  rm -rf "${temp_dir}"
}
trap cleanup EXIT

perf_require_harness
printf 'elapsed_seconds,rss_bytes\n' >"${samples_path}"
"${PERF_HARNESS_BIN}" steady-load \
  --duration-seconds "${duration_seconds}" \
  --target-eps "${target_eps}" \
  --report-path "${report_path}" >/dev/null &
harness_pid="$!"
started_at="$(date +%s)"

while kill -0 "${harness_pid}" >/dev/null 2>&1; do
  now="$(date +%s)"
  elapsed="$((now - started_at))"
  rss_bytes="$(perf_sample_rss_bytes "${harness_pid}")"
  printf '%s,%s\n' "${elapsed}" "${rss_bytes}" >>"${samples_path}"
  sleep "${sample_interval_seconds}"
done
wait "${harness_pid}"
harness_pid=""

python3 - <<'PY' "${report_path}" "${samples_path}" "${max_peak_bytes}" "${max_slope_mb_per_minute}"
import csv
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
rows = list(csv.DictReader(Path(sys.argv[2]).open(encoding="utf-8")))
max_peak_bytes = int(sys.argv[3])
max_slope_mb_per_minute = float(sys.argv[4])
assert rows, "no RSS samples collected"

times = [float(row["elapsed_seconds"]) for row in rows]
rss_bytes = [float(row["rss_bytes"]) for row in rows]
peak = max(rss_bytes)
steady_state_offset = max(1, len(rows) // 4)
steady_rows = rows[steady_state_offset:]
steady_times = [float(row["elapsed_seconds"]) for row in steady_rows]
steady_rss = [float(row["rss_bytes"]) for row in steady_rows]
mean_time = sum(steady_times) / len(steady_times)
mean_rss = sum(steady_rss) / len(steady_rss)
numerator = sum((t - mean_time) * (r - mean_rss) for t, r in zip(steady_times, steady_rss))
denominator = sum((t - mean_time) ** 2 for t in steady_times)
slope_bytes_per_second = 0.0 if denominator == 0.0 else numerator / denominator
slope_mb_per_minute = slope_bytes_per_second * 60.0 / (1024.0 * 1024.0)
slope_mb_per_hour = slope_bytes_per_second * 3600.0 / (1024.0 * 1024.0)

assert peak < max_peak_bytes, {"peak_rss_bytes": peak, "report": report}
assert slope_mb_per_minute < max_slope_mb_per_minute, {
    "slope_mb_per_minute": slope_mb_per_minute,
    "report": report,
}

summary = {
    "steady_load_report": report,
    "peak_rss_bytes": int(peak),
    "rss_slope_mb_per_minute": slope_mb_per_minute,
    "rss_slope_mb_per_hour": slope_mb_per_hour,
    "steady_state_samples": steady_rows,
    "samples": rows,
}
print(json.dumps(summary, indent=2, sort_keys=True))
PY

echo "PASS: steady-load RSS stayed below the peak and growth-slope limits"
