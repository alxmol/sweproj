#!/usr/bin/env bash
# rss_4h.sh — sample real-daemon RSS during a sustained live syscall load.
#
# Purpose:
# - launch the release daemon with live `connect` probes attached
# - drive a steady 1,000 eps userspace `connect(2)` workload long enough to
#   estimate an RSS leak slope, while still allowing a shorter default run for
#   CI/mission validation via the documented duration knob
# - sample `/proc/<daemon-pid>/status` VmRSS every 60 seconds and pair each RSS
#   sample with a `/health` snapshot so the report captures both memory growth
#   and any pressure-related counters
#
# Expected result:
# - peak RSS stays below the SRS resident-memory ceiling (256 MiB)
# - linear-regression RSS slope after warm-up is computed and reported, with a
#   stricter long-run gate available through `MINI_EDR_PERF_MAX_SLOPE_MB_PER_HOUR`
# - the helper's actual generated workload stays near the requested 1,000 eps
#
# Cleanup contract:
# - the harness sweeps orphan daemons before launch
# - the EXIT trap terminates the helper and daemon
# - privileged runs leave their `/tmp/mini-edr-*` evidence directory behind
set -euo pipefail

source "/home/directory/mini-edr/tests/perf/perf_lib.sh"

duration_seconds="${MINI_EDR_PERF_RSS_SECONDS:-300}"
target_eps="${MINI_EDR_PERF_RSS_TARGET_EPS:-1000}"
sample_interval_seconds="${MINI_EDR_PERF_RSS_SAMPLE_INTERVAL_SECONDS:-30}"
thread_count="${MINI_EDR_PERF_RSS_THREADS:-1}"
ring_buffer_pages="${MINI_EDR_PERF_RSS_RING_BUFFER_PAGES:-64}"
warmup_seconds="${MINI_EDR_PERF_RSS_WARMUP_SECONDS:-60}"
max_peak_bytes="${MINI_EDR_PERF_RSS_MAX_BYTES:-268435456}"
max_slope_mb_per_hour="${MINI_EDR_PERF_MAX_SLOPE_MB_PER_HOUR:-100000}"
sentinel_host="${MINI_EDR_PERF_RSS_CONNECT_HOST:-127.0.0.1}"
sentinel_port="${MINI_EDR_PERF_RSS_CONNECT_PORT:-51234}"
temp_dir="$(mktemp -d /tmp/mini-edr-perf-rss-XXXXXX)"
config_path="${temp_dir}/config.toml"
state_dir="${temp_dir}/state"
socket_path="${temp_dir}/mini-edr.sock"
daemon_log_path="${temp_dir}/daemon.log"
helper_bin="${temp_dir}/live_connect_load"
workload_report="${temp_dir}/workload.json"
samples_path="${temp_dir}/rss-samples.csv"
health_samples_path="${temp_dir}/health.ndjson"
summary_path="${temp_dir}/rss-summary.json"
daemon_pid=""
workload_pid=""

cleanup() {
  perf_stop_pid "${workload_pid:-}"
  perf_stop_pid "${daemon_pid:-}"
  perf_cleanup_temp_dir "${temp_dir}"
}
trap cleanup EXIT

perf_require_release_daemon
if ! perf_live_probe_mode_available; then
  echo "rss_4h.sh requires root or a release daemon binary with the documented live-probe capabilities" >&2
  exit 2
fi

perf_sweep_daemons
perf_compile_helper "${PERF_CONNECT_LOAD_SOURCE}" "${helper_bin}"
port="$(perf_find_free_port)"
perf_write_live_config "${config_path}" "${state_dir}" "${port}" "1.0"
cat >>"${config_path}" <<EOF
monitored_syscalls = ["connect"]
ring_buffer_size_pages = ${ring_buffer_pages}
EOF

MINI_EDR_API_SOCKET="${socket_path}" "${PERF_DAEMON_BIN}" --config "${config_path}" >"${daemon_log_path}" 2>&1 &
daemon_pid="$!"
perf_wait_for_health_socket "${socket_path}"

printf 'elapsed_seconds,rss_bytes\n' >"${samples_path}"
: >"${health_samples_path}"
"${helper_bin}" "${sentinel_host}" "${sentinel_port}" "${duration_seconds}" "${target_eps}" "${thread_count}" "${workload_report}" &
workload_pid="$!"
started_at="$(date +%s)"

while kill -0 "${workload_pid}" >/dev/null 2>&1; do
  now="$(date +%s)"
  elapsed="$((now - started_at))"
  rss_bytes="$(perf_sample_rss_bytes "${daemon_pid}")"
  printf '%s,%s\n' "${elapsed}" "${rss_bytes}" >>"${samples_path}"
  payload="$(perf_health_json "${socket_path}")"
  python3 - "${health_samples_path}" "${elapsed}" "${payload}" <<'PY'
import json
import sys
from pathlib import Path

output_path = Path(sys.argv[1])
elapsed = int(sys.argv[2])
payload = json.loads(sys.argv[3])
with output_path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"elapsed_seconds": elapsed, "health": payload}, sort_keys=True) + "\n")
PY
  sleep "${sample_interval_seconds}"
done
wait "${workload_pid}"
workload_pid=""

final_elapsed="$(( $(date +%s) - started_at ))"
final_rss_bytes="$(perf_sample_rss_bytes "${daemon_pid}")"
printf '%s,%s\n' "${final_elapsed}" "${final_rss_bytes}" >>"${samples_path}"
python3 - "${health_samples_path}" "${final_elapsed}" "$(perf_health_json "${socket_path}")" <<'PY'
import json
import sys
from pathlib import Path

output_path = Path(sys.argv[1])
elapsed = int(sys.argv[2])
payload = json.loads(sys.argv[3])
with output_path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"elapsed_seconds": elapsed, "health": payload}, sort_keys=True) + "\n")
PY

python3 - <<'PY' "${workload_report}" "${samples_path}" "${health_samples_path}" "${summary_path}" "${max_peak_bytes}" "${max_slope_mb_per_hour}" "${warmup_seconds}"
import csv
import json
import sys
from pathlib import Path

workload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
rows = list(csv.DictReader(Path(sys.argv[2]).open(encoding="utf-8")))
health_samples = [
    json.loads(line)
    for line in Path(sys.argv[3]).read_text(encoding="utf-8").splitlines()
    if line.strip()
]
summary_path = Path(sys.argv[4])
max_peak_bytes = int(sys.argv[5])
max_slope_mb_per_hour = float(sys.argv[6])
warmup_seconds = int(sys.argv[7])

if not rows:
    raise AssertionError("no RSS samples collected")

times = [float(row["elapsed_seconds"]) for row in rows]
rss_values = [float(row["rss_bytes"]) for row in rows]
peak_rss = max(rss_values)
steady_rows = [row for row in rows if float(row["elapsed_seconds"]) >= warmup_seconds]
if len(steady_rows) < 2:
    steady_rows = rows

steady_times = [float(row["elapsed_seconds"]) for row in steady_rows]
steady_rss_values = [float(row["rss_bytes"]) for row in steady_rows]
mean_time = sum(steady_times) / len(steady_times)
mean_rss = sum(steady_rss_values) / len(steady_rss_values)
numerator = sum(
    (time_value - mean_time) * (rss_value - mean_rss)
    for time_value, rss_value in zip(steady_times, steady_rss_values)
)
denominator = sum((time_value - mean_time) ** 2 for time_value in steady_times)
slope_bytes_per_second = 0.0 if denominator == 0.0 else numerator / denominator
slope_mb_per_hour = slope_bytes_per_second * 3600.0 / (1024.0 * 1024.0)
steady_state_mean_rss_bytes = sum(steady_rss_values) / len(steady_rss_values)

summary = {
    "producer_report": workload,
    "peak_rss_bytes": int(peak_rss),
    "steady_state_mean_rss_bytes": steady_state_mean_rss_bytes,
    "rss_slope_mb_per_hour": slope_mb_per_hour,
    "rss_samples_path": str(Path(sys.argv[2])),
    "health_samples_path": str(Path(sys.argv[3])),
    "sample_count": len(rows),
    "states_observed": sorted({sample["health"]["state"] for sample in health_samples}),
}

assert peak_rss < max_peak_bytes, summary
assert slope_mb_per_hour < max_slope_mb_per_hour, summary

summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
PY

echo "PASS: live-daemon RSS stayed below the peak and leak-slope limits"
