#!/usr/bin/env bash
# cpu_overhead.sh — measure daemon CPU delta under a real live-syscall load.
#
# Purpose:
# - launch the release daemon with live `connect` probes attached
# - record `/proc/<daemon-pid>/stat` user+system tick deltas over a 60-second
#   idle baseline and a second 60-second load phase
# - drive the load phase with the real userspace `connect(2)` helper instead of
#   the synthetic in-process perf_harness
# - assert that the daemon's additional CPU consumption attributable to a
#   normal-load real-syscall workload stays below the updated 5% budget
#
# Expected result:
# - helper-generated throughput stays at or above the configured normal-load
#   floor during the load phase
# - load-phase daemon CPU percent minus baseline daemon CPU percent < 5.0
#
# Cleanup contract:
# - the harness sweeps orphan daemons before launch
# - the EXIT trap terminates the helper and daemon
# - privileged runs leave their `/tmp/mini-edr-*` evidence directory behind
set -euo pipefail

source "/home/directory/mini-edr/tests/perf/perf_lib.sh"

phase_seconds="${MINI_EDR_PERF_CPU_SECONDS:-60}"
target_eps="${MINI_EDR_PERF_CPU_TARGET_EPS:-5000}"
min_observed_eps="${MINI_EDR_PERF_CPU_MIN_OBSERVED_EPS:-4000}"
thread_count="${MINI_EDR_PERF_CPU_THREADS:-5}"
ring_buffer_pages="${MINI_EDR_PERF_CPU_RING_BUFFER_PAGES:-64}"
max_additional_cpu_percent="${MINI_EDR_PERF_CPU_MAX_DELTA_PERCENT:-5}"
sentinel_host="${MINI_EDR_PERF_CPU_CONNECT_HOST:-127.0.0.1}"
sentinel_port="${MINI_EDR_PERF_CPU_CONNECT_PORT:-51234}"
temp_dir="$(mktemp -d /tmp/mini-edr-perf-cpu-XXXXXX)"
config_path="${temp_dir}/config.toml"
state_dir="${temp_dir}/state"
socket_path="${temp_dir}/mini-edr.sock"
daemon_log_path="${temp_dir}/daemon.log"
helper_bin="${temp_dir}/live_connect_load"
workload_report="${temp_dir}/workload.json"
summary_path="${temp_dir}/cpu-summary.json"
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
  echo "cpu_overhead.sh requires root or a release daemon binary with the documented live-probe capabilities" >&2
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

baseline_started_at="$(python3 - <<'PY'
import time
print(time.monotonic())
PY
)"
baseline_health_before="$(perf_health_json "${socket_path}")"
baseline_start_ticks="$(perf_read_cpu_ticks "${daemon_pid}")"
sleep "${phase_seconds}"
baseline_end_ticks="$(perf_read_cpu_ticks "${daemon_pid}")"
baseline_finished_at="$(python3 - <<'PY'
import time
print(time.monotonic())
PY
)"
baseline_health_after="$(perf_health_json "${socket_path}")"

health_before_load="${baseline_health_after}"
load_started_at="$(python3 - <<'PY'
import time
print(time.monotonic())
PY
)"
load_start_ticks="$(perf_read_cpu_ticks "${daemon_pid}")"
"${helper_bin}" "${sentinel_host}" "${sentinel_port}" "${phase_seconds}" "${target_eps}" "${thread_count}" "${workload_report}" &
workload_pid="$!"
wait "${workload_pid}"
workload_pid=""
load_end_ticks="$(perf_read_cpu_ticks "${daemon_pid}")"
load_finished_at="$(python3 - <<'PY'
import time
print(time.monotonic())
PY
)"
health_after_load="$(perf_health_json "${socket_path}")"

python3 - <<'PY' \
  "${baseline_started_at}" "${baseline_finished_at}" "${baseline_start_ticks}" "${baseline_end_ticks}" \
  "${load_started_at}" "${load_finished_at}" "${load_start_ticks}" "${load_end_ticks}" \
  "${workload_report}" "${summary_path}" "${min_observed_eps}" "${max_additional_cpu_percent}" \
  "${health_before_load}" "${health_after_load}" "${baseline_health_before}" "${baseline_health_after}"
import json
import os
import sys
from pathlib import Path

baseline_started_at = float(sys.argv[1])
baseline_finished_at = float(sys.argv[2])
baseline_start_ticks = int(sys.argv[3])
baseline_end_ticks = int(sys.argv[4])
load_started_at = float(sys.argv[5])
load_finished_at = float(sys.argv[6])
load_start_ticks = int(sys.argv[7])
load_end_ticks = int(sys.argv[8])
workload = json.loads(Path(sys.argv[9]).read_text(encoding="utf-8"))
summary_path = Path(sys.argv[10])
throughput_floor = float(sys.argv[11])
max_additional_cpu_percent = float(sys.argv[12])
health_before = json.loads(sys.argv[13])
health_after = json.loads(sys.argv[14])
baseline_health_before = json.loads(sys.argv[15])
baseline_health_after = json.loads(sys.argv[16])

clock_ticks_per_second = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
baseline_elapsed = baseline_finished_at - baseline_started_at
load_elapsed = load_finished_at - load_started_at
baseline_cpu_percent = (
    (baseline_end_ticks - baseline_start_ticks) / clock_ticks_per_second / baseline_elapsed * 100.0
)
load_cpu_percent = (
    (load_end_ticks - load_start_ticks) / clock_ticks_per_second / load_elapsed * 100.0
)
additional_cpu_percent = load_cpu_percent - baseline_cpu_percent
baseline_daemon_observed_eps = (
    baseline_health_after["ring_events_received_total"] - baseline_health_before["ring_events_received_total"]
) / baseline_elapsed
raw_daemon_observed_eps = (
    health_after["ring_events_received_total"] - health_before["ring_events_received_total"]
) / load_elapsed
daemon_observed_eps = max(0.0, raw_daemon_observed_eps - baseline_daemon_observed_eps)

summary = {
    "baseline_cpu_percent": baseline_cpu_percent,
    "load_cpu_percent": load_cpu_percent,
    "additional_cpu_percent": additional_cpu_percent,
    "clock_ticks_per_second": clock_ticks_per_second,
    "baseline_elapsed_seconds": baseline_elapsed,
    "load_elapsed_seconds": load_elapsed,
    "baseline_daemon_observed_events_per_second": baseline_daemon_observed_eps,
    "raw_daemon_observed_events_per_second": raw_daemon_observed_eps,
    "daemon_observed_events_per_second": daemon_observed_eps,
    "ring_events_dropped_delta": (
        health_after["ring_events_dropped_total"] - health_before["ring_events_dropped_total"]
    ),
    "windows_evicted_delta": (
        health_after["windows_evicted_total"] - health_before["windows_evicted_total"]
    ),
    "producer_report": workload,
}

assert workload["observed_events_per_second"] >= throughput_floor, summary
assert additional_cpu_percent < max_additional_cpu_percent, summary

summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
PY

echo "PASS: real-daemon CPU overhead stayed inside the additional 5% budget"
