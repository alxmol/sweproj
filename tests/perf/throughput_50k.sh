#!/usr/bin/env bash
# throughput_50k.sh — measure sustained real-daemon throughput at live syscall load.
#
# Purpose:
# - launch the release daemon with live `connect` probes attached
# - drive a paced userspace `connect(2)` workload for 60 seconds through the
#   real kernel tracepoint path instead of the synthetic perf_harness
# - sample `/health` once per second so the report contains daemon-observed
#   ring-buffer throughput plus backpressure/drop counters over the run
#
# Expected result:
# - helper-generated throughput >= 50,000 real `connect(2)` syscalls/s
# - the daemon remains in the `Running` state while the helper runs
# - the report records the daemon's host-global ring-buffer receive/drop deltas
#   so operators can inspect real drop behavior during the run
#
# Cleanup contract:
# - the harness sweeps any orphaned daemon before it starts
# - the EXIT trap terminates the helper and daemon
# - privileged runs leave their `/tmp/mini-edr-*` evidence directory behind
set -euo pipefail

source "/home/directory/mini-edr/tests/perf/perf_lib.sh"

duration_seconds="${MINI_EDR_PERF_DURATION_SECONDS:-60}"
target_eps="${MINI_EDR_PERF_TARGET_EPS:-50000}"
min_observed_eps="${MINI_EDR_PERF_MIN_OBSERVED_EPS:-49000}"
thread_count="${MINI_EDR_PERF_LOAD_THREADS:-50}"
ring_buffer_pages="${MINI_EDR_PERF_RING_BUFFER_PAGES:-64}"
warmup_seconds="${MINI_EDR_PERF_WARMUP_SECONDS:-5}"
sentinel_host="${MINI_EDR_PERF_CONNECT_HOST:-127.0.0.1}"
sentinel_port="${MINI_EDR_PERF_CONNECT_PORT:-51234}"
temp_dir="$(mktemp -d /tmp/mini-edr-perf-throughput-XXXXXX)"
config_path="${temp_dir}/config.toml"
state_dir="${temp_dir}/state"
socket_path="${temp_dir}/mini-edr.sock"
daemon_log_path="${temp_dir}/daemon.log"
helper_bin="${temp_dir}/live_connect_load"
workload_report="${temp_dir}/workload.json"
health_samples_path="${temp_dir}/health.ndjson"
summary_path="${temp_dir}/throughput-summary.json"
daemon_pid=""
workload_pid=""
sampler_pid=""

cleanup() {
  perf_stop_pid "${sampler_pid:-}"
  perf_stop_pid "${workload_pid:-}"
  perf_stop_pid "${daemon_pid:-}"
  perf_cleanup_temp_dir "${temp_dir}"
}
trap cleanup EXIT

sample_health_forever() {
  local socket_path="$1"
  local output_path="$2"
  local started_at
  started_at="$(date +%s)"
  while true; do
    local now elapsed payload
    now="$(date +%s)"
    elapsed="$((now - started_at))"
    payload="$(perf_health_json "${socket_path}")"
    python3 - "${output_path}" "${elapsed}" "${payload}" <<'PY'
import json
import sys
from pathlib import Path

output_path = Path(sys.argv[1])
elapsed = int(sys.argv[2])
payload = json.loads(sys.argv[3])
with output_path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"elapsed_seconds": elapsed, "health": payload}, sort_keys=True) + "\n")
PY
    sleep 1
  done
}

perf_require_release_daemon
if ! perf_live_probe_mode_available; then
  echo "throughput_50k.sh requires root or a release daemon binary with the documented live-probe capabilities" >&2
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

: >"${health_samples_path}"
sample_health_forever "${socket_path}" "${health_samples_path}" &
sampler_pid="$!"

health_before_load="$(perf_health_json "${socket_path}")"
"${helper_bin}" "${sentinel_host}" "${sentinel_port}" "${duration_seconds}" "${target_eps}" "${thread_count}" "${workload_report}" &
workload_pid="$!"
wait "${workload_pid}"
workload_pid=""
sleep "${warmup_seconds}"
health_after_load="$(perf_health_json "${socket_path}")"
sleep 1
perf_stop_pid "${sampler_pid:-}"
sampler_pid=""

python3 - <<'PY' \
  "${workload_report}" "${health_samples_path}" "${summary_path}" "${min_observed_eps}" "${health_before_load}" "${health_after_load}"
import json
import sys
from pathlib import Path

workload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
samples = [
    json.loads(line)
    for line in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
    if line.strip()
]
summary_path = Path(sys.argv[3])
floor = float(sys.argv[4])
health_before_load = json.loads(sys.argv[5])
health_after_load = json.loads(sys.argv[6])

if len(samples) < 2:
    raise AssertionError("throughput harness collected fewer than two /health samples")

first = samples[0]
last = samples[-1]
elapsed_seconds = max(1, last["elapsed_seconds"] - first["elapsed_seconds"])
received_delta = (
    health_after_load["ring_events_received_total"]
    - health_before_load["ring_events_received_total"]
)
ring_drop_delta = (
    health_after_load["ring_events_dropped_total"]
    - health_before_load["ring_events_dropped_total"]
)
window_evict_delta = (
    health_after_load["windows_evicted_total"]
    - health_before_load["windows_evicted_total"]
)

summary = {
    "producer_report": workload,
    "health_samples_path": str(Path(sys.argv[2])),
    "daemon_ring_events_per_second": received_delta / elapsed_seconds,
    "ring_events_received_delta": received_delta,
    "ring_events_dropped_total": ring_drop_delta,
    "windows_evicted_total": window_evict_delta,
    "states_observed": sorted({sample["health"]["state"] for sample in samples}),
    "sample_count": len(samples),
}

assert workload["observed_events_per_second"] >= floor, summary
assert "Running" in summary["states_observed"], summary

summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
PY

echo "PASS: live real-syscall throughput run completed and recorded daemon drop counters"
