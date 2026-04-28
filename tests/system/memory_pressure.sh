#!/usr/bin/env bash
# memory_pressure.sh — verify real cgroup near-cap behavior at memory.max=240M.
#
# Purpose:
# - re-exec the harness inside a transient `systemd-run --scope -p MemoryMax=240M`
#   so every helper process, alert generator, and the daemon itself share the
#   same cgroup-v2 memory ceiling required by scrutiny round 1
# - keep the cgroup at >=95% of `memory.max` for at least 60 seconds with a
#   dedicated memory hog while a live high-rate connect workload drives
#   BackPressure-visible drop counters
# - continue spawning short-lived one-connect helper PIDs so the harness can
#   prove alerts still arrive throughout the sustained near-cap interval
#
# Expected result:
# - the daemon survives the full run without any `oom_kill` events in the scope
# - the cgroup stays at or above the target near-cap ratio for >=60 seconds
# - `/api/health` shows BackPressure (or equivalent shed-load counters) while
#   PID-matched alerts continue to arrive during the sustained near-cap window
#
# Cleanup contract:
# - an EXIT trap stops the daemon and helper PIDs started by this harness
# - privileged runs hand temp-dir cleanup to availability_cleanup_temp_dir so
#   the mission's deferred `/tmp/mini-edr-*` sweep remains intact
set -euo pipefail

script_path="$(readlink -f "$0")"
if [[ "${MINI_EDR_MEMORY_PRESSURE_IN_SCOPE:-0}" != "1" ]]; then
  exec systemd-run --quiet --scope -p MemoryMax=240M env MINI_EDR_MEMORY_PRESSURE_IN_SCOPE=1 PATH="$PATH" "${script_path}" "$@"
fi

source "/home/alexm/mini-edr/tests/system/availability_lib.sh"

duration_arg="${MINI_EDR_MEMORY_PRESSURE_DURATION:-90s}"
sustain_arg="${MINI_EDR_MEMORY_PRESSURE_SUSTAIN:-60s}"
inject_every_arg="${MINI_EDR_MEMORY_PRESSURE_INJECT_EVERY:-5s}"
report_path=""
target_ratio="${MINI_EDR_MEMORY_PRESSURE_TARGET_RATIO:-0.95}"
alert_eps="${MINI_EDR_MEMORY_PRESSURE_ALERT_EPS:-2}"
alert_linger_ms="${MINI_EDR_MEMORY_PRESSURE_ALERT_LINGER_MS:-1000}"
load_eps="${MINI_EDR_MEMORY_PRESSURE_LOAD_EPS:-50000}"
load_threads="${MINI_EDR_MEMORY_PRESSURE_LOAD_THREADS:-50}"
ring_buffer_pages="${MINI_EDR_MEMORY_PRESSURE_RING_BUFFER_PAGES:-4}"
max_active_windows="${MINI_EDR_MEMORY_PRESSURE_MAX_ACTIVE_WINDOWS:-64}"
port_base="${MINI_EDR_MEMORY_PRESSURE_PORT_BASE:-54000}"
failure_reason=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration)
      duration_arg="$2"
      shift 2
      ;;
    --sustain)
      sustain_arg="$2"
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
sustain_seconds="$(availability_parse_duration_seconds "${sustain_arg}")"
inject_every_seconds="$(availability_parse_duration_seconds "${inject_every_arg}")"
if (( duration_seconds < sustain_seconds )); then
  echo "duration must be at least as long as the required sustained near-cap window" >&2
  exit 2
fi

cgroup_relative_path="$(awk -F: '$1 == "0" {print $3}' /proc/self/cgroup)"
memory_cgroup_path="/sys/fs/cgroup${cgroup_relative_path}"
memory_max_raw="$(cat "${memory_cgroup_path}/memory.max")"
if [[ "${memory_max_raw}" == "max" ]]; then
  echo "memory.max is unlimited inside the transient scope; expected systemd-run to apply MemoryMax=240M" >&2
  exit 1
fi

temp_dir="$(mktemp -d /tmp/mini-edr-memory-pressure-XXXXXX)"
helper_bin="${temp_dir}/live_connect_latency"
load_helper_bin="${temp_dir}/live_connect_load"
metadata_dir="${temp_dir}/metadata"
event_map_path="${temp_dir}/port-host-pid-map.json"
alert_spawner_report_path="${temp_dir}/alert-spawner.json"
load_report_path="${temp_dir}/live-load.json"
health_snapshots_path="${temp_dir}/health-snapshots.ndjson"
stream_capture_path="${temp_dir}/alerts-stream.jsonl"
injections_path="${temp_dir}/injections.jsonl"
hog_samples_path="${temp_dir}/memory-current.ndjson"
hog_summary_path="${temp_dir}/memory-hog-summary.json"
summary_path="${report_path:-${temp_dir}/summary.json}"
fixtures=(
  "reverse_shell"
  "privesc_setuid"
  "cryptominer_emulator"
  "port_scan"
)

cleanup() {
  if [[ -n "${stream_pid:-}" ]]; then
    fixture_stop_alert_stream "${stream_pid}"
  fi
  perf_stop_pid "${event_poller_pid:-}"
  perf_stop_pid "${alert_spawner_pid:-}"
  perf_stop_pid "${load_pid:-}"
  perf_stop_pid "${hog_pid:-}"
  if [[ -n "${daemon_pid:-}" ]]; then
    availability_stop_daemon "${daemon_pid}"
  fi
  if [[ -z "${report_path}" ]]; then
    availability_cleanup_temp_dir "${temp_dir}"
  fi
}
trap cleanup EXIT

availability_sweep_daemons
availability_compile_connect_helper "${helper_bin}"
availability_compile_connect_load_helper "${load_helper_bin}"
read -r daemon_pid daemon_port daemon_config_path daemon_log_path daemon_socket alert_log_path < <(
  MINI_EDR_TEST_MAX_ACTIVE_WINDOWS="${max_active_windows}" \
    availability_start_live_daemon "${temp_dir}" "0.0" "connect" "${ring_buffer_pages}" "30"
)
stream_pid="$(fixture_start_alert_stream "${daemon_socket}" "${stream_capture_path}")"

run_started_ns="$(date +%s%N)"
: >"${health_snapshots_path}"
port_span="$("${FIXTURE_PYTHON_BIN}" - "${duration_seconds}" "${alert_eps}" <<'PY'
import math
import sys

duration_seconds = float(sys.argv[1])
events_per_second = float(sys.argv[2])
print(int(math.ceil(duration_seconds * events_per_second)) + 16)
PY
)"
python3 - "${daemon_port}" "${port_base}" "${port_span}" "${duration_seconds}" "${event_map_path}" <<'PY' &
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

daemon_port = int(sys.argv[1])
port_base = int(sys.argv[2])
port_span = int(sys.argv[3])
duration_seconds = float(sys.argv[4])
output_path = Path(sys.argv[5])
deadline = time.time() + duration_seconds + 5.0
mapped_ports = {}
url = f"http://127.0.0.1:{daemon_port}/api/events?limit=4096"

while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=2.0) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        time.sleep(0.1)
        continue

    for event in payload:
        if event.get("syscall_type") != "Connect":
            continue
        port = event.get("port")
        pid = event.get("pid")
        if isinstance(port, int) and isinstance(pid, int) and port_base <= port < port_base + port_span:
            mapped_ports[str(port)] = pid
    time.sleep(0.1)

output_path.write_text(json.dumps(mapped_ports, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(mapped_ports, indent=2, sort_keys=True))
PY
event_poller_pid="$!"
python3 "/home/alexm/mini-edr/tests/system/cgroup_memory_hog.py" \
  --memory-current-path "${memory_cgroup_path}/memory.current" \
  --memory-max-path "${memory_cgroup_path}/memory.max" \
  --memory-events-path "${memory_cgroup_path}/memory.events" \
  --target-ratio "${target_ratio}" \
  --hold-seconds "${duration_seconds}" \
  --sample-interval-seconds 1 \
  --samples-path "${hog_samples_path}" \
  --summary-path "${hog_summary_path}" &
hog_pid="$!"

"${load_helper_bin}" "127.0.0.1" "51234" "${duration_seconds}" "${load_eps}" "${load_threads}" "${load_report_path}" &
load_pid="$!"
python3 "/home/alexm/mini-edr/tests/system/live_connect_spawner.py" \
  --helper-bin "${helper_bin}" \
  --host "127.0.0.1" \
  --port-base "${port_base}" \
  --events-per-second "${alert_eps}" \
  --duration-seconds "${duration_seconds}" \
  --linger-ms "${alert_linger_ms}" \
  --metadata-dir "${metadata_dir}" \
  --report-path "${alert_spawner_report_path}" &
alert_spawner_pid="$!"

started_at="$(date +%s)"
next_injection_at="${started_at}"
injection_index=0
while true; do
  now="$(date +%s)"
  elapsed="$((now - started_at))"
  if (( elapsed >= duration_seconds )); then
    break
  fi
  if ! kill -0 "${daemon_pid}" >/dev/null 2>&1; then
    failure_reason="daemon_exited_under_memory_pressure"
    break
  fi
  health_json="$(availability_health_json "${daemon_port}")"
  python3 - "${health_snapshots_path}" "${elapsed}" "${health_json}" <<'PY'
import json
import sys
from pathlib import Path

output_path = Path(sys.argv[1])
elapsed = int(sys.argv[2])
payload = json.loads(sys.argv[3])
with output_path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"elapsed_seconds": elapsed, "health": payload}, sort_keys=True) + "\n")
PY
  if (( now >= next_injection_at )); then
    fixture_name="${fixtures[$((injection_index % ${#fixtures[@]}))]}"
    fixture_script="/home/alexm/mini-edr/tests/fixtures/malware/${fixture_name}.sh"
    start_line="$(fixture_stream_line_count "${stream_capture_path}")"
    result_json="$("${fixture_script}" --daemon-port "${daemon_port}" --trial "${injection_index}")"
    expected_binary_path="$(fixture_json_get "${result_json}" "expected_binary_path")"
    expected_pid="$(fixture_json_get "${result_json}" "pid")"
    if correlated_alerts_json="$(fixture_wait_for_correlated_alerts "${stream_capture_path}" "${expected_binary_path}" "${expected_pid}" "${start_line}" 10)"; then
      :
    else
      correlated_alerts_json="[]"
    fi
    "${FIXTURE_PYTHON_BIN}" - "${result_json}" "${correlated_alerts_json}" "${elapsed}" >>"${injections_path}" <<'PY'
import json
import sys

fixture_result = json.loads(sys.argv[1])
correlated_alerts = json.loads(sys.argv[2])
elapsed = int(sys.argv[3])
fixture_result["elapsed_seconds"] = elapsed
fixture_result["correlated_alerts"] = correlated_alerts
fixture_result["detected"] = bool(correlated_alerts)
print(json.dumps(fixture_result, separators=(",", ":")))
PY
    injection_index="$((injection_index + 1))"
    next_injection_at="$((now + inject_every_seconds))"
  fi
  sleep 1
done

wait "${alert_spawner_pid}" || failure_reason="${failure_reason:-alert_spawner_failed}"
alert_spawner_pid=""
wait "${event_poller_pid}" || failure_reason="${failure_reason:-event_poller_failed}"
event_poller_pid=""
wait "${load_pid}" || failure_reason="${failure_reason:-live_connect_load_failed}"
load_pid=""
wait "${hog_pid}" || failure_reason="${failure_reason:-memory_hog_failed}"
hog_pid=""

if [[ -z "${failure_reason}" ]] && kill -0 "${daemon_pid}" >/dev/null 2>&1; then
  final_health_json="$(availability_health_json "${daemon_port}")"
else
  final_health_json='{}'
fi
sleep 5
availability_stop_daemon "${daemon_pid}"
daemon_pid=""

"${FIXTURE_PYTHON_BIN}" - \
  "${metadata_dir}" \
  "${alert_log_path}" \
  "${event_map_path}" \
  "${alert_spawner_report_path}" \
  "${load_report_path}" \
  "${health_snapshots_path}" \
  "${injections_path}" \
  "${hog_summary_path}" \
  "${summary_path}" \
  "${daemon_log_path}" \
  "${daemon_config_path}" \
  "${memory_cgroup_path}" \
  "${run_started_ns}" \
  "${sustain_seconds}" \
  "${failure_reason}" \
  "${final_health_json}" <<'PY'
import json
import sys
from datetime import datetime
from pathlib import Path

metadata_dir = Path(sys.argv[1])
alert_log_path = Path(sys.argv[2])
event_map = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
alert_spawner_report = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
load_report = json.loads(Path(sys.argv[5]).read_text(encoding="utf-8"))
health_samples = [
    json.loads(line)
    for line in Path(sys.argv[6]).read_text(encoding="utf-8").splitlines()
    if line.strip()
]
injection_records = [
    json.loads(line)
    for line in Path(sys.argv[7]).read_text(encoding="utf-8").splitlines()
    if line.strip()
]
hog_summary = json.loads(Path(sys.argv[8]).read_text(encoding="utf-8"))
summary_path = Path(sys.argv[9])
daemon_log_path = sys.argv[10]
daemon_config_path = sys.argv[11]
memory_cgroup_path = sys.argv[12]
run_started_ns = int(sys.argv[13])
sustain_seconds = int(sys.argv[14])
failure_reason = sys.argv[15]
final_health = json.loads(sys.argv[16])

launch_records = []
for launch in alert_spawner_report["launches"]:
    metadata_path = Path(launch["metadata_path"])
    if not metadata_path.exists():
        continue
    metadata_payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    assigned_port = launch["assigned_port"]
    host_pid = event_map.get(str(assigned_port))
    launch_records.append(
        {
            "assigned_port": assigned_port,
            "host_pid": host_pid,
            "start_ns": int(metadata_payload["start_ns"]),
        }
    )

alerts_by_pid = {}
alert_timestamps_ns = []
if alert_log_path.exists():
    for line in alert_log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        pid = payload.get("pid")
        if isinstance(pid, int):
            alerts_by_pid[pid] = payload
        timestamp = payload.get("timestamp")
        if isinstance(timestamp, str):
            alert_timestamps_ns.append(
                int(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp() * 1_000_000_000)
            )

ring_drop_values = [
    sample["health"]["ring_events_dropped_total"]
    for sample in health_samples
]
window_evict_values = [
    sample["health"]["windows_evicted_total"]
    for sample in health_samples
]
states_observed = sorted({sample["health"]["state"] for sample in health_samples})
ring_drop_delta = max(ring_drop_values, default=0) - min(ring_drop_values, default=0)
window_evict_delta = max(window_evict_values, default=0) - min(window_evict_values, default=0)
backpressure_seen = (
    "BackPressure" in states_observed
    or ring_drop_delta > 0
    or window_evict_delta > 0
)
longest_start_seconds = hog_summary["longest_streak_start_seconds"]
longest_end_seconds = hog_summary["longest_streak_end_seconds"]
alerts_during_sustained_window = 0
alerts_per_bucket = []
if longest_start_seconds is not None and longest_end_seconds is not None:
    interval_start_ns = run_started_ns + int(longest_start_seconds * 1_000_000_000)
    interval_end_ns = interval_start_ns + sustain_seconds * 1_000_000_000
    bucket_size_ns = max(1, sustain_seconds // 4) * 1_000_000_000
    for bucket_start in range(interval_start_ns, interval_end_ns, bucket_size_ns):
        bucket_end = min(interval_end_ns, bucket_start + bucket_size_ns)
        bucket_count = sum(
            1
            for injection in injection_records
            if injection.get("detected")
            and bucket_start
            <= run_started_ns + int(injection.get("elapsed_seconds", 0)) * 1_000_000_000
            < bucket_end
        )
        alerts_per_bucket.append(bucket_count)
    alerts_during_sustained_window = sum(alerts_per_bucket)
else:
    interval_start_ns = None
    interval_end_ns = None

summary = {
    "mode": "memory_pressure",
    "daemon_log_path": daemon_log_path,
    "daemon_config_path": daemon_config_path,
    "memory_cgroup_path": memory_cgroup_path,
    "failure_reason": failure_reason,
    "final_health": final_health,
    "health_samples_path": str(Path(sys.argv[6])),
    "memory_hog_summary": hog_summary,
    "alert_spawner_report": alert_spawner_report,
    "load_report": load_report,
    "injections_path": str(Path(sys.argv[7])),
    "detected_injection_count": sum(1 for injection in injection_records if injection.get("detected")),
    "states_observed": states_observed,
    "ring_events_dropped_delta": ring_drop_delta,
    "windows_evicted_delta": window_evict_delta,
    "backpressure_seen": backpressure_seen,
    "mapped_helper_pid_count": sum(1 for payload in launch_records if isinstance(payload["host_pid"], int)),
    "matched_alert_pid_count": sum(
        1 for payload in launch_records if isinstance(payload["host_pid"], int) and payload["host_pid"] in alerts_by_pid
    ),
    "alerts_during_sustained_window": alerts_during_sustained_window,
    "alerts_per_bucket": alerts_per_bucket,
    "sustained_window_start_ns": interval_start_ns,
    "sustained_window_end_ns": interval_end_ns,
    "pass": (
        not failure_reason
        and bool(final_health)
        and hog_summary["oom_kill_delta"] == 0
        and hog_summary["max_contiguous_seconds_at_or_above_target"] >= sustain_seconds
        and backpressure_seen
        and all(bucket_count > 0 for bucket_count in alerts_per_bucket)
    ),
}

summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
if not summary["pass"]:
    raise SystemExit("memory-pressure availability contract failed")
PY

echo "PASS: real cgroup memory pressure kept the daemon alive near the 240M cap"
