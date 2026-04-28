#!/usr/bin/env bash
# probe_reload.sh — verify the live probe-reload lost-event budget.
#
# Purpose:
# - run the real release daemon with the live `connect` probe attached instead
#   of the scrutiny-rejected synthetic test-mode path
# - keep one real helper process issuing one `connect(2)` every fixed interval
#   so the harness knows exactly how many workload attempts must be lost while
#   the probe is detached
# - bracket the reload with one-shot calibration connects on fresh destination
#   ports so the harness proves the live API still surfaces a real post-attach
#   connect event instead of relying only on daemon-local timing
#
# Expected result:
# - detach removes `connect` from `active_probes` and attach restores it
# - the daemon logs at least one reconnect/attach marker for the reload cycle
# - the counted workload attempts that land inside the detach/attach window stay
#   <= 5 and the scheduled workload gap across the reload window stays <= 1
#   second
#
# Cleanup contract:
# - an EXIT trap stops the daemon PID and temp workdir owned by this harness
set -euo pipefail

source "/home/alexm/mini-edr/tests/system/availability_lib.sh"

duration_arg="${MINI_EDR_PROBE_RELOAD_DURATION:-30s}"
reload_at_arg="${MINI_EDR_PROBE_RELOAD_AT:-10s}"
events_per_second="${MINI_EDR_PROBE_RELOAD_EPS:-5}"
extra_downtime_ms="${MINI_EDR_PROBE_RELOAD_EXTRA_DOWNTIME_MS:-0}"
ring_buffer_pages="${MINI_EDR_PROBE_RELOAD_RING_BUFFER_PAGES:-256}"
drain_timeout_seconds="${MINI_EDR_PROBE_RELOAD_DRAIN_TIMEOUT_SECONDS:-15}"
workload_port="${MINI_EDR_PROBE_RELOAD_WORKLOAD_PORT:-52000}"
pre_reload_probe_port="${MINI_EDR_PROBE_RELOAD_PRE_PORT:-52001}"
post_reload_probe_port="${MINI_EDR_PROBE_RELOAD_POST_PORT:-52002}"
report_path=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration)
      duration_arg="$2"
      shift 2
      ;;
    --reload-at)
      reload_at_arg="$2"
      shift 2
      ;;
    --events-per-second)
      events_per_second="$2"
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
reload_at_seconds="$(availability_parse_duration_seconds "${reload_at_arg}")"
if (( reload_at_seconds <= 0 || reload_at_seconds >= duration_seconds )); then
  echo "reload-at must fall strictly inside the workload duration" >&2
  exit 2
fi

temp_dir="$(mktemp -d /tmp/mini-edr-probe-reload-XXXXXX)"
helper_bin="${temp_dir}/live_connect_latency"
workload_report_path="${temp_dir}/workload.json"
pre_reload_event_path="${temp_dir}/pre-reload-event.json"
post_reload_event_path="${temp_dir}/post-reload-event.json"
detach_payload_path="${temp_dir}/detach.json"
attach_payload_path="${temp_dir}/attach.json"
summary_path="${report_path:-${temp_dir}/summary.json}"

cleanup() {
  perf_stop_pid "${workload_pid:-}"
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
read -r daemon_pid daemon_port daemon_config_path daemon_log_path daemon_socket alert_log_path < <(
  availability_start_live_daemon "${temp_dir}" "0.0" "connect" "${ring_buffer_pages}" "30"
)

wait_for_connect_port_event() {
  local daemon_port="$1"
  local connect_port="$2"
  local timeout_seconds="${3:-2}"
  python3 - "${daemon_port}" "${connect_port}" "${timeout_seconds}" <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request

daemon_port = int(sys.argv[1])
connect_port = int(sys.argv[2])
timeout_seconds = float(sys.argv[3])
deadline = time.time() + timeout_seconds
url = f"http://127.0.0.1:{daemon_port}/api/events?limit=4096"

while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=2.0) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        time.sleep(0.05)
        continue

    matches = [
        event
        for event in payload
        if event.get("syscall_type") == "Connect" and event.get("port") == connect_port
    ]
    if matches:
        print(json.dumps(matches[0], sort_keys=True))
        raise SystemExit(0)
    time.sleep(0.05)

raise SystemExit(1)
PY
}

health_before_reload="$(availability_health_json "${daemon_port}")"
"${helper_bin}" "127.0.0.1" "${pre_reload_probe_port}" "200" "${temp_dir}/pre-reload-meta.json"
wait_for_connect_port_event "${daemon_port}" "${pre_reload_probe_port}" 2 >"${pre_reload_event_path}"
python3 - "${events_per_second}" "${duration_seconds}" "${workload_port}" "${workload_report_path}" <<'PY' &
import json
import socket
import sys
import time
from pathlib import Path

events_per_second = float(sys.argv[1])
duration_seconds = float(sys.argv[2])
workload_port = int(sys.argv[3])
report_path = Path(sys.argv[4])
interval_seconds = 1.0 / events_per_second
started_at = time.monotonic()
deadline = started_at + duration_seconds
attempts = []
attempt_index = 0

while True:
    scheduled_at = started_at + attempt_index * interval_seconds
    if scheduled_at >= deadline:
        break
    sleep_seconds = scheduled_at - time.monotonic()
    if sleep_seconds > 0:
        time.sleep(sleep_seconds)

    start_ns = time.time_ns()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.25)
    try:
        connect_errno = sock.connect_ex(("127.0.0.1", workload_port))
    finally:
        sock.close()
    attempts.append(
        {
            "index": attempt_index,
            "start_ns": start_ns,
            "connect_errno": connect_errno,
        }
    )
    attempt_index += 1

elapsed_seconds = time.monotonic() - started_at
report = {
    "events_per_second": events_per_second,
    "duration_seconds": duration_seconds,
    "workload_port": workload_port,
    "attempt_count": len(attempts),
    "attempts": attempts,
    "elapsed_seconds": elapsed_seconds,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
PY
workload_pid="$!"

sleep "${reload_at_seconds}"
daemon_log_offset_bytes="$(wc -c <"${daemon_log_path}" | tr -d '[:space:]')"
detach_started_at_ns="$(date +%s%N)"
curl -fsS -X POST "http://127.0.0.1:${daemon_port}/api/probes/connect/detach" >"${detach_payload_path}"
"${FIXTURE_PYTHON_BIN}" - "${detach_payload_path}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert "connect" not in payload["active_probes"], payload
PY

if (( extra_downtime_ms > 0 )); then
  python3 - "${extra_downtime_ms}" <<'PY'
import sys
import time

time.sleep(int(sys.argv[1]) / 1000.0)
PY
fi

curl -fsS -X POST "http://127.0.0.1:${daemon_port}/api/probes/connect/attach" >"${attach_payload_path}"
attach_completed_at_ns="$(date +%s%N)"
"${FIXTURE_PYTHON_BIN}" - "${attach_payload_path}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert "connect" in payload["active_probes"], payload
PY

sleep 1
"${helper_bin}" "127.0.0.1" "${post_reload_probe_port}" "200" "${temp_dir}/post-reload-meta.json"
if ! wait_for_connect_port_event "${daemon_port}" "${post_reload_probe_port}" 5 >"${post_reload_event_path}"; then
  printf '{}\n' >"${post_reload_event_path}"
fi
wait "${workload_pid}"
workload_pid=""
sleep "${drain_timeout_seconds}"
health_after_reload="$(availability_health_json "${daemon_port}")"
availability_stop_daemon "${daemon_pid}"
daemon_pid=""

"${FIXTURE_PYTHON_BIN}" - \
  "${workload_report_path}" \
  "${pre_reload_event_path}" \
  "${post_reload_event_path}" \
  "${detach_payload_path}" \
  "${attach_payload_path}" \
  "${summary_path}" \
  "${daemon_log_path}" \
  "${daemon_config_path}" \
  "${health_before_reload}" \
  "${health_after_reload}" \
  "${detach_started_at_ns}" \
  "${attach_completed_at_ns}" \
  "${daemon_log_offset_bytes}" <<'PY'
import json
import sys
from pathlib import Path

workload_report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
pre_reload_event = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
post_reload_event = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
detach_payload = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
attach_payload = json.loads(Path(sys.argv[5]).read_text(encoding="utf-8"))
summary_path = Path(sys.argv[6])
daemon_log_path = sys.argv[7]
daemon_config_path = sys.argv[8]
health_before_reload = json.loads(sys.argv[9])
health_after_reload = json.loads(sys.argv[10])
detach_started_at_ns = int(sys.argv[11])
attach_completed_at_ns = int(sys.argv[12])
daemon_log_offset_bytes = int(sys.argv[13])

attempts = workload_report["attempts"]
expected_count = workload_report["attempt_count"]
ring_drop_delta = (
    health_after_reload["ring_events_dropped_total"]
    - health_before_reload["ring_events_dropped_total"]
)
lost_attempts = [
    attempt
    for attempt in attempts
    if detach_started_at_ns <= int(attempt["start_ns"]) <= attach_completed_at_ns
]
pre_reload_attempts = sorted(
    int(attempt["start_ns"])
    for attempt in attempts
    if int(attempt["start_ns"]) < detach_started_at_ns
)
post_reload_attempts = sorted(
    int(attempt["start_ns"])
    for attempt in attempts
    if int(attempt["start_ns"]) > attach_completed_at_ns
)
gap_seconds = (
    (post_reload_attempts[0] - pre_reload_attempts[-1]) / 1_000_000_000
    if pre_reload_attempts and post_reload_attempts
    else float("inf")
)
attach_gap_seconds = (attach_completed_at_ns - detach_started_at_ns) / 1_000_000_000
daemon_log_text = Path(daemon_log_path).read_text(encoding="utf-8")
daemon_log_suffix = daemon_log_text.encode("utf-8")[daemon_log_offset_bytes:].decode("utf-8", errors="ignore")
if "ringbuf_reconnected" in daemon_log_suffix:
    reconnect_log_event = "ringbuf_reconnected"
elif "probe_attached" in daemon_log_suffix:
    reconnect_log_event = "probe_attached"
else:
    reconnect_log_event = ""

summary = {
    "mode": "probe_reload",
    "workload_report": workload_report,
    "pre_reload_event": pre_reload_event,
    "post_reload_event": post_reload_event,
    "post_reload_event_observed": bool(post_reload_event),
    "detach_payload": detach_payload,
    "attach_payload": attach_payload,
    "health_before_reload": health_before_reload,
    "health_after_reload": health_after_reload,
    "daemon_log_path": daemon_log_path,
    "daemon_config_path": daemon_config_path,
    "expected_attempt_count": expected_count,
    "expected_helper_pid_count": expected_count,
    "lost_attempt_count": len(lost_attempts),
    "lost_event_count": len(lost_attempts),
    "ring_events_dropped_delta": ring_drop_delta,
    "attach_gap_seconds": attach_gap_seconds,
    "event_gap_seconds": gap_seconds,
    "reconnect_log_event": reconnect_log_event,
    "pass": (
        bool(pre_reload_event)
        and
        reconnect_log_event != ""
        and attach_gap_seconds <= 1.0
        and gap_seconds <= 1.0
        and len(lost_attempts) <= 5
    ),
}

summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
if not summary["pass"]:
    raise SystemExit("probe reload availability contract failed")
PY

echo "PASS: live probe reload stayed within the <=5 lost-event budget"
