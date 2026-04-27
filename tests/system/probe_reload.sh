#!/usr/bin/env bash
# probe_reload.sh — verify synthetic probe detach/reattach continuity.
#
# Purpose:
# - run the daemon in deterministic test-mode sensor mode so probe attach/detach
#   semantics can be exercised without CAP_BPF on routine developer hosts
# - require `connect` to disappear from `/api/health.active_probes`, then
#   reappear, while a fresh synthetic connect event lands within 1 second
# - require the daemon log to record the synthetic `ringbuf_reconnected` event
#
# Expected result:
# - detach removes `connect` from the active-probe list
# - reattach restores `connect` and a newer connect event arrives within 1 s
# - the daemon stays alive throughout the transition
#
# Cleanup contract:
# - an EXIT trap stops the daemon and removes the temp directory
set -euo pipefail

source "/home/alexm/mini-edr/tests/system/availability_lib.sh"

temp_dir="$(mktemp -d /tmp/mini-edr-probe-reload-XXXXXX)"
report_path="${temp_dir}/summary.json"

cleanup() {
  if [[ -n "${daemon_pid:-}" ]]; then
    availability_stop_daemon "${daemon_pid}"
  fi
  rm -rf "${temp_dir}"
}
trap cleanup EXIT

export MINI_EDR_TEST_SENSOR_RATE="${MINI_EDR_TEST_SENSOR_RATE:-20}"
export MINI_EDR_TEST_SENSOR_PID_COUNT="${MINI_EDR_TEST_SENSOR_PID_COUNT:-32}"
export MINI_EDR_TEST_SENSOR_RECONNECT_DELAY_MS="${MINI_EDR_TEST_SENSOR_RECONNECT_DELAY_MS:-200}"

read -r daemon_pid daemon_port daemon_config_path daemon_log_path daemon_socket < <(
  availability_start_test_daemon "${temp_dir}" "0.7"
)

baseline_event_id="$("${FIXTURE_PYTHON_BIN}" - "${daemon_port}" <<'PY'
import json
import sys
import time
import urllib.request

port = int(sys.argv[1])
deadline = time.time() + 2.0
while time.time() < deadline:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/events?limit=200") as response:
        events = json.loads(response.read().decode("utf-8"))
    connect_ids = [event["event_id"] for event in events if event["syscall_type"] == "Connect"]
    if connect_ids:
        print(max(connect_ids))
        raise SystemExit(0)
    time.sleep(0.05)
raise SystemExit("synthetic sensor did not emit a baseline connect event")
PY
)"

curl -fsS -X POST "http://127.0.0.1:${daemon_port}/api/probes/connect/detach" >"${temp_dir}/detach.json"
"${FIXTURE_PYTHON_BIN}" - "${temp_dir}/detach.json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert "connect" not in payload["active_probes"], payload
PY

attach_started_at="$(date +%s%N)"
curl -fsS -X POST "http://127.0.0.1:${daemon_port}/api/probes/connect/attach" >"${temp_dir}/attach.json"

"${FIXTURE_PYTHON_BIN}" - "${daemon_port}" "${baseline_event_id}" <<'PY' >"${temp_dir}/event-gap.json"
import json
import subprocess
import sys
import time
import urllib.request

port = int(sys.argv[1])
baseline = int(sys.argv[2])
deadline = time.time() + 1.0
while time.time() < deadline:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/events?limit=200") as response:
        events = json.loads(response.read().decode("utf-8"))
    connect_events = [event for event in events if event["syscall_type"] == "Connect" and event["event_id"] > baseline]
    if connect_events:
        connect_events.sort(key=lambda item: item["event_id"])
        print(json.dumps(connect_events[0]))
        raise SystemExit(0)
    time.sleep(0.05)
raise SystemExit("timed out waiting for a fresh synthetic connect event after reattach")
PY

attach_completed_at="$(date +%s%N)"
if ! grep -q 'ringbuf_reconnected' "${daemon_log_path}"; then
  echo "daemon log did not record ringbuf_reconnected after probe reattach" >&2
  cat "${daemon_log_path}" >&2
  exit 1
fi

"${FIXTURE_PYTHON_BIN}" - "${temp_dir}/attach.json" "${temp_dir}/event-gap.json" "${attach_started_at}" "${attach_completed_at}" "${MINI_EDR_TEST_SENSOR_RATE}" "${report_path}" "${daemon_log_path}" "${daemon_config_path}" <<'PY'
import json
import sys
from pathlib import Path

attach_payload = json.load(open(sys.argv[1], encoding="utf-8"))
event_payload = json.load(open(sys.argv[2], encoding="utf-8"))
attach_started_at = int(sys.argv[3])
attach_completed_at = int(sys.argv[4])
sensor_rate = float(sys.argv[5])
report_path = Path(sys.argv[6])
daemon_log_path = sys.argv[7]
daemon_config_path = sys.argv[8]

assert "connect" in attach_payload["active_probes"], attach_payload
gap_seconds = (attach_completed_at - attach_started_at) / 1_000_000_000
connect_cadence_seconds = max(0.05, 4.0 / sensor_rate)

summary = {
    "mode": "probe_reload",
    "connect_event": event_payload,
    "attach_gap_seconds": gap_seconds,
    "connect_cadence_seconds": connect_cadence_seconds,
    "daemon_log_path": daemon_log_path,
    "daemon_config_path": daemon_config_path,
    "pass": gap_seconds <= 1.0 and gap_seconds <= connect_cadence_seconds * 2.0,
}

report_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
if not summary["pass"]:
    raise SystemExit("probe reconnect gap exceeded the configured budget")
PY

echo "PASS: synthetic probe reload restored connect events within the reconnect budget"
