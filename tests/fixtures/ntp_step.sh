#!/usr/bin/env bash
# Validate that alert timestamps stay monotonic across a backward wall-clock step.
#
# The harness intentionally separates two notions of time:
#   1. The daemon's persisted `Alert.timestamp` values, which operators read as
#      wall clock.
#   2. A side-channel `CLOCK_MONOTONIC` trace captured beside each synthetic
#      alert request.
#
# The validation passes only when the JSON log stays monotonic AND the relative
# timestamp deltas match the monotonic side channel within 1 ms. That proves
# the daemon is deriving alert ordering from monotonic time rather than blindly
# trusting a mutable wall clock that NTP can step backwards.

set -euo pipefail

source "/home/directory/mini-edr/tests/fixtures/fixture_runtime_lib.sh"

temp_dir="$(mktemp -d /tmp/mini-edr-ntp-step-XXXXXX)"
config_path="${temp_dir}/config.toml"
daemon_log_path="${temp_dir}/daemon.log"
socket_path="${temp_dir}/api.sock"
sample_path="${temp_dir}/monotonic-samples.jsonl"
result_path="${temp_dir}/verification.json"
alert_log_path="${temp_dir}/logs/alerts.jsonl"
state_dir_path="${temp_dir}/state"
port="${MINI_EDR_NTP_STEP_PORT:-$(fixture_find_free_port)}"
rate_hz="${MINI_EDR_NTP_STEP_RATE_HZ:-10}"
pre_step_seconds="${MINI_EDR_NTP_STEP_PRE_SECONDS:-5}"
post_step_seconds="${MINI_EDR_NTP_STEP_POST_SECONDS:-60}"
payload_path="${MINI_EDR_NTP_STEP_PAYLOAD:-/home/directory/mini-edr/tests/fixtures/feature_vectors/high_085.json}"
step_command="${MINI_EDR_NTP_STEP_COMMAND:-chronyc makestep -- -30}"
total_requests="$(( rate_hz * (pre_step_seconds + post_step_seconds) ))"

cleanup() {
  if [[ -n "${emitter_pid:-}" ]]; then
    wait "${emitter_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${daemon_pid:-}" ]]; then
    cleanup_daemon "${daemon_pid}"
  fi
  rm -rf "${temp_dir}"
}
trap cleanup EXIT

fixture_require_release_daemon
fixture_require_model_artifact
mkdir -p "${state_dir_path}"

if [[ ! -f "${payload_path}" ]]; then
  echo "missing alert payload fixture at ${payload_path}" >&2
  exit 1
fi

cat >"${config_path}" <<EOF
alert_threshold = 0.7
web_port = ${port}
model_path = "${FIXTURE_DEFAULT_MODEL}"
log_file_path = "alerts.jsonl"
state_dir = "${state_dir_path}"
EOF

daemon_pid="$(MINI_EDR_API_SOCKET="${socket_path}" start_daemon "${config_path}" "${daemon_log_path}")"
wait_for_health "${port}"

"${FIXTURE_PYTHON_BIN}" - "${port}" "${payload_path}" "${sample_path}" "${rate_hz}" "${total_requests}" <<'PY' &
import json
import socket
import sys
import time
import urllib.request
from pathlib import Path

port = int(sys.argv[1])
payload_path = Path(sys.argv[2])
sample_path = Path(sys.argv[3])
rate_hz = int(sys.argv[4])
total_requests = int(sys.argv[5])
period = 1.0 / rate_hz
payload = payload_path.read_text(encoding="utf-8").encode("utf-8")
url = f"http://127.0.0.1:{port}/internal/predict"
request = urllib.request.Request(
    url,
    data=None,
    headers={"content-type": "application/json"},
    method="POST",
)
next_deadline = time.monotonic()

with sample_path.open("w", encoding="utf-8") as handle:
    for index in range(total_requests):
        request.data = payload
        with urllib.request.urlopen(request, timeout=10) as response:
            body = json.loads(response.read())
        monotonic_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        handle.write(
            json.dumps(
                {
                    "request_index": index,
                    "monotonic_ns": monotonic_ns,
                    "response_score": body["threat_score"],
                    "response_would_alert": body["would_alert"],
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        handle.flush()
        next_deadline += period
        sleep_seconds = next_deadline - time.monotonic()
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)
PY
emitter_pid="$!"

sleep "${pre_step_seconds}"
eval "${step_command}"
wait "${emitter_pid}"

"${FIXTURE_PYTHON_BIN}" - "${alert_log_path}" "${sample_path}" "${daemon_log_path}" "${result_path}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

alert_log_path = Path(sys.argv[1])
sample_path = Path(sys.argv[2])
daemon_log_path = Path(sys.argv[3])
result_path = Path(sys.argv[4])

alerts = [
    json.loads(line)
    for line in alert_log_path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]
samples = [
    json.loads(line)
    for line in sample_path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]
daemon_log = daemon_log_path.read_text(encoding="utf-8")

assert alerts, "alerts.jsonl was empty"
assert len(alerts) == len(samples), (
    f"expected one alert per synthetic request, saw {len(alerts)} alerts for {len(samples)} samples"
)
assert "panicked at" not in daemon_log and "panic" not in daemon_log.lower(), (
    "daemon log recorded a panic during the NTP-step harness"
)

def parse_rfc3339_ns(value: str) -> int:
    return int(
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        .astimezone(timezone.utc)
        .timestamp()
        * 1_000_000_000
    )

alert_timestamp_ns = [parse_rfc3339_ns(alert["timestamp"]) for alert in alerts]

for previous, current in zip(alert_timestamp_ns, alert_timestamp_ns[1:]):
    assert current >= previous, "alert timestamps moved backwards in alerts.jsonl"

anchor_alert_ns = alert_timestamp_ns[0]
anchor_monotonic_ns = samples[0]["monotonic_ns"]
max_delta_ns = 0
for alert_ns, sample in zip(alert_timestamp_ns, samples):
    expected_alert_ns = anchor_alert_ns + (sample["monotonic_ns"] - anchor_monotonic_ns)
    max_delta_ns = max(max_delta_ns, abs(alert_ns - expected_alert_ns))

assert max_delta_ns < 1_000_000, (
    f"max monotonic-vs-log delta {max_delta_ns}ns exceeded the 1ms contract"
)

result = {
    "alert_count": len(alerts),
    "max_delta_ns": max_delta_ns,
    "first_timestamp": alerts[0]["timestamp"],
    "last_timestamp": alerts[-1]["timestamp"],
}
result_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
print(json.dumps(result, indent=2, sort_keys=True))
PY
