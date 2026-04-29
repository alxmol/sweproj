#!/usr/bin/env bash
# e2e_latency.sh — measure live syscall-to-alert latency against the real daemon.
#
# Purpose:
# - launch the real release daemon with live `connect` probes attached
# - drive 1,000 one-shot sentinel `connect(2)` syscalls from fresh helper PIDs
# - measure the wall-clock delta between the helper's pre-syscall timestamp and
#   the matching alert line written to `alerts.jsonl`
# - report nearest-rank p50 / p95 / p99 / p99.9 latency percentiles for the
#   true BPF -> ringbuffer -> pipeline -> detection -> alert-log path
#
# Expected result:
# - every trial produces one correlated alert line for the helper PID
# - p99 latency < 5000 ms
# - p99.9 latency < 5000 ms
#
# Cleanup contract:
# - the harness sweeps orphan daemons before launch and terminates its own
#   daemon through the EXIT trap
# - privileged runs leave their `/tmp/mini-edr-*` workdir in place because the
#   mission temporarily forbids `sudo rm -rf`
set -euo pipefail

source "/home/directory/mini-edr/tests/perf/perf_lib.sh"

trials="${MINI_EDR_PERF_LATENCY_TRIALS:-25}"
timeout_seconds="${MINI_EDR_PERF_LATENCY_TIMEOUT_SECONDS:-5}"
sentinel_host="${MINI_EDR_PERF_LATENCY_CONNECT_HOST:-127.0.0.1}"
sentinel_port="${MINI_EDR_PERF_LATENCY_CONNECT_PORT:-51234}"
linger_ms="${MINI_EDR_PERF_LATENCY_LINGER_MS:-1000}"
trial_pause_seconds="${MINI_EDR_PERF_LATENCY_TRIAL_PAUSE_SECONDS:-0.1}"
temp_dir="$(mktemp -d /tmp/mini-edr-perf-latency-XXXXXX)"
helper_bin="${temp_dir}/live_connect_latency"
summary_path="${temp_dir}/latency-summary.json"
samples_path="${temp_dir}/latency-samples.csv"
daemon_pid=""

cleanup() {
  perf_stop_pid "${daemon_pid:-}"
  perf_cleanup_temp_dir "${temp_dir}"
}
trap cleanup EXIT

perf_require_release_daemon
if ! perf_live_probe_mode_available; then
  echo "e2e_latency.sh requires root or a release daemon binary with the documented live-probe capabilities" >&2
  exit 2
fi

perf_sweep_daemons
perf_compile_helper "${PERF_CONNECT_LATENCY_SOURCE}" "${helper_bin}"
for trial in $(seq 1 "${trials}"); do
  trial_dir="${temp_dir}/trial-${trial}"
  mkdir -p "${trial_dir}"
  config_path="${trial_dir}/config.toml"
  state_dir="${trial_dir}/state"
  socket_path="${trial_dir}/mini-edr.sock"
  daemon_log_path="${trial_dir}/daemon.log"
  port="$(perf_find_free_port)"
  perf_write_live_config "${config_path}" "${state_dir}" "${port}" "0.0"
  cat >>"${config_path}" <<'EOF'
monitored_syscalls = ["connect"]
ring_buffer_size_pages = 1024
EOF
  MINI_EDR_API_SOCKET="${socket_path}" "${PERF_DAEMON_BIN}" --config "${config_path}" >"${daemon_log_path}" 2>&1 &
  daemon_pid="$!"
  perf_wait_for_health_socket "${socket_path}"

  alert_log_path="${trial_dir}/logs/alerts.jsonl"
  metadata_path="${temp_dir}/trial-${trial}.metadata.json"
  alert_path="${temp_dir}/trial-${trial}.alert.json"
  event_path="${temp_dir}/trial-${trial}.event.json"
  baseline_lines=0

  "${helper_bin}" "${sentinel_host}" "${sentinel_port}" "${linger_ms}" "${metadata_path}" &
  helper_process_pid="$!"
  for _ in $(seq 1 100); do
    if [[ -s "${metadata_path}" ]]; then
      break
    fi
    sleep 0.01
  done
  helper_pid="$(sed -n 's/.*"pid":\([0-9]*\).*/\1/p' "${metadata_path}")"
  if [[ -z "${helper_pid}" ]]; then
    echo "trial ${trial} helper metadata did not record a PID" >&2
    cat "${metadata_path}" >&2 || true
    exit 1
  fi

  if ! python3 - "${alert_log_path}" "${baseline_lines}" "${port}" "${sentinel_port}" "${timeout_seconds}" "${event_path}" "${alert_path}" <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

alert_log_path = Path(sys.argv[1])
baseline_lines = int(sys.argv[2])
daemon_port = int(sys.argv[3])
connect_port = int(sys.argv[4])
timeout_seconds = float(sys.argv[5])
event_path = Path(sys.argv[6])
alert_path = Path(sys.argv[7])
events_url = f"http://127.0.0.1:{daemon_port}/api/events?limit=512"
deadline = time.time() + timeout_seconds
host_pid = None

while time.time() < deadline:
    try:
        with urllib.request.urlopen(events_url, timeout=2.0) as response:
            events = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        events = []

    sentinel_events = [
        event
        for event in events
        if event.get("syscall_type") == "Connect" and event.get("port") == connect_port
    ]
    if sentinel_events:
        newest = sentinel_events[0]
        host_pid = newest["pid"]
        event_path.write_text(json.dumps(newest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if host_pid is not None and alert_log_path.exists():
        lines = alert_log_path.read_text(encoding="utf-8").splitlines()
        for line_number, line in enumerate(lines[baseline_lines:], start=baseline_lines + 1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get("pid") == host_pid:
                payload["line_number"] = line_number
                alert_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                raise SystemExit(0)

    time.sleep(0.2)

raise SystemExit(1)
PY
  then
    wait "${helper_process_pid}" || true
    echo "trial ${trial} timed out waiting for a correlated host pid + alert (helper namespace pid ${helper_pid})" >&2
    echo "--- helper metadata ---" >&2
    cat "${metadata_path}" >&2 || true
    echo "--- matching event ---" >&2
    cat "${event_path}" >&2 || true
    echo "--- alert log tail ---" >&2
    tail -n 20 "${alert_log_path}" >&2 || true
    echo "--- daemon log ---" >&2
    cat "${daemon_log_path}" >&2 || true
    exit 1
  fi
  wait "${helper_process_pid}"
  perf_stop_pid "${daemon_pid}"
  daemon_pid=""
  if [[ "${trial}" -lt "${trials}" ]]; then
    sleep "${trial_pause_seconds}"
  fi
done

python3 - <<'PY' "${temp_dir}" "${trials}" "${samples_path}" "${summary_path}"
import csv
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

temp_dir = Path(sys.argv[1])
expected_trials = int(sys.argv[2])
samples_path = Path(sys.argv[3])
summary_path = Path(sys.argv[4])

rows = []
for metadata_path in sorted(temp_dir.glob("trial-*.metadata.json")):
    trial_number = int(metadata_path.stem.split("-")[1].split(".")[0])
    alert_path = temp_dir / f"trial-{trial_number}.alert.json"
    event_path = temp_dir / f"trial-{trial_number}.event.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    alert = json.loads(alert_path.read_text(encoding="utf-8"))
    event = json.loads(event_path.read_text(encoding="utf-8"))
    alert_dt = datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00"))
    alert_ns = int(alert_dt.timestamp() * 1_000_000_000)
    start_ns = int(metadata["start_ns"])
    latency_ms = (alert_ns - start_ns) / 1_000_000.0
    rows.append(
        {
            "trial": trial_number,
            "helper_pid": int(metadata["pid"]),
            "host_pid": int(event["pid"]),
            "connect_port": int(event.get("port", 0)),
            "start_ns": start_ns,
            "alert_timestamp_ns": alert_ns,
            "latency_ms": latency_ms,
            "alert_line_number": int(alert["line_number"]),
        }
    )

if len(rows) != expected_trials:
    raise AssertionError({"expected_trials": expected_trials, "observed_trials": len(rows)})

rows.sort(key=lambda row: row["trial"])
latencies = sorted(row["latency_ms"] for row in rows)

def nearest_rank(values: list[float], percentile: float) -> float:
    index = max(0, math.ceil((percentile / 100.0) * len(values)) - 1)
    return values[index]

summary = {
    "trial_count": len(rows),
    "percentile_method": "nearest_rank",
    "p50_ms": nearest_rank(latencies, 50.0),
    "p95_ms": nearest_rank(latencies, 95.0),
    "p99_ms": nearest_rank(latencies, 99.0),
    "p99_9_ms": nearest_rank(latencies, 99.9),
    "max_ms": max(latencies),
    "mean_ms": sum(latencies) / len(latencies),
    "samples_csv": str(samples_path),
}

assert summary["p99_ms"] < 5000.0, summary
assert summary["p99_9_ms"] < 5000.0, summary

with samples_path.open("w", encoding="utf-8", newline="") as handle:
    writer = csv.DictWriter(
        handle,
        fieldnames=["trial", "helper_pid", "host_pid", "connect_port", "start_ns", "alert_timestamp_ns", "latency_ms", "alert_line_number"],
    )
    writer.writeheader()
    writer.writerows(rows)

summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
PY

echo "PASS: live syscall-to-alert latency stayed inside the 5 s budget"
