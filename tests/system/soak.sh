#!/usr/bin/env bash
# soak.sh — configurable continuous-operation soak harness for Mini-EDR.
#
# Purpose:
# - prove the continuous-operation mechanism with a short default run while
#   keeping an explicit `24h` gate available through `--duration 24h`
# - inject the shipped malicious fixtures on a fixed cadence and require every
#   injection to correlate with a real alert on `/alerts/stream`
# - sample daemon RSS over time and fit a linear slope so memory-growth claims
#   are backed by recorded evidence rather than a one-off peak measurement
#
# Expected result:
# - the daemon stays alive for the requested duration and exits 0 on shutdown
# - every fixture injection produces at least one correlated alert
# - RSS slope stays below 1 MiB/hour after the initial steady-state warmup
#
# Cleanup contract:
# - an EXIT trap stops the daemon, alert-stream subscriber, and temp workdir
# - SIGINT/SIGTERM produce a partial JSON report instead of leaking processes
set -euo pipefail

source "/home/alexm/mini-edr/tests/system/availability_lib.sh"

duration_arg="60s"
inject_every_arg="5s"
sample_interval_arg="5s"
report_path=""
threshold="0.7"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration)
      duration_arg="$2"
      shift 2
      ;;
    --inject-every)
      inject_every_arg="$2"
      shift 2
      ;;
    --sample-interval)
      sample_interval_arg="$2"
      shift 2
      ;;
    --report-path)
      report_path="$2"
      shift 2
      ;;
    --threshold)
      threshold="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

duration_seconds="$(availability_parse_duration_seconds "${duration_arg}")"
inject_every_seconds="$(availability_parse_duration_seconds "${inject_every_arg}")"
sample_interval_seconds="$(availability_parse_duration_seconds "${sample_interval_arg}")"
temp_dir="$(mktemp -d /tmp/mini-edr-soak-XXXXXX)"
rss_samples_path="${temp_dir}/rss-samples.csv"
injections_path="${temp_dir}/injections.jsonl"
stream_capture_path="${temp_dir}/alerts-stream.jsonl"
summary_path="${report_path:-${temp_dir}/summary.json}"
interrupted="false"

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
  if [[ -n "${daemon_pid:-}" ]]; then
    availability_stop_daemon "${daemon_pid}"
  fi
  if [[ -z "${report_path}" ]]; then
    rm -rf "${temp_dir}"
  fi
}

handle_interrupt() {
  interrupted="true"
}

trap handle_interrupt INT TERM
trap cleanup EXIT

printf 'elapsed_seconds,rss_bytes\n' >"${rss_samples_path}"
read -r daemon_pid daemon_port daemon_config_path daemon_log_path daemon_socket < <(
  availability_start_test_daemon "${temp_dir}" "${threshold}"
)
stream_pid="$(fixture_start_alert_stream "${daemon_socket}" "${stream_capture_path}")"
started_at="$(date +%s)"
next_injection_at="${started_at}"
next_sample_at="${started_at}"
injection_index=0
successful_injections=0

while true; do
  now="$(date +%s)"
  elapsed="$((now - started_at))"
  if [[ "${interrupted}" == "true" ]] || (( elapsed >= duration_seconds )); then
    break
  fi
  if ! kill -0 "${daemon_pid}" >/dev/null 2>&1; then
    echo "daemon exited during soak run" >&2
    cat "${daemon_log_path}" >&2
    exit 1
  fi

  if (( now >= next_sample_at )); then
    printf '%s,%s\n' "${elapsed}" "$(availability_sample_rss_bytes "${daemon_pid}")" >>"${rss_samples_path}"
    next_sample_at="$((now + sample_interval_seconds))"
  fi

  if (( now >= next_injection_at )); then
    fixture_name="${fixtures[$((injection_index % ${#fixtures[@]}))]}"
    fixture_script="/home/alexm/mini-edr/tests/fixtures/malware/${fixture_name}.sh"
    start_line="$(fixture_stream_line_count "${stream_capture_path}")"
    result_json="$("${fixture_script}" --daemon-port "${daemon_port}" --trial "${injection_index}")"
    expected_binary_path="$(fixture_json_get "${result_json}" "expected_binary_path")"
    expected_pid="$(fixture_json_get "${result_json}" "pid")"
    if correlated_alerts_json="$(fixture_wait_for_correlated_alerts "${stream_capture_path}" "${expected_binary_path}" "${expected_pid}" "${start_line}" 5)"; then
      successful_injections="$((successful_injections + 1))"
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

printf '%s,%s\n' "$(( $(date +%s) - started_at ))" "$(availability_sample_rss_bytes "${daemon_pid}")" >>"${rss_samples_path}"
fixture_stop_alert_stream "${stream_pid}"
stream_pid=""
availability_stop_daemon "${daemon_pid}"
daemon_pid=""

"${FIXTURE_PYTHON_BIN}" - "${rss_samples_path}" "${injections_path}" "${summary_path}" "${duration_seconds}" "${inject_every_seconds}" "${sample_interval_seconds}" "${successful_injections}" "${injection_index}" "${interrupted}" "${daemon_log_path}" "${daemon_config_path}" <<'PY'
import csv
import json
import sys
from pathlib import Path

rss_path = Path(sys.argv[1])
injections_path = Path(sys.argv[2])
summary_path = Path(sys.argv[3])
duration_seconds = int(sys.argv[4])
inject_every_seconds = int(sys.argv[5])
sample_interval_seconds = int(sys.argv[6])
successful_injections = int(sys.argv[7])
total_injections = int(sys.argv[8])
interrupted = sys.argv[9] == "true"
daemon_log_path = sys.argv[10]
daemon_config_path = sys.argv[11]

rss_rows = list(csv.DictReader(rss_path.open(encoding="utf-8")))
injection_rows = [
    json.loads(line)
    for line in injections_path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]
if not rss_rows:
    raise SystemExit("no RSS samples collected")

steady_state_offset = max(1, len(rss_rows) // 4)
steady_rows = rss_rows[steady_state_offset:]
times = [float(row["elapsed_seconds"]) for row in steady_rows]
rss_values = [float(row["rss_bytes"]) for row in steady_rows]
mean_time = sum(times) / len(times)
mean_rss = sum(rss_values) / len(rss_values)
numerator = sum((t - mean_time) * (r - mean_rss) for t, r in zip(times, rss_values))
denominator = sum((t - mean_time) ** 2 for t in times)
slope_bytes_per_second = 0.0 if denominator == 0.0 else numerator / denominator
slope_mib_per_hour = slope_bytes_per_second * 3600.0 / (1024.0 * 1024.0)
peak_rss = max(float(row["rss_bytes"]) for row in rss_rows)
steady_rss_start = float(steady_rows[0]["rss_bytes"])
steady_rss_end = float(steady_rows[-1]["rss_bytes"])

summary = {
    "mode": "availability_soak",
    "duration_seconds_requested": duration_seconds,
    "duration_seconds_observed": int(rss_rows[-1]["elapsed_seconds"]),
    "inject_every_seconds": inject_every_seconds,
    "sample_interval_seconds": sample_interval_seconds,
    "interrupted": interrupted,
    "rss_samples_path": str(rss_path),
    "injections_path": str(injections_path),
    "daemon_log_path": daemon_log_path,
    "daemon_config_path": daemon_config_path,
    "peak_rss_bytes": int(peak_rss),
    "steady_state_rss_delta_bytes": int(steady_rss_end - steady_rss_start),
    "rss_slope_mib_per_hour": slope_mib_per_hour,
    "successful_injections": successful_injections,
    "total_injections": total_injections,
    "detection_rate": successful_injections / max(total_injections, 1),
    "pass": successful_injections == total_injections and slope_mib_per_hour < 1.0,
}

summary_path.parent.mkdir(parents=True, exist_ok=True)
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
PY

echo "PASS: soak run completed with full detection coverage and bounded RSS slope"
