#!/usr/bin/env bash
# soak.sh — continuous-operation soak harness with real RSS leak gating.
#
# Purpose:
# - run the real release daemon with live `connect` probes attached instead of
#   the synthetic test-mode path rejected in scrutiny round 1
# - keep a low-rate live syscall workload flowing through the probe/ring-buffer
#   path while the harness still injects the existing malicious fixtures through
#   `/internal/predict` for VAL-AVAIL-002 coverage
# - sample `/proc/<daemon>/status` every 60 seconds, establish the steady-state
#   baseline after a five-minute warm-up, and fail-fast once the post-warm-up
#   RSS delta exceeds the required 10 MiB bound from VAL-AVAIL-003
#
# Expected result:
# - the daemon stays alive for the requested duration and exits 0 on shutdown
# - every fixture injection produces a correlated alert
# - RSS slope stays below 1 MiB/hour and final steady-state RSS delta stays
#   below 10 MiB after the initial five-minute warm-up window
#
# Cleanup contract:
# - an EXIT trap stops the alert-stream subscriber, live workload helper, and
#   daemon PID spawned by this harness
# - privileged runs delegate temp-dir cleanup to availability_cleanup_temp_dir
#   so the mission's "no sudo rm -rf" restriction is preserved
set -euo pipefail

source "/home/directory/mini-edr/tests/system/availability_lib.sh"

duration_arg="${MINI_EDR_SOAK_DURATION:-10m}"
inject_every_arg="${MINI_EDR_SOAK_INJECT_EVERY:-60s}"
sample_interval_arg="${MINI_EDR_SOAK_SAMPLE_INTERVAL:-60s}"
warmup_arg="${MINI_EDR_SOAK_WARMUP:-5m}"
report_path=""
threshold="${MINI_EDR_SOAK_THRESHOLD:-0.7}"
connect_eps="${MINI_EDR_SOAK_CONNECT_EPS:-25}"
connect_threads="${MINI_EDR_SOAK_CONNECT_THREADS:-1}"
ring_buffer_pages="${MINI_EDR_SOAK_RING_BUFFER_PAGES:-256}"
max_delta_mib="${MINI_EDR_SOAK_MAX_DELTA_MIB:-10}"
fake_leak_bytes="${MINI_EDR_SOAK_FAKE_LEAK_BYTES:-0}"
failure_reason=""
interrupted="false"

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
    --warmup)
      warmup_arg="$2"
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
    --connect-eps)
      connect_eps="$2"
      shift 2
      ;;
    --max-delta-mib)
      max_delta_mib="$2"
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
warmup_seconds="$(availability_parse_duration_seconds "${warmup_arg}")"
max_delta_bytes="$("${FIXTURE_PYTHON_BIN}" - "${max_delta_mib}" <<'PY'
import sys
print(int(float(sys.argv[1]) * 1024 * 1024))
PY
)"
if (( duration_seconds <= warmup_seconds )); then
  echo "duration must exceed the warm-up window so VAL-AVAIL-003 can measure a steady-state RSS baseline" >&2
  exit 2
fi

temp_dir="$(mktemp -d /tmp/mini-edr-soak-XXXXXX)"
load_helper_bin="${temp_dir}/live_connect_load"
load_report_path="${temp_dir}/live-load.json"
rss_samples_path="${temp_dir}/rss-samples.csv"
injections_path="${temp_dir}/injections.jsonl"
stream_capture_path="${temp_dir}/alerts-stream.jsonl"
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
  perf_stop_pid "${load_pid:-}"
  if [[ -n "${daemon_pid:-}" ]]; then
    availability_stop_daemon "${daemon_pid}"
  fi
  if [[ -z "${report_path}" ]]; then
    availability_cleanup_temp_dir "${temp_dir}"
  fi
}

handle_interrupt() {
  interrupted="true"
  if [[ -z "${failure_reason}" ]]; then
    failure_reason="interrupted_by_signal"
  fi
}

trap handle_interrupt INT TERM
trap cleanup EXIT

availability_sweep_daemons
availability_compile_connect_load_helper "${load_helper_bin}"

printf 'elapsed_seconds,raw_rss_bytes,adjusted_rss_bytes,baseline_rss_bytes,steady_state_delta_bytes\n' >"${rss_samples_path}"
read -r daemon_pid daemon_port daemon_config_path daemon_log_path daemon_socket alert_log_path < <(
  availability_start_live_daemon "${temp_dir}" "${threshold}" "connect" "${ring_buffer_pages}" "30"
)
stream_pid="$(fixture_start_alert_stream "${daemon_socket}" "${stream_capture_path}")"
"${load_helper_bin}" "127.0.0.1" "51234" "${duration_seconds}" "${connect_eps}" "${connect_threads}" "${load_report_path}" &
load_pid="$!"

started_at="$(date +%s)"
next_injection_at="${started_at}"
next_sample_at="${started_at}"
steady_state_baseline_bytes=""
injection_index=0
successful_injections=0

while true; do
  now="$(date +%s)"
  elapsed="$((now - started_at))"
  if [[ "${interrupted}" == "true" ]] || (( elapsed >= duration_seconds )) || [[ -n "${failure_reason}" ]]; then
    break
  fi
  if ! kill -0 "${daemon_pid}" >/dev/null 2>&1; then
    failure_reason="daemon_exited_during_soak"
    break
  fi

  if (( now >= next_sample_at )); then
    raw_rss_bytes="$(availability_sample_rss_bytes "${daemon_pid}")"
    adjusted_rss_bytes="$("${FIXTURE_PYTHON_BIN}" - "${raw_rss_bytes}" "${elapsed}" "${warmup_seconds}" "${fake_leak_bytes}" <<'PY'
import sys

raw_rss = int(sys.argv[1])
elapsed = int(sys.argv[2])
warmup = int(sys.argv[3])
fake_leak = int(sys.argv[4])
print(raw_rss + (fake_leak if elapsed > warmup else 0))
PY
)"
    if [[ -z "${steady_state_baseline_bytes}" ]] && (( elapsed >= warmup_seconds )); then
      steady_state_baseline_bytes="${adjusted_rss_bytes}"
    fi
    if [[ -n "${steady_state_baseline_bytes}" ]]; then
      steady_state_delta_bytes="$((adjusted_rss_bytes - steady_state_baseline_bytes))"
      if (( steady_state_delta_bytes > max_delta_bytes )); then
        failure_reason="steady_state_rss_delta_exceeded"
      fi
    else
      steady_state_delta_bytes=""
    fi
    printf '%s,%s,%s,%s,%s\n' \
      "${elapsed}" \
      "${raw_rss_bytes}" \
      "${adjusted_rss_bytes}" \
      "${steady_state_baseline_bytes}" \
      "${steady_state_delta_bytes}" >>"${rss_samples_path}"
    next_sample_at="$((now + sample_interval_seconds))"
  fi

  if [[ -n "${failure_reason}" ]]; then
    break
  fi

  if (( now >= next_injection_at )); then
    fixture_name="${fixtures[$((injection_index % ${#fixtures[@]}))]}"
    fixture_script="/home/directory/mini-edr/tests/fixtures/malware/${fixture_name}.sh"
    start_line="$(fixture_stream_line_count "${stream_capture_path}")"
    result_json="$("${fixture_script}" --daemon-port "${daemon_port}" --trial "${injection_index}")"
    expected_binary_path="$(fixture_json_get "${result_json}" "expected_binary_path")"
    expected_pid="$(fixture_json_get "${result_json}" "pid")"
    if correlated_alerts_json="$(fixture_wait_for_correlated_alerts "${stream_capture_path}" "${expected_binary_path}" "${expected_pid}" "${start_line}" 5)"; then
      successful_injections="$((successful_injections + 1))"
    else
      correlated_alerts_json="[]"
      failure_reason="fixture_injection_not_detected"
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

final_elapsed="$(( $(date +%s) - started_at ))"
if kill -0 "${daemon_pid}" >/dev/null 2>&1; then
  final_raw_rss_bytes="$(availability_sample_rss_bytes "${daemon_pid}")"
  final_adjusted_rss_bytes="$("${FIXTURE_PYTHON_BIN}" - "${final_raw_rss_bytes}" "${final_elapsed}" "${warmup_seconds}" "${fake_leak_bytes}" <<'PY'
import sys

raw_rss = int(sys.argv[1])
elapsed = int(sys.argv[2])
warmup = int(sys.argv[3])
fake_leak = int(sys.argv[4])
print(raw_rss + (fake_leak if elapsed > warmup else 0))
PY
)"
  if [[ -n "${steady_state_baseline_bytes}" ]]; then
    final_delta_bytes="$((final_adjusted_rss_bytes - steady_state_baseline_bytes))"
  else
    final_delta_bytes=""
  fi
  printf '%s,%s,%s,%s,%s\n' \
    "${final_elapsed}" \
    "${final_raw_rss_bytes}" \
    "${final_adjusted_rss_bytes}" \
    "${steady_state_baseline_bytes}" \
    "${final_delta_bytes}" >>"${rss_samples_path}"
fi

wait "${load_pid}" || failure_reason="${failure_reason:-live_connect_load_failed}"
load_pid=""
fixture_stop_alert_stream "${stream_pid}"
stream_pid=""
availability_stop_daemon "${daemon_pid}"
daemon_pid=""

"${FIXTURE_PYTHON_BIN}" - \
  "${rss_samples_path}" \
  "${injections_path}" \
  "${load_report_path}" \
  "${summary_path}" \
  "${duration_seconds}" \
  "${inject_every_seconds}" \
  "${sample_interval_seconds}" \
  "${warmup_seconds}" \
  "${max_delta_bytes}" \
  "${successful_injections}" \
  "${injection_index}" \
  "${interrupted}" \
  "${failure_reason}" \
  "${daemon_log_path}" \
  "${daemon_config_path}" \
  "${fake_leak_bytes}" <<'PY'
import csv
import json
import sys
from pathlib import Path

rss_path = Path(sys.argv[1])
injections_path = Path(sys.argv[2])
load_report_path = Path(sys.argv[3])
summary_path = Path(sys.argv[4])
duration_seconds = int(sys.argv[5])
inject_every_seconds = int(sys.argv[6])
sample_interval_seconds = int(sys.argv[7])
warmup_seconds = int(sys.argv[8])
max_delta_bytes = int(sys.argv[9])
successful_injections = int(sys.argv[10])
total_injections = int(sys.argv[11])
interrupted = sys.argv[12] == "true"
failure_reason = sys.argv[13]
daemon_log_path = sys.argv[14]
daemon_config_path = sys.argv[15]
fake_leak_bytes = int(sys.argv[16])

rss_rows = list(csv.DictReader(rss_path.open(encoding="utf-8")))
injection_rows = [
    json.loads(line)
    for line in injections_path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]
load_report = json.loads(load_report_path.read_text(encoding="utf-8"))
if not rss_rows:
    raise SystemExit("no RSS samples collected")

steady_rows = [
    row for row in rss_rows if int(row["elapsed_seconds"]) >= warmup_seconds and row["baseline_rss_bytes"]
]
if not steady_rows:
    raise SystemExit("no steady-state RSS samples were collected after warm-up")

steady_times = [float(row["elapsed_seconds"]) for row in steady_rows]
steady_rss_values = [float(row["adjusted_rss_bytes"]) for row in steady_rows]
steady_observation_seconds = int(steady_times[-1] - steady_times[0]) if len(steady_times) >= 2 else 0
slope_gate_applied = steady_observation_seconds >= 300
mean_time = sum(steady_times) / len(steady_times)
mean_rss = sum(steady_rss_values) / len(steady_rss_values)
numerator = sum((time_value - mean_time) * (rss_value - mean_rss) for time_value, rss_value in zip(steady_times, steady_rss_values))
denominator = sum((time_value - mean_time) ** 2 for time_value in steady_times)
slope_bytes_per_second = 0.0 if denominator == 0.0 else numerator / denominator
slope_mib_per_hour = slope_bytes_per_second * 3600.0 / (1024.0 * 1024.0)
peak_rss_bytes = max(int(row["adjusted_rss_bytes"]) for row in rss_rows)
steady_state_baseline_rss_bytes = int(steady_rows[0]["baseline_rss_bytes"])
steady_state_rss_delta_bytes = int(steady_rows[-1]["adjusted_rss_bytes"]) - steady_state_baseline_rss_bytes

summary = {
    "mode": "availability_soak",
    "duration_seconds_requested": duration_seconds,
    "duration_seconds_observed": int(rss_rows[-1]["elapsed_seconds"]),
    "inject_every_seconds": inject_every_seconds,
    "sample_interval_seconds": sample_interval_seconds,
    "warmup_seconds": warmup_seconds,
    "interrupted": interrupted,
    "failure_reason": failure_reason,
    "rss_samples_path": str(rss_path),
    "injections_path": str(injections_path),
    "load_report": load_report,
    "daemon_log_path": daemon_log_path,
    "daemon_config_path": daemon_config_path,
    "peak_rss_bytes": peak_rss_bytes,
    "steady_state_baseline_rss_bytes": steady_state_baseline_rss_bytes,
    "steady_state_rss_delta_bytes": steady_state_rss_delta_bytes,
    "steady_observation_seconds": steady_observation_seconds,
    "max_steady_state_delta_bytes": max_delta_bytes,
    "rss_slope_mib_per_hour": slope_mib_per_hour,
    "slope_gate_applied": slope_gate_applied,
    "successful_injections": successful_injections,
    "total_injections": total_injections,
    "detection_rate": successful_injections / max(total_injections, 1),
    "fake_leak_bytes": fake_leak_bytes,
    "pass": (
        not interrupted
        and not failure_reason
        and successful_injections == total_injections
        and (not slope_gate_applied or slope_mib_per_hour < 1.0)
        and steady_state_rss_delta_bytes < max_delta_bytes
    ),
}

summary_path.parent.mkdir(parents=True, exist_ok=True)
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
if not summary["pass"]:
    raise SystemExit("soak availability contract failed")
PY

echo "PASS: soak run completed with real RSS leak gates and full detection coverage"
