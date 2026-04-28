#!/usr/bin/env bash
# run_demo.sh — single entry-point Mini-EDR demo workflow.
#
# Purpose:
# - launch the real release daemon from a clean shell without modifying the
#   rest of the repo,
# - walk through probe attach, live observation, alert correlation,
#   reload/rollback hygiene, a light performance snapshot, and clean shutdown,
# - keep all persistent runtime artifacts under `/tmp/mini-edr-demo-*`.
#
# Cleanup contract:
# - an EXIT trap terminates only the daemon and helper processes spawned by
#   this script,
# - the trap does not sweep unrelated Mini-EDR daemons owned by the user,
#   because the demo refuses to start when a pre-existing daemon is active.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_ROOT="${REPO_ROOT}/demo"
OBSERVER_HELPER="${DEMO_ROOT}/helpers/demo_observer.py"
WORKLOAD_HELPER="${DEMO_ROOT}/helpers/live_workload.py"
DAEMON_BIN="${REPO_ROOT}/target/release/mini-edr-daemon"
MODEL_PATH="${REPO_ROOT}/training/output/model.onnx"
EBPF_OBJECT_PATH="${REPO_ROOT}/target/mini-edr-sensor-ebpf/bpfel-unknown-none/release/mini-edr-sensor-ebpf"

RUN_DIR=""
PORT=""
SOCKET_PATH=""
CONFIG_PATH=""
ALERT_LOG_PATH=""
DAEMON_STDOUT_LOG=""
BPFTOOL_BIN=""
daemon_pid=""
sentinel_pid=""
suspicious_driver_pid=""
storm_pid=""
rss_sampler_pid=""
daemon_loaded_after=0

perf_duration_seconds=10
perf_thread_count=4

cleanup() {
  local exit_code=$?

  # Stop background helpers before the daemon so the final SIGTERM only audits
  # the daemon's own shutdown behavior.
  for pid_var in rss_sampler_pid storm_pid suspicious_driver_pid sentinel_pid; do
    local pid_value="${!pid_var:-}"
    if [[ -n "${pid_value}" ]] && kill -0 "${pid_value}" >/dev/null 2>&1; then
      kill -TERM "${pid_value}" >/dev/null 2>&1 || true
      wait "${pid_value}" >/dev/null 2>&1 || true
    fi
  done

  if [[ -n "${daemon_pid}" ]] && kill -0 "${daemon_pid}" >/dev/null 2>&1; then
    kill -TERM "${daemon_pid}" >/dev/null 2>&1 || true
    wait "${daemon_pid}" >/dev/null 2>&1 || true
  fi

  exit "${exit_code}"
}
trap cleanup EXIT

phase() {
  printf '\n=== %s ===\n' "$1"
}

require_file() {
  local path="$1"
  if [[ ! -e "${path}" ]]; then
    echo "missing required file: ${path}" >&2
    exit 2
  fi
}

detect_bpftool() {
  local candidates=(
    "${BPFTOOL_BIN:-}"
    "/usr/lib/linux-tools/6.8.0-110-generic/bpftool"
    "/usr/sbin/bpftool"
  )
  for candidate in "${candidates[@]}"; do
    if [[ -n "${candidate}" && -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  if command -v bpftool >/dev/null 2>&1; then
    command -v bpftool
    return 0
  fi
  echo "bpftool not found; install linux-tools or set BPFTOOL_BIN" >&2
  exit 2
}

run_bpftool_json() {
  local output_path="$1"
  if sudo -n true >/dev/null 2>&1; then
    sudo -n "${BPFTOOL_BIN}" prog list --json >"${output_path}"
  else
    "${BPFTOOL_BIN}" prog list --json >"${output_path}"
  fi
}

check_required_capabilities() {
  local caps_line
  caps_line="$(getcap "${DAEMON_BIN}" 2>/dev/null || true)"
  printf '%s\n' "${caps_line}"
  if [[ -z "${caps_line}" ]] \
    || ! echo "${caps_line}" | grep -q 'cap_bpf' \
    || ! echo "${caps_line}" | grep -q 'cap_perfmon' \
    || ! echo "${caps_line}" | grep -q 'cap_sys_admin' \
    || ! echo "${caps_line}" | grep -q 'cap_dac_read_search'
  then
    echo "The demo requires file capabilities on ${DAEMON_BIN}." >&2
    echo "Apply them with:" >&2
    echo "  sudo setcap cap_bpf,cap_perfmon,cap_sys_admin,cap_dac_read_search+ep \"${DAEMON_BIN}\"" >&2
    exit 2
  fi
}

write_demo_config() {
  local threshold="$1"
  local model_path="$2"
  mkdir -p "${RUN_DIR}/logs" "${RUN_DIR}/state" "${RUN_DIR}/evidence"
  cat >"${CONFIG_PATH}" <<EOF
alert_threshold = ${threshold}
web_port = ${PORT}
model_path = "${model_path}"
log_file_path = "${RUN_DIR}/logs/alerts.jsonl"
state_dir = "${RUN_DIR}/state"
monitored_syscalls = ["execve", "openat", "connect", "clone"]
ring_buffer_size_pages = 1024
enable_tui = false
enable_web = true
EOF
}

wait_for_file() {
  local path="$1"
  for _ in $(seq 1 100); do
    if [[ -s "${path}" ]]; then
      return 0
    fi
    sleep 0.05
  done
  echo "timed out waiting for ${path}" >&2
  exit 1
}

read_json_field() {
  local json_path="$1"
  local field="$2"
  python3 - "${json_path}" "${field}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
value = payload
for segment in sys.argv[2].split("."):
    if isinstance(value, list) and segment.isdigit():
        value = value[int(segment)]
    else:
        value = value[segment]
print(value)
PY
}

record_proc_snapshot() {
  local output_path="$1"
  local timestamp_ns
  local daemon_ticks
  local total_ticks
  local rss_bytes

  timestamp_ns="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"
  daemon_ticks="$(awk '{print $14 + $15}' "/proc/${daemon_pid}/stat")"
  total_ticks="$(awk '/^cpu / {sum = 0; for (i = 2; i <= NF; i += 1) sum += $i; print sum}' /proc/stat)"
  rss_bytes="$(awk '/^VmRSS:/ {print $2 * 1024}' "/proc/${daemon_pid}/status")"

  cat >"${output_path}" <<EOF
{"timestamp_ns":${timestamp_ns},"daemon_ticks":${daemon_ticks},"total_ticks":${total_ticks},"rss_bytes":${rss_bytes}}
EOF
}

start_rss_sampler() {
  local output_path="$1"
  : >"${output_path}"
  (
    while [[ -n "${storm_pid}" ]] && kill -0 "${storm_pid}" >/dev/null 2>&1; do
      local timestamp_ns
      local rss_bytes
      timestamp_ns="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"
      rss_bytes="$(awk '/^VmRSS:/ {print $2 * 1024}' "/proc/${daemon_pid}/status")"
      printf '{"timestamp_ns":%s,"rss_bytes":%s}\n' "${timestamp_ns}" "${rss_bytes}" >>"${output_path}"
      sleep 1
    done
  ) &
  rss_sampler_pid="$!"
}

assert_file_contains_json_rows() {
  local path="$1"
  local minimum_count="$2"
  python3 - "${path}" "${minimum_count}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
minimum_count = int(sys.argv[2])
payload = json.loads(path.read_text(encoding="utf-8"))
if len(payload) < minimum_count:
    raise SystemExit(f"expected at least {minimum_count} rows, saw {len(payload)}")
PY
}

RUN_DIR="${1:-$(mktemp -d /tmp/mini-edr-demo-XXXXXX)}"
mkdir -p "${RUN_DIR}"
PORT="$(python3 "${OBSERVER_HELPER}" find-free-port --start 8081 --end 8099)"
SOCKET_PATH="${RUN_DIR}/api.sock"
CONFIG_PATH="${RUN_DIR}/config.toml"
ALERT_LOG_PATH="${RUN_DIR}/logs/alerts.jsonl"
DAEMON_STDOUT_LOG="${RUN_DIR}/daemon.stdout.log"
BPFTOOL_BIN="$(detect_bpftool)"

require_file "${OBSERVER_HELPER}"
require_file "${WORKLOAD_HELPER}"
require_file "${DAEMON_BIN}"
require_file "${MODEL_PATH}"
if [[ -f "${EBPF_OBJECT_PATH}" ]]; then
  export MINI_EDR_EBPF_OBJECT="${EBPF_OBJECT_PATH}"
fi

if pgrep -af '/target/(debug|release)/mini-edr-daemon' >/dev/null 2>&1; then
  echo "Refusing to run while another Mini-EDR daemon is already active:" >&2
  pgrep -af '/target/(debug|release)/mini-edr-daemon' >&2
  exit 2
fi

phase "Phase 1: System bring-up"
echo "File capabilities on the release daemon:"
check_required_capabilities
echo "Why file caps: they let the daemon attach eBPF probes without keeping the whole process root."

write_demo_config "0.0" "${MODEL_PATH}"
daemon_loaded_after="$(date +%s)"
MINI_EDR_API_SOCKET="${SOCKET_PATH}" "${DAEMON_BIN}" --config "${CONFIG_PATH}" >"${DAEMON_STDOUT_LOG}" 2>&1 &
daemon_pid="$!"
python3 "${OBSERVER_HELPER}" wait-health --port "${PORT}" --state Running --timeout 20 --output "${RUN_DIR}/evidence/phase1-health.json"
echo "Health JSON:"
cat "${RUN_DIR}/evidence/phase1-health.json"

run_bpftool_json "${RUN_DIR}/evidence/phase1-bpftool.json"
python3 "${OBSERVER_HELPER}" filter-bpftool \
  --input "${RUN_DIR}/evidence/phase1-bpftool.json" \
  --daemon-pid "${daemon_pid}" \
  --loaded-after "${daemon_loaded_after}" \
  --output "${RUN_DIR}/evidence/phase1-probes.json"
assert_file_contains_json_rows "${RUN_DIR}/evidence/phase1-probes.json" 4
echo "Attached probes for daemon pid ${daemon_pid}:"
cat "${RUN_DIR}/evidence/phase1-probes.json"

phase "Phase 2: Live observation"
python3 "${OBSERVER_HELPER}" wait-process \
  --port "${PORT}" \
  --timeout 20 \
  --output "${RUN_DIR}/evidence/phase2-live-process.json"
python3 "${OBSERVER_HELPER}" wait-events \
  --port "${PORT}" \
  --minimum 5 \
  --limit 20 \
  --timeout 20 \
  --output "${RUN_DIR}/evidence/phase2-live-events.json"
curl -fsS "http://127.0.0.1:${PORT}/api/health" >"${RUN_DIR}/evidence/phase2-health.json"
observed_pid="$(read_json_field "${RUN_DIR}/evidence/phase2-live-process.json" "pid")"
echo "Observed live process PID: ${observed_pid}"
echo "Top live process-tree row:"
cat "${RUN_DIR}/evidence/phase2-live-process.json"
echo "Recent live event sample:"
cat "${RUN_DIR}/evidence/phase2-live-events.json"
echo "Updated health snapshot:"
cat "${RUN_DIR}/evidence/phase2-health.json"

phase "Phase 3: Live alert correlation"
baseline_alert_lines=0
if [[ -f "${ALERT_LOG_PATH}" ]]; then
  baseline_alert_lines="$(wc -l <"${ALERT_LOG_PATH}" | tr -d '[:space:]')"
fi
python3 "${OBSERVER_HELPER}" wait-alert \
  --alerts-file "${ALERT_LOG_PATH}" \
  --start-line "${baseline_alert_lines}" \
  --timeout 20 \
  --output "${RUN_DIR}/evidence/phase3-alert.json"
host_alert_pid="$(read_json_field "${RUN_DIR}/evidence/phase3-alert.json" "pid")"
python3 "${OBSERVER_HELPER}" wait-process \
  --port "${PORT}" \
  --pid "${host_alert_pid}" \
  --timeout 20 \
  --output "${RUN_DIR}/evidence/phase3-process.json"
python3 "${OBSERVER_HELPER}" dashboard-alerts \
  --port "${PORT}" \
  --pid "${host_alert_pid}" \
  --output "${RUN_DIR}/evidence/phase3-dashboard-alerts.json"
echo "Correlated live alert PID: ${host_alert_pid}"
echo "Correlated alert from alerts.jsonl:"
cat "${RUN_DIR}/evidence/phase3-alert.json"
echo "Matching process-tree row with feature vector detail:"
cat "${RUN_DIR}/evidence/phase3-process.json"
echo "Dashboard alert snapshot filtered to the same PID:"
cat "${RUN_DIR}/evidence/phase3-dashboard-alerts.json"

phase "Phase 4: Reload and rollback hygiene"
curl -fsS "http://127.0.0.1:${PORT}/api/health" >"${RUN_DIR}/evidence/phase4-before-reload.json"
write_demo_config "0.7" "${MODEL_PATH}"
kill -HUP "${daemon_pid}"
for _ in $(seq 1 100); do
  curl -fsS "http://127.0.0.1:${PORT}/api/health" >"${RUN_DIR}/evidence/phase4-after-reload.json"
  if python3 - "${RUN_DIR}/evidence/phase4-before-reload.json" "${RUN_DIR}/evidence/phase4-after-reload.json" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1], encoding="utf-8"))
after = json.load(open(sys.argv[2], encoding="utf-8"))
raise SystemExit(
    0
    if after["alert_threshold"] == 0.7
    and after["config_reload_success_total"] > before["config_reload_success_total"]
    else 1
)
PY
  then
    break
  fi
  sleep 0.1
done
echo "Threshold reload evidence:"
cat "${RUN_DIR}/evidence/phase4-after-reload.json"

cp "${RUN_DIR}/evidence/phase4-after-reload.json" "${RUN_DIR}/evidence/phase4-before-rollback.json"
write_demo_config "0.1" "${RUN_DIR}/missing-model.onnx"
kill -HUP "${daemon_pid}"
python3 "${OBSERVER_HELPER}" wait-log \
  --log-path "${DAEMON_STDOUT_LOG}" \
  --substring "model_path_missing" \
  --timeout 10 \
  --output "${RUN_DIR}/evidence/phase4-rollback-log.json"
curl -fsS "http://127.0.0.1:${PORT}/api/health" >"${RUN_DIR}/evidence/phase4-after-rollback.json"
python3 - "${RUN_DIR}/evidence/phase4-before-rollback.json" "${RUN_DIR}/evidence/phase4-after-rollback.json" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1], encoding="utf-8"))
after = json.load(open(sys.argv[2], encoding="utf-8"))
assert after["state"] == "Running", after
assert after["alert_threshold"] == before["alert_threshold"], (before, after)
assert after["model_hash"] == before["model_hash"], (before, after)
assert after["config_reload_success_total"] == before["config_reload_success_total"], (before, after)
PY
write_demo_config "0.7" "${MODEL_PATH}"
echo "Rejected reload kept the live config:"
cat "${RUN_DIR}/evidence/phase4-after-rollback.json"
echo "Rollback log lines:"
cat "${RUN_DIR}/evidence/phase4-rollback-log.json"

phase "Phase 5: Light performance snapshot"
perf_port="$(python3 "${OBSERVER_HELPER}" find-free-port --start 8090 --end 8099)"
curl -fsS "http://127.0.0.1:${PORT}/api/health" >"${RUN_DIR}/evidence/phase5-health-before.json"
record_proc_snapshot "${RUN_DIR}/evidence/phase5-proc-before.json"
python3 "${WORKLOAD_HELPER}" connect-storm \
  --summary-file "${RUN_DIR}/evidence/phase5-helper-report.json" \
  --host 127.0.0.1 \
  --port "${perf_port}" \
  --duration-seconds "${perf_duration_seconds}" \
  --thread-count "${perf_thread_count}" \
  >/dev/null 2>&1 &
storm_pid="$!"
start_rss_sampler "${RUN_DIR}/evidence/phase5-rss-samples.jsonl"
wait "${storm_pid}"
storm_pid=""
if [[ -n "${rss_sampler_pid}" ]] && kill -0 "${rss_sampler_pid}" >/dev/null 2>&1; then
  wait "${rss_sampler_pid}" >/dev/null 2>&1 || true
fi
rss_sampler_pid=""
record_proc_snapshot "${RUN_DIR}/evidence/phase5-proc-after.json"
curl -fsS "http://127.0.0.1:${PORT}/api/health" >"${RUN_DIR}/evidence/phase5-health-after.json"
python3 "${OBSERVER_HELPER}" summarize-perf \
  --helper-report "${RUN_DIR}/evidence/phase5-helper-report.json" \
  --health-before "${RUN_DIR}/evidence/phase5-health-before.json" \
  --health-after "${RUN_DIR}/evidence/phase5-health-after.json" \
  --proc-before "${RUN_DIR}/evidence/phase5-proc-before.json" \
  --proc-after "${RUN_DIR}/evidence/phase5-proc-after.json" \
  --rss-samples "${RUN_DIR}/evidence/phase5-rss-samples.jsonl" \
  --output "${RUN_DIR}/evidence/phase5-summary.json"
python3 - "${RUN_DIR}/evidence/phase5-summary.json" <<'PY'
import json
import sys

summary = json.load(open(sys.argv[1], encoding="utf-8"))
assert summary["generator_events_per_second"] > 100.0, summary
assert summary["daemon_received_events_total"] > 0, summary
assert summary["rss_peak_mb"] > 0.0, summary
assert summary["state_after"] in {"Running", "BackPressure"}, summary
PY
echo "Illustrative perf snapshot:"
cat "${RUN_DIR}/evidence/phase5-summary.json"

phase "Phase 6: Clean shutdown"
kill -TERM "${daemon_pid}"
wait "${daemon_pid}"
daemon_pid=""
run_bpftool_json "${RUN_DIR}/evidence/phase6-bpftool.json"
python3 - "${RUN_DIR}/evidence/phase1-probes.json" "${RUN_DIR}/evidence/phase6-bpftool.json" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1], encoding="utf-8"))
after = json.load(open(sys.argv[2], encoding="utf-8"))
remaining_ids = {program["id"] for program in after if "id" in program}
probe_ids = {program["id"] for program in before if "id" in program}
assert remaining_ids.isdisjoint(probe_ids), {"remaining_probe_ids": sorted(remaining_ids & probe_ids)}
PY
if pgrep -af '/target/(debug|release)/mini-edr-daemon' >/dev/null 2>&1; then
  echo "Mini-EDR daemon remained alive after the demo finished" >&2
  pgrep -af '/target/(debug|release)/mini-edr-daemon' >&2
  exit 1
fi
echo "Clean shutdown left no demo-owned daemon process behind."
echo "Demo artifacts: ${RUN_DIR}"
