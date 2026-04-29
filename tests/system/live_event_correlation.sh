#!/usr/bin/env bash
# live_event_correlation.sh — verify that a post-startup PID reaches alerts.jsonl.
#
# Purpose:
# - start the real release daemon with live probes attached
# - spawn one brand-new workload PID after startup that performs one outbound
#   `connect`
# - derive the host-visible PID from `/api/events` using that workload's unique
#   destination port, then require at least one alert line in alerts.jsonl whose
#   `pid` matches that host-visible PID, proving the live sensor -> pipeline ->
#   detection -> alert path even when the harness itself runs inside a nested
#   PID namespace
#
# Expected result:
# - the helper PID is recorded before the workload starts issuing syscalls
# - the daemon writes at least one matching alert within the observation window
# - cleanup leaves no harness-owned daemon process behind
set -euo pipefail

source "/home/directory/mini-edr/tests/fixtures/fixture_runtime_lib.sh"

repo_root="/home/directory/mini-edr"
binary="${repo_root}/target/release/mini-edr-daemon"
helper_source="${repo_root}/tests/system/live_event_workload.rs"
temp_dir="$(mktemp -d /tmp/mini-edr-live-event-correlation-XXXXXX)"
socket_path="${temp_dir}/api.sock"
daemon_log_path="${temp_dir}/daemon.log"
config_path="${temp_dir}/config.toml"
helper_bin="${temp_dir}/live_event_workload"
workload_pid_file="${temp_dir}/workload.pid"
sentinel_connect_port="51234"
daemon_pid=""
workload_wrapper_pid=""

cleanup() {
  if [[ -n "${workload_wrapper_pid}" ]] && kill -0 "${workload_wrapper_pid}" >/dev/null 2>&1; then
    kill -TERM "${workload_wrapper_pid}" >/dev/null 2>&1 || true
    wait "${workload_wrapper_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${daemon_pid}" ]]; then
    cleanup_daemon "${daemon_pid}"
  fi
  rm -rf "${temp_dir}"
}
trap cleanup EXIT

# The daemon-cleanup mandate requires clearing any leftovers before a new live
# probe run so sockets, alert logs, and the BPF attach path stay deterministic.
pgrep -x mini-edr-daemon | xargs -r kill -TERM 2>/dev/null || true
sleep 1
pgrep -x mini-edr-daemon | xargs -r kill -KILL 2>/dev/null || true

cargo build --release -p mini-edr-daemon --manifest-path "${repo_root}/Cargo.toml" >/dev/null
if [[ ${EUID} -ne 0 ]]; then
  # Cargo rewrites the release binary on every build, which clears file
  # capabilities. Reapply the documented WSL2 capability set so the helper can
  # run the daemon directly without keeping root for the whole harness.
  sudo setcap cap_bpf,cap_perfmon,cap_sys_admin,cap_dac_read_search+ep "${binary}"
  caps_line="$(getcap "${binary}" 2>/dev/null || true)"
  if [[ -z "${caps_line}" ]] || ! { echo "${caps_line}" | grep -q 'cap_bpf' && echo "${caps_line}" | grep -q 'cap_perfmon'; }; then
    echo "live_event_correlation.sh requires root or a mini-edr-daemon binary with CAP_BPF + CAP_PERFMON" >&2
    exit 2
  fi
fi

rustc --edition=2024 "${helper_source}" -O -o "${helper_bin}"

port="$(fixture_find_free_port)"
write_config "${config_path}" "${FIXTURE_DEFAULT_MODEL}" "0.0" "${port}"
# This harness wants a deterministic correlation gate, not a whole-host
# openat-storm benchmark. Restricting the live probe set to `connect` keeps the
# WSL2 host's background procfs churn from drowning the post-startup helper PID
# in unrelated `openat` traffic, while a zero threshold still guarantees that a
# single live connect-only partial window emits an alert after exit. The helper
# uses the sensor crate's privileged-harness sentinel port (`127.0.0.1:51234`)
# so `/api/events` can recover the host-visible PID even when the shell's PID
# namespace differs from what the eBPF tracepoint reports.
cat >>"${config_path}" <<'EOF'
monitored_syscalls = ["connect"]
ring_buffer_size_pages = 1024
EOF
daemon_pid="$(MINI_EDR_API_SOCKET="${socket_path}" start_daemon "${config_path}" "${daemon_log_path}")"
deadline=$((SECONDS + 20))
until curl --unix-socket "${socket_path}" -fsS "http://localhost/health" >/dev/null 2>&1; do
  if ! kill -0 "${daemon_pid}" >/dev/null 2>&1; then
    echo "daemon exited before the health endpoint became ready" >&2
    cat "${daemon_log_path}" >&2 || true
    exit 1
  fi
  if (( SECONDS >= deadline )); then
    echo "daemon health endpoint never became ready on :${port}" >&2
    cat "${daemon_log_path}" >&2 || true
    exit 1
  fi
  sleep 0.2
done

alert_log_path="${temp_dir}/logs/alerts.jsonl"
baseline_alert_count=0
if [[ -f "${alert_log_path}" ]]; then
  baseline_alert_count="$(wc -l <"${alert_log_path}" | tr -d '[:space:]')"
fi

"${helper_bin}" "/etc/passwd" "0" "127.0.0.1" "${sentinel_connect_port}" "5000" "${workload_pid_file}" &
workload_wrapper_pid="$!"

for _ in $(seq 1 100); do
  if [[ -s "${workload_pid_file}" ]]; then
    break
  fi
  sleep 0.05
done

if [[ ! -s "${workload_pid_file}" ]]; then
  echo "workload helper never wrote its pid file" >&2
  cat "${daemon_log_path}" >&2
  exit 1
fi

workload_namespace_pid="$(cat "${workload_pid_file}")"

if ! "${FIXTURE_PYTHON_BIN}" - "${alert_log_path}" "${baseline_alert_count}" "${port}" "${sentinel_connect_port}" "${temp_dir}/events.json" "${temp_dir}/matching-alert.json" "${temp_dir}/observed-host-pid.txt" <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

alert_log_path = Path(sys.argv[1])
baseline_count = int(sys.argv[2])
daemon_port = int(sys.argv[3])
sentinel_port = int(sys.argv[4])
events_path = Path(sys.argv[5])
alert_output_path = Path(sys.argv[6])
host_pid_output_path = Path(sys.argv[7])
deadline = time.time() + 15.0
events_url = f"http://127.0.0.1:{daemon_port}/api/events?limit=512"

def load_recent_events() -> list[dict]:
    try:
        with urllib.request.urlopen(events_url, timeout=2.0) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return []

while time.time() < deadline:
    events = load_recent_events()
    events_path.write_text(json.dumps(events, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sentinel_events = [
        event
        for event in events
        if event.get("syscall_type") == "Connect" and event.get("port") == sentinel_port
    ]
    host_pid_counts = Counter(
        event["pid"]
        for event in sentinel_events
        if isinstance(event.get("pid"), int)
    )
    if host_pid_counts:
        host_pid, _ = host_pid_counts.most_common(1)[0]
        host_pid_output_path.write_text(f"{host_pid}\n", encoding="utf-8")
        if alert_log_path.exists():
            matches = []
            for index, line in enumerate(alert_log_path.read_text(encoding="utf-8").splitlines(), start=1):
                if index <= baseline_count or not line.strip():
                    continue
                payload = json.loads(line)
                if payload.get("pid") == host_pid:
                    matches.append(payload)
            if matches:
                alert_output_path.write_text(
                    json.dumps(matches[-1], indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                raise SystemExit(0)
    time.sleep(0.2)

raise SystemExit(1)
PY
then
  wait "${workload_wrapper_pid}" || true
  workload_wrapper_pid=""
  observed_host_pid="unknown"
  if [[ -s "${temp_dir}/observed-host-pid.txt" ]]; then
    observed_host_pid="$(cat "${temp_dir}/observed-host-pid.txt")"
  fi
  echo "no alert for workload namespace pid ${workload_namespace_pid} (observed host pid ${observed_host_pid})" >&2
  echo "--- recent events ---" >&2
  cat "${temp_dir}/events.json" >&2 || true
  echo "--- daemon log ---" >&2
  cat "${daemon_log_path}" >&2
  exit 1
fi

wait "${workload_wrapper_pid}" || true
workload_wrapper_pid=""
observed_host_pid="$(cat "${temp_dir}/observed-host-pid.txt")"
echo "PASS: live workload namespace pid ${workload_namespace_pid} produced an alert for host pid ${observed_host_pid}"
cat "${temp_dir}/matching-alert.json"
