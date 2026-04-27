#!/usr/bin/env bash
# bpftool_profile.sh — capture per-probe kernel profiling output for live eBPF programs.
#
# Purpose:
# - start the real release daemon with probe attachment enabled
# - trigger a small benign syscall workload while `bpftool prog profile` samples each attached probe
# - persist the raw profiling output plus the parsed percentage for each program
#
# Expected result:
# - exactly four Mini-EDR tracepoint programs belong to the daemon PID
# - every `bpftool prog profile` percentage is below 1.0
#
# Cleanup contract:
# - the daemon is always terminated by the EXIT trap
# - the Unix socket, logs, and reports live under a mktemp directory
set -euo pipefail

source "/home/alexm/mini-edr/tests/perf/perf_lib.sh"

profile_duration_seconds="${MINI_EDR_PERF_BPFTOOL_DURATION_SECONDS:-10}"
temp_dir="$(mktemp -d /tmp/mini-edr-perf-bpftool-XXXXXX)"
config_path="${temp_dir}/config.toml"
state_dir="${temp_dir}/state"
socket_path="${temp_dir}/mini-edr.sock"
daemon_log_path="${temp_dir}/daemon.log"
profiles_dir="${temp_dir}/profiles"
mkdir -p "${profiles_dir}"

cleanup() {
  if [[ -n "${daemon_pid:-}" ]] && kill -0 "${daemon_pid}" >/dev/null 2>&1; then
    kill -TERM "${daemon_pid}" >/dev/null 2>&1 || true
    wait "${daemon_pid}" >/dev/null 2>&1 || true
  fi
  rm -rf "${temp_dir}"
}
trap cleanup EXIT

perf_build_release_artifacts
if ! perf_live_probe_mode_available; then
  echo "bpftool_profile.sh requires root or a CAP_BPF/CAP_PERFMON release daemon binary" >&2
  exit 2
fi

port="$(perf_find_free_port)"
perf_write_live_config "${config_path}" "${state_dir}" "${port}"
MINI_EDR_API_SOCKET="${socket_path}" "${PERF_DAEMON_BIN}" --config "${config_path}" >"${daemon_log_path}" 2>&1 &
daemon_pid="$!"
perf_wait_for_health_socket "${socket_path}"

"${PERF_REPO_ROOT}/tests/fixtures/benign/kernel_compile.sh" --daemon-port "${port}" >/dev/null
mapfile -t program_ids < <("${PERF_BPFTOOL_BIN}" --json prog list \
  | python3 - "${daemon_pid}" <<'PY'
import json
import sys

daemon_pid = int(sys.argv[1])
payload = json.load(sys.stdin)
for program in payload:
    if program.get("type") != "tracepoint":
        continue
    pids = program.get("pids") or []
    if any(item.get("pid") == daemon_pid for item in pids if isinstance(item, dict)):
        print(program["id"])
PY
)

if [[ "${#program_ids[@]}" -ne 4 ]]; then
  echo "expected 4 Mini-EDR tracepoint programs, found ${#program_ids[@]}" >&2
  "${PERF_BPFTOOL_BIN}" prog list >&2
  exit 1
fi

summary_rows=()
for program_id in "${program_ids[@]}"; do
  profile_path="${profiles_dir}/prog-${program_id}.txt"
  "${PERF_BPFTOOL_BIN}" prog profile id "${program_id}" duration "${profile_duration_seconds}" cycles instructions \
    >"${profile_path}"
  percentage="$(python3 - "${profile_path}" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r"\(([0-9.]+)%\)", text)
if not match:
    raise SystemExit("no percentage found in bpftool output")
print(match.group(1))
PY
)"
  python3 - <<'PY' "${percentage}" "${program_id}" "${profile_path}"
import json
import sys

percentage = float(sys.argv[1])
assert percentage < 1.0, {
    "program_id": int(sys.argv[2]),
    "percentage": percentage,
    "profile_path": sys.argv[3],
}
PY
  summary_rows+=("{\"program_id\":${program_id},\"percentage\":${percentage},\"profile_path\":\"${profile_path}\"}")
done

python3 - <<'PY' "${daemon_pid}" "${profile_duration_seconds}" "${summary_rows[*]:-}"
import json
import sys

daemon_pid = int(sys.argv[1])
duration = int(sys.argv[2])
rows = [json.loads(item) for item in sys.argv[3].split() if item]
print(json.dumps({
    "daemon_pid": daemon_pid,
    "profile_duration_seconds": duration,
    "profiles": rows,
}, indent=2, sort_keys=True))
PY

echo "PASS: bpftool reported sub-1% per-probe kernel overhead"
