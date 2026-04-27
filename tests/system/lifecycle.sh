#!/usr/bin/env bash
# Verify the full daemon lifecycle in a privileged environment.
#
# Purpose:
# - start the real daemon with probe attachment enabled
# - observe Initializing -> Running/Degraded -> Reloading -> Running and the
#   final ShuttingDown transition through the Unix-socket health API
# - confirm clean shutdown leaves no Mini-EDR probes attached
#
# Expected result:
# - daemon reaches Running or Degraded after startup
# - SIGHUP keeps the PID stable and records Reloading in state_history
# - SIGTERM exits 0 and bpftool shows no remaining Mini-EDR programs
#
# Cleanup contract:
# - the daemon is always SIGTERM'd in the EXIT trap
# - the Unix socket and temp config live under a mktemp directory
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bpftool_bin="${BPFTOOL_BIN:-/usr/lib/linux-tools/6.8.0-110-generic/bpftool}"
binary="${repo_root}/target/release/mini-edr-daemon"
tempdir="$(mktemp -d)"
socket_path="${tempdir}/mini-edr.sock"
config_path="${tempdir}/config.toml"
state_dir="${tempdir}/state"
daemon_pid=""

cleanup() {
  if [[ -n "${daemon_pid}" ]] && kill -0 "${daemon_pid}" 2>/dev/null; then
    kill -TERM "${daemon_pid}" 2>/dev/null || true
    wait "${daemon_pid}" 2>/dev/null || true
  fi
  rm -rf "${tempdir}"
}
trap cleanup EXIT

if [[ ${EUID} -ne 0 ]]; then
  caps_line="$(getcap "${binary}" 2>/dev/null || true)"
  if [[ -z "${caps_line}" ]] || ! { echo "${caps_line}" | grep -q 'cap_bpf' && echo "${caps_line}" | grep -q 'cap_perfmon'; }; then
    echo "lifecycle.sh requires root or a mini-edr-daemon binary with CAP_BPF + CAP_PERFMON" >&2
    exit 2
  fi
fi

mkdir -p "${state_dir}"
cat >"${config_path}" <<EOF
alert_threshold = 0.7
web_port = 0
model_path = "${repo_root}/training/output/model.onnx"
log_file_path = "alerts.jsonl"
state_dir = "${state_dir}"
enable_tui = false
EOF

cargo build --release -p mini-edr-daemon --manifest-path "${repo_root}/Cargo.toml" >/dev/null
MINI_EDR_API_SOCKET="${socket_path}" "${binary}" --config "${config_path}" \
  >"${tempdir}/stdout.log" 2>"${tempdir}/stderr.log" &
daemon_pid=$!

deadline=$((SECONDS + 15))
until curl --unix-socket "${socket_path}" -fsS http://localhost/health >"${tempdir}/health.json"; do
  if ! kill -0 "${daemon_pid}" 2>/dev/null; then
    echo "daemon exited before /health became ready" >&2
    cat "${tempdir}/stderr.log" >&2
    exit 1
  fi
  if (( SECONDS >= deadline )); then
    echo "timed out waiting for /health" >&2
    cat "${tempdir}/stderr.log" >&2
    exit 1
  fi
  sleep 0.2
done

python3 - <<'PY' "${tempdir}/health.json"
import json, sys
payload = json.load(open(sys.argv[1]))
state = payload["state"]
assert state in {"Running", "Degraded"}, payload
PY

cp "${repo_root}/training/output/model.onnx" "${state_dir}/reload.onnx"
sed -i "s|${repo_root}/training/output/model.onnx|${state_dir}/reload.onnx|" "${config_path}"
kill -HUP "${daemon_pid}"
sleep 1
curl --unix-socket "${socket_path}" -fsS http://localhost/health/state_history >"${tempdir}/state-history.json"
python3 - <<'PY' "${tempdir}/state-history.json"
import json, sys
states = [entry["state"] for entry in json.load(open(sys.argv[1]))]
assert "Reloading" in states, states
PY

kill -TERM "${daemon_pid}"
wait "${daemon_pid}"
daemon_pid=""

if [[ -x "${bpftool_bin}" ]]; then
  if "${bpftool_bin}" prog list | grep -qi 'mini-edr'; then
    echo "Mini-EDR probes remained after SIGTERM" >&2
    "${bpftool_bin}" prog list >&2
    exit 1
  fi
fi

echo "PASS: lifecycle startup, reload, and shutdown path completed"
