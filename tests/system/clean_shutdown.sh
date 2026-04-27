#!/usr/bin/env bash
# Verify that SIGTERM performs a clean probe-detaching daemon shutdown.
#
# Purpose:
# - launch the real daemon in a privilege-capable environment
# - wait for the Unix-socket health endpoint
# - send SIGTERM and assert exit code 0 plus no remaining Mini-EDR probes
#
# Expected result:
# - daemon exits 0
# - bpftool shows no Mini-EDR programs after shutdown
#
# Cleanup contract:
# - an EXIT trap SIGTERMs the daemon if the script aborts early
# - all temp files are removed automatically
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

if [[ ${EUID} -ne 0 ]] && ! getcap "${binary}" 2>/dev/null | grep -q 'cap_bpf.*cap_perfmon'; then
  echo "clean_shutdown.sh requires root or a mini-edr-daemon binary with CAP_BPF + CAP_PERFMON" >&2
  exit 2
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
until curl --unix-socket "${socket_path}" -fsS http://localhost/health >/dev/null; do
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

kill -TERM "${daemon_pid}"
if ! wait "${daemon_pid}"; then
  echo "daemon did not exit 0 after SIGTERM" >&2
  exit 1
fi
daemon_pid=""

if [[ -x "${bpftool_bin}" ]] && "${bpftool_bin}" prog list | grep -qi 'mini-edr'; then
  echo "Mini-EDR probes remained after clean shutdown" >&2
  "${bpftool_bin}" prog list >&2
  exit 1
fi

echo "PASS: clean SIGTERM shutdown exited 0 and left no Mini-EDR probes"
