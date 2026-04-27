#!/usr/bin/env bash
# Verify that mini-edr-daemon refuses to start without CAP_BPF + CAP_PERFMON.
#
# Purpose:
# - exercise the operator-facing startup refusal required by VAL-SEC-009..013
#   and VAL-DAEMON-005 when the daemon is launched without elevated privileges
# - prove the daemon exits non-zero before it can attach probes or bind sockets
#
# Expected result:
# - exit code 2
# - stderr names CAP_BPF and CAP_PERFMON
#
# Cleanup contract:
# - all temporary files live under a mktemp directory removed on EXIT
# - no daemon process is left running because startup must fail before bind
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
binary="${repo_root}/target/release/mini-edr-daemon"
tempdir="$(mktemp -d)"
trap 'rm -rf "${tempdir}"' EXIT

mkdir -p "${tempdir}/state"
config_path="${tempdir}/config.toml"
socket_path="${tempdir}/mini-edr.sock"
stderr_path="${tempdir}/stderr.log"

cat >"${config_path}" <<EOF
alert_threshold = 0.7
web_port = 0
model_path = "${repo_root}/training/output/model.onnx"
log_file_path = "alerts.jsonl"
state_dir = "${tempdir}/state"
enable_tui = false
EOF

cargo build --release -p mini-edr-daemon --manifest-path "${repo_root}/Cargo.toml" >/dev/null

set +e
MINI_EDR_API_SOCKET="${socket_path}" \
  "${binary}" --config "${config_path}" \
  >"${tempdir}/stdout.log" 2>"${stderr_path}"
exit_code=$?
set -e

if [[ ${exit_code} -ne 2 ]]; then
  echo "expected exit code 2 when capabilities are missing, got ${exit_code}" >&2
  cat "${stderr_path}" >&2
  exit 1
fi

if ! grep -q 'CAP_BPF' "${stderr_path}" || ! grep -q 'CAP_PERFMON' "${stderr_path}"; then
  echo "stderr did not name both CAP_BPF and CAP_PERFMON" >&2
  cat "${stderr_path}" >&2
  exit 1
fi

echo "PASS: capability refusal exited 2 and named CAP_BPF + CAP_PERFMON"
