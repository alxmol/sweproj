#!/usr/bin/env bash
# Prove VAL-ALERT-010's stale-socket recovery path by launching the daemon
# against a pre-created orphaned Unix socket and then asserting the startup log
# contains the structured `stale_socket_removed` record with the removed path.

set -euo pipefail

source "/home/directory/mini-edr/tests/fixtures/fixture_runtime_lib.sh"

temp_dir="$(mktemp -d /tmp/mini-edr-stale-socket-XXXXXX)"
socket_path="${TMPDIR:-/tmp}/mini-edr-stale-${BASHPID}.sock"
config_path="${temp_dir}/config.toml"
log_path="${temp_dir}/daemon.log"
port="$(fixture_find_free_port)"

cleanup() {
  if [[ -n "${daemon_pid:-}" ]]; then
    cleanup_daemon "${daemon_pid}"
  fi
  rm -f "${socket_path}"
  rm -rf "${temp_dir}"
}
trap cleanup EXIT

rm -f "${socket_path}"
"${FIXTURE_PYTHON_BIN}" - "${socket_path}" <<'PY'
import socket
import sys
from pathlib import Path

socket_path = Path(sys.argv[1])
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.bind(str(socket_path))
PY

fixture_require_release_daemon
fixture_require_model_artifact
write_config "${config_path}" "${FIXTURE_DEFAULT_MODEL}" "0.7" "${port}"
daemon_pid="$(MINI_EDR_API_SOCKET="${socket_path}" start_daemon "${config_path}" "${log_path}")"
wait_for_health "${port}"
curl --unix-socket "${socket_path}" -fsS "http://localhost/health" >"${temp_dir}/health.json"

"${FIXTURE_PYTHON_BIN}" - "${temp_dir}/health.json" <<'PY'
import json
import sys

health = json.load(open(sys.argv[1], encoding="utf-8"))
assert health["state"] == "Running", health
PY

if ! grep -F "stale_socket_removed" "${log_path}" >/dev/null; then
  echo "daemon log did not contain stale_socket_removed startup proof" >&2
  cat "${log_path}" >&2
  exit 1
fi

if ! grep -F "${socket_path}" "${log_path}" >/dev/null; then
  echo "daemon log did not mention stale socket path ${socket_path}" >&2
  cat "${log_path}" >&2
  exit 1
fi
