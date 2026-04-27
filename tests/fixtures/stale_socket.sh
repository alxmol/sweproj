#!/usr/bin/env bash
# Validate that a stale Unix socket path is cleaned up before the daemon binds.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/fixture_runtime_lib.sh"

temp_dir="$(mktemp -d /tmp/mini-edr-stale-socket-XXXXXX)"
socket_path="${temp_dir}/api.sock"
config_path="${temp_dir}/config.toml"
log_path="${temp_dir}/daemon.log"
port="$(fixture_find_free_port)"

cleanup() {
  if [[ -n "${daemon_pid:-}" ]]; then
    cleanup_daemon "${daemon_pid}"
  fi
}
trap cleanup EXIT

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
