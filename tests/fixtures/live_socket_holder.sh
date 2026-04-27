#!/usr/bin/env bash
# Validate that the daemon refuses to replace a live Unix socket holder.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/fixture_runtime_lib.sh"

temp_dir="$(mktemp -d /tmp/mini-edr-live-socket-XXXXXX)"
socket_path="${temp_dir}/api.sock"
config_path="${temp_dir}/config.toml"
stderr_path="${temp_dir}/stderr.log"
port="$(fixture_find_free_port)"

cleanup() {
  if [[ -n "${holder_pid:-}" ]] && kill -0 "${holder_pid}" >/dev/null 2>&1; then
    kill -TERM "${holder_pid}" >/dev/null 2>&1 || true
    wait "${holder_pid}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

"${FIXTURE_PYTHON_BIN}" - "${socket_path}" <<'PY' &
import socket
import sys
from pathlib import Path

socket_path = Path(sys.argv[1])
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.bind(str(socket_path))
    sock.listen(1)
    sock.settimeout(5.0)
    try:
        sock.accept()
    except TimeoutError:
        pass
PY
holder_pid="$!"
sleep 0.1

fixture_require_release_daemon
fixture_require_model_artifact
write_config "${config_path}" "${FIXTURE_DEFAULT_MODEL}" "0.7" "${port}"

set +e
MINI_EDR_API_SOCKET="${socket_path}" "${FIXTURE_DAEMON_BIN}" --config "${config_path}" > /dev/null 2>"${stderr_path}"
daemon_rc=$?
set -e

if [[ "${daemon_rc}" -eq 0 ]]; then
  echo "daemon unexpectedly started while a live process owned ${socket_path}" >&2
  exit 1
fi

rg "socket_in_use" "${stderr_path}" >/dev/null
