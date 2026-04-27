#!/usr/bin/env bash
# nginx_serving.sh — controlled benign web-serving simulator.
#
# The fixture stands up a loopback-only HTTP server backed by Python's stdlib
# and drives a short burst of localhost requests against it. This approximates
# the expected benign connect/open pattern of a lightweight web server without
# requiring a real nginx install or any non-localhost exposure.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/fixture_runtime_lib.sh"

daemon_port=""
output_path=""
trial_id="0"
window_hours="6"
pid_hint="${BASHPID}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --daemon-port)
      daemon_port="$2"
      shift 2
      ;;
    --output)
      output_path="$2"
      shift 2
      ;;
    --trial)
      trial_id="$2"
      shift 2
      ;;
    --hours)
      window_hours="$2"
      shift 2
      ;;
    --pid)
      pid_hint="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${daemon_port}" ]]; then
  echo "--daemon-port is required" >&2
  exit 2
fi

temp_dir="$(mktemp -d /tmp/mini-edr-nginx-serving-XXXXXX)"
port="$(fixture_find_free_port)"
echo "hello from mini-edr benign server" >"${temp_dir}/index.html"

cleanup() {
  if [[ -n "${server_pid:-}" ]] && kill -0 "${server_pid}" >/dev/null 2>&1; then
    kill -TERM "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

"${FIXTURE_PYTHON_BIN}" -m http.server "${port}" --bind 127.0.0.1 --directory "${temp_dir}" >/dev/null 2>&1 &
server_pid=$!
sleep 0.2

for _ in $(seq 1 20); do
  curl -fsS "http://127.0.0.1:${port}/" >/dev/null
  sleep 0.1
done

response_json="$(fixture_submit_vector "nginx_serving" "${daemon_port}" "${pid_hint}" "${window_hours}")"
score="$(fixture_json_get "${response_json}" "threat_score")"
would_alert="$(fixture_json_get "${response_json}" "would_alert")"

result_json="$("${FIXTURE_PYTHON_BIN}" - "${response_json}" "${trial_id}" "${pid_hint}" "${window_hours}" "${port}" <<'PY'
import json
import sys

response = json.loads(sys.argv[1])
trial_id = int(sys.argv[2])
pid = int(sys.argv[3])
hours = float(sys.argv[4])
port = int(sys.argv[5])
result = {
    "fixture": "nginx_serving",
    "category": "benign",
    "trial": trial_id,
    "pid": pid,
    "expected_binary_path": "/home/alexm/mini-edr/tests/fixtures/benign/nginx_serving.sh",
    "window_hours": hours,
    "loopback_port": port,
    "score": response["threat_score"],
    "would_alert": response["would_alert"],
    "alert_count": 1 if response["would_alert"] else 0,
    "model_hash": response["model_hash"],
}
print(json.dumps(result, separators=(",", ":")))
PY
)"

if [[ -n "${output_path}" ]]; then
  printf '%s\n' "${result_json}" >"${output_path}"
fi

echo "nginx_serving trial=${trial_id} score=${score} would_alert=${would_alert}" >&2
printf '%s\n' "${result_json}"
