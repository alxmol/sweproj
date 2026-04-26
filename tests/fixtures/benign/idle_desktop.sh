#!/usr/bin/env bash
# idle_desktop.sh — controlled low-activity desktop simulator.
#
# The fixture performs a tiny amount of harmless local file inspection and then
# idles. This gives the benign suite a near-zero-noise baseline that should not
# trigger the model even when evaluated over a long synthetic window.

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

home_profile="${HOME}/.profile"
if [[ -f "${home_profile}" ]]; then
  head -n 5 "${home_profile}" >/dev/null
fi
sleep 0.5

response_json="$(fixture_submit_vector "idle_desktop" "${daemon_port}" "${pid_hint}" "${window_hours}")"
score="$(fixture_json_get "${response_json}" "threat_score")"
would_alert="$(fixture_json_get "${response_json}" "would_alert")"

result_json="$("${FIXTURE_PYTHON_BIN}" - "${response_json}" "${trial_id}" "${pid_hint}" "${window_hours}" <<'PY'
import json
import sys

response = json.loads(sys.argv[1])
trial_id = int(sys.argv[2])
pid = int(sys.argv[3])
hours = float(sys.argv[4])
result = {
    "fixture": "idle_desktop",
    "category": "benign",
    "trial": trial_id,
    "pid": pid,
    "window_hours": hours,
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

echo "idle_desktop trial=${trial_id} score=${score} would_alert=${would_alert}" >&2
printf '%s\n' "${result_json}"
