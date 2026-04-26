#!/usr/bin/env bash
# Validate that SIGHUP during a partial config write is treated as transient and
# the final file contents are applied once the writer closes the file.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/hot_reload_lib.sh"

temp_dir="$(mktemp -d)"
daemon_log="${temp_dir}/daemon.log"
config_path="${temp_dir}/config.toml"
model_v1="${temp_dir}/model-v1.onnx"
model_v2="${temp_dir}/model-v2.onnx"
port=8085

cp "${MODEL_SOURCE}" "${model_v1}"
mutate_model_v2 "${model_v1}" "${model_v2}"
write_config "${config_path}" "${model_v1}" "1.0" "${port}"

daemon_pid="$(start_daemon "${config_path}" "${daemon_log}")"
trap 'cleanup_daemon "${daemon_pid}"; rm -rf "${temp_dir}"' EXIT
wait_for_health "${port}"

"${PYTHON_BIN}" - "${config_path}" "${model_v2}" "${port}" <<'PY' &
import sys
import time

config_path, model_path, port = sys.argv[1:4]
content = (
    "alert_threshold = 0.0\n"
    f"web_port = {port}\n"
    f"model_path = \"{model_path}\"\n"
    "log_file_path = \"alerts.json\"\n"
)
with open(config_path, "w", encoding="utf-8") as handle:
    for character in content:
        handle.write(character)
        handle.flush()
        time.sleep(0.005)
PY
writer_pid=$!

for _ in $(seq 1 20); do
  kill -HUP "${daemon_pid}"
  sleep 0.01
done
wait "${writer_pid}"
sleep 0.3
health_json "${port}" >"${temp_dir}/health.json"

"${PYTHON_BIN}" - "${temp_dir}/health.json" <<'PY'
import json
import sys

health_path = sys.argv[1]
with open(health_path, encoding="utf-8") as handle:
    health = json.load(handle)

assert health["state"] == "Running", f"daemon left Running: {health['state']}"
assert health["alert_threshold"] == 0.0, health
assert health["config_reload_partial_total"] > 0, health
assert health["config_reload_success_total"] >= 1, health
PY

grep -q 'config_reload_partial' "${daemon_log}"
