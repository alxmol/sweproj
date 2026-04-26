#!/usr/bin/env bash
# Validate that a corrupted model candidate is rejected and v1 remains live.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/hot_reload_lib.sh"

temp_dir="$(mktemp -d)"
daemon_log="${temp_dir}/daemon.log"
config_path="${temp_dir}/config.toml"
model_path="${temp_dir}/model.onnx"
port=8082

cp "${MODEL_SOURCE}" "${model_path}"
write_config "${config_path}" "${model_path}" "1.0" "${port}"

daemon_pid="$(start_daemon "${config_path}" "${daemon_log}")"
trap 'cleanup_daemon "${daemon_pid}"; rm -rf "${temp_dir}"' EXIT
wait_for_health "${port}"

health_json "${port}" >"${temp_dir}/before.json"
printf 'not-a-valid-onnx-model' >"${model_path}"
kill -HUP "${daemon_pid}"
sleep 0.2
health_json "${port}" >"${temp_dir}/after.json"

"${PYTHON_BIN}" - "${temp_dir}/before.json" "${temp_dir}/after.json" <<'PY'
import json
import sys

before_path, after_path = sys.argv[1:3]
with open(before_path, encoding="utf-8") as handle:
    before = json.load(handle)
with open(after_path, encoding="utf-8") as handle:
    after = json.load(handle)

assert before["model_hash"] == after["model_hash"], "invalid reload changed the live model hash"
assert after["state"] == "Running", f"daemon left Running: {after['state']}"
PY

grep -q 'model_validation_failed' "${daemon_log}"
