#!/usr/bin/env bash
# Validate threshold hot reload and invalid-threshold rollback behavior.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/hot_reload_lib.sh"

temp_dir="$(mktemp -d)"
daemon_log="${temp_dir}/daemon.log"
config_path="${temp_dir}/config.toml"
model_path="${temp_dir}/model.onnx"
port=8083

cp "${MODEL_SOURCE}" "${model_path}"
write_config "${config_path}" "${model_path}" "1.0" "${port}"

daemon_pid="$(start_daemon "${config_path}" "${daemon_log}")"
trap 'cleanup_daemon "${daemon_pid}"; rm -rf "${temp_dir}"' EXIT
wait_for_health "${port}"

sample_feature_vector_json | predict_json "${port}" >"${temp_dir}/before.json"
write_config "${config_path}" "${model_path}" "0.0" "${port}"
kill -HUP "${daemon_pid}"
sleep 0.2
sample_feature_vector_json | predict_json "${port}" >"${temp_dir}/after.json"
write_config "${config_path}" "${model_path}" "2.0" "${port}"
kill -HUP "${daemon_pid}"
sleep 0.2
sample_feature_vector_json | predict_json "${port}" >"${temp_dir}/after_invalid.json"

"${PYTHON_BIN}" - "${temp_dir}/before.json" "${temp_dir}/after.json" "${temp_dir}/after_invalid.json" <<'PY'
import json
import sys

before_path, after_path, after_invalid_path = sys.argv[1:4]
with open(before_path, encoding="utf-8") as handle:
    before = json.load(handle)
with open(after_path, encoding="utf-8") as handle:
    after = json.load(handle)
with open(after_invalid_path, encoding="utf-8") as handle:
    after_invalid = json.load(handle)

assert before["threshold"] == 1.0, before
assert after["threshold"] == 0.0, after
assert after["would_alert"], "threshold 0.0 should always alert"
assert after_invalid["threshold"] == 0.0, after_invalid
assert after_invalid["would_alert"], "invalid threshold reload must retain the previous 0.0 threshold"
PY

grep -q 'alert_threshold_rejected' "${daemon_log}"
