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

sample_feature_vector_json | predict_json "${port}" >"${temp_dir}/before-predict.json"
health_json "${port}" >"${temp_dir}/before-health.json"

"${PYTHON_BIN}" - "${config_path}" "${model_v2}" "${port}" "${temp_dir}/writer.log" <<'PY' &
import sys
import time

config_path, model_path, port, writer_log_path = sys.argv[1:5]
content = (
    "alert_threshold = 0.0\n"
    f"web_port = {port}\n"
    f"model_path = \"{model_path}\"\n"
    "log_file_path = \"alerts.json\"\n"
)
with open(config_path, "w", encoding="utf-8") as handle:
    for index, character in enumerate(content, start=1):
        handle.write(character)
        handle.flush()
        with open(writer_log_path, "a", encoding="utf-8") as writer_log:
            writer_log.write(f"{index}:{character!r}\n")
        time.sleep(0.2)
PY
writer_pid=$!

sampled_states_path="${temp_dir}/sampled-states.jsonl"
while kill -0 "${writer_pid}" >/dev/null 2>&1; do
  kill -HUP "${daemon_pid}"
  health_json "${port}" >>"${sampled_states_path}"
  printf '\n' >>"${sampled_states_path}"
  sleep 0.05
done
wait "${writer_pid}"

expected_config_hash="$(python3 - "${config_path}" <<'PY'
import hashlib
import pathlib
import sys

config_path = pathlib.Path(sys.argv[1])
print(hashlib.sha256(config_path.read_bytes()).hexdigest())
PY
)"

for _ in $(seq 1 120); do
  health_json "${port}" >"${temp_dir}/health.json"
  if python3 - "${temp_dir}/before-health.json" "${temp_dir}/health.json" "${expected_config_hash}" <<'PY'
import json
import sys

before_health_path, current_health_path, expected_hash = sys.argv[1:4]
with open(before_health_path, encoding="utf-8") as handle:
    before_health = json.load(handle)
with open(current_health_path, encoding="utf-8") as handle:
    current_health = json.load(handle)

success_advanced = (
    current_health["config_reload_success_total"]
    > before_health["config_reload_success_total"]
)
hash_converged = current_health["config_hash"] == expected_hash
running = current_health["state"] == "Running"

raise SystemExit(0 if success_advanced and hash_converged and running else 1)
PY
  then
    break
  fi
  sleep 0.1
done

sample_feature_vector_json | predict_json "${port}" >"${temp_dir}/after-predict.json"

"${PYTHON_BIN}" - \
  "${temp_dir}/before-health.json" \
  "${temp_dir}/health.json" \
  "${temp_dir}/before-predict.json" \
  "${temp_dir}/after-predict.json" \
  "${sampled_states_path}" \
  "${expected_config_hash}" <<'PY'
import json
import sys

(
    before_health_path,
    final_health_path,
    before_predict_path,
    after_predict_path,
    sampled_states_path,
    expected_hash,
) = sys.argv[1:7]

with open(before_health_path, encoding="utf-8") as handle:
    before_health = json.load(handle)
with open(final_health_path, encoding="utf-8") as handle:
    final_health = json.load(handle)
with open(before_predict_path, encoding="utf-8") as handle:
    before_predict = json.load(handle)
with open(after_predict_path, encoding="utf-8") as handle:
    after_predict = json.load(handle)
with open(sampled_states_path, encoding="utf-8") as handle:
    sampled_states = [json.loads(line) for line in handle if line.strip()]

assert sampled_states, "expected at least one health sample during the write"
assert all(
    sample["state"] == "Running" for sample in sampled_states
), sampled_states
assert final_health["state"] == "Running", final_health
assert final_health["alert_threshold"] == 0.0, final_health
assert final_health["config_hash"] == expected_hash, final_health
assert final_health["config_reload_partial_total"] >= 1, final_health
assert (
    final_health["config_reload_success_total"]
    > before_health["config_reload_success_total"]
), (before_health, final_health)
assert after_predict["threshold"] == 0.0, after_predict
assert (
    after_predict["model_hash"] != before_predict["model_hash"]
), (before_predict, after_predict)
PY

grep -q 'config_reload_partial' "${daemon_log}"
