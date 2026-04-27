#!/usr/bin/env bash
# Verify that rejected SIGHUP reloads leave the live daemon config untouched
# and that same-path model swaps force a fresh runtime prior-catalog load.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/hot_reload_lib.sh"

repo_root="/home/alexm/mini-edr"
binary="${repo_root}/target/release/mini-edr-daemon"
temp_dir="$(mktemp -d)"
daemon_log="${temp_dir}/daemon.log"
config_path="${temp_dir}/config.toml"
model_path="${temp_dir}/model.onnx"
prior_catalog_path="${temp_dir}/prior_catalog.json"
socket_path="${temp_dir}/api.sock"
state_dir="${temp_dir}/state"
port="${MINI_EDR_RELOAD_ROLLBACK_PORT:-8086}"
daemon_pid=""

sweep_orphan_daemons() {
  pgrep -x mini-edr-daemon | xargs -r kill -TERM 2>/dev/null || true
  sleep 3
  pgrep -x mini-edr-daemon | xargs -r kill -KILL 2>/dev/null || true
}

cleanup() {
  if [[ -n "${daemon_pid}" ]]; then
    cleanup_daemon "${daemon_pid}"
  fi
  sweep_orphan_daemons
  rm -rf "${temp_dir}"
}
trap cleanup EXIT

sweep_orphan_daemons

cargo build --release -p mini-edr-daemon --manifest-path "${repo_root}/Cargo.toml" >/dev/null

cp "${MODEL_SOURCE}" "${model_path}"
cp "${repo_root}/training/output/prior_catalog.json" "${prior_catalog_path}"
mkdir -p "${state_dir}"
write_config "${config_path}" "${model_path}" "1.0" "${port}"

MINI_EDR_TEST_MODE=1 \
MINI_EDR_TEST_SENSOR_RATE=250 \
MINI_EDR_API_SOCKET="${socket_path}" \
  "${binary}" --config "${config_path}" >"${daemon_log}" 2>&1 &
daemon_pid=$!

wait_for_health "${port}"

# Phase 1: the config on disk changes threshold + monitored probes, but the
# model path is missing. A rejected SIGHUP must keep the live sensor config,
# threshold, and model hash untouched.
health_json "${port}" >"${temp_dir}/before-reject-health.json"
sample_feature_vector_json | predict_json "${port}" >"${temp_dir}/before-reject-predict.json"
cat >"${config_path}" <<EOF
alert_threshold = 0.0
web_port = ${port}
model_path = "${temp_dir}/missing-model.onnx"
log_file_path = "${temp_dir}/logs/alerts.jsonl"
state_dir = "${state_dir}"
monitored_syscalls = ["openat"]
enable_tui = false
EOF
kill -HUP "${daemon_pid}"

for _ in $(seq 1 120); do
  if grep -q 'model_path_missing' "${daemon_log}"; then
    break
  fi
  sleep 0.05
done

health_json "${port}" >"${temp_dir}/after-reject-health.json"
sample_feature_vector_json | predict_json "${port}" >"${temp_dir}/after-reject-predict.json"

"${PYTHON_BIN}" - \
  "${temp_dir}/before-reject-health.json" \
  "${temp_dir}/after-reject-health.json" \
  "${temp_dir}/before-reject-predict.json" \
  "${temp_dir}/after-reject-predict.json" <<'PY'
import json
import sys

(
    before_health_path,
    after_health_path,
    before_predict_path,
    after_predict_path,
) = sys.argv[1:5]

with open(before_health_path, encoding="utf-8") as handle:
    before_health = json.load(handle)
with open(after_health_path, encoding="utf-8") as handle:
    after_health = json.load(handle)
with open(before_predict_path, encoding="utf-8") as handle:
    before_predict = json.load(handle)
with open(after_predict_path, encoding="utf-8") as handle:
    after_predict = json.load(handle)

assert after_health["state"] == "Running", after_health
assert after_health["model_hash"] == before_health["model_hash"], (before_health, after_health)
assert after_health["alert_threshold"] == before_health["alert_threshold"], (
    before_health,
    after_health,
)
assert after_health["active_probes"] == before_health["active_probes"], (
    before_health,
    after_health,
)
assert after_health["state_history"] == before_health["state_history"], (
    before_health,
    after_health,
)
assert (
    after_health["config_reload_success_total"]
    == before_health["config_reload_success_total"]
), (before_health, after_health)
assert after_predict["model_hash"] == before_predict["model_hash"], (
    before_predict,
    after_predict,
)
assert after_predict["threshold"] == before_predict["threshold"], (
    before_predict,
    after_predict,
)
PY

grep -q 'model_path_missing' "${daemon_log}"

# Phase 2: swap new model bytes into the same path and overwrite the companion
# prior catalog in place. The daemon must load priors again even though the
# model path string did not change.
write_config "${config_path}" "${model_path}" "1.0" "${port}"
health_json "${port}" >"${temp_dir}/before-swap-health.json"
sample_feature_vector_json | predict_json "${port}" >"${temp_dir}/before-swap-predict.json"
prior_reload_count_before="$(grep -c 'runtime_prior_catalog_loaded' "${daemon_log}" || true)"

"${PYTHON_BIN}" - "${model_path}" <<'PY'
import sys
import onnx

model_path = sys.argv[1]
model = onnx.load(model_path)
model.producer_name = "mini-edr-reload-rollback-v2"

for node in model.graph.node:
    if node.op_type != "TreeEnsembleClassifier":
        continue
    for attribute in node.attribute:
        if attribute.name == "base_values":
            attribute.floats[0] = attribute.floats[0] + 0.75
            break
    break

onnx.save(model, model_path)
PY
"${PYTHON_BIN}" - "${prior_catalog_path}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    catalog = json.load(handle)

catalog["global_positive_rate"] = 0.91
catalog["process_positive_rate"]["synthetic-worker"] = 0.93
catalog["event_positive_rate"]["openat"] = 0.89
catalog["path_positive_rate"]["/tmp/mini-edr-synthetic-0.tmp"] = 0.87

with open(path, "w", encoding="utf-8") as handle:
    json.dump(catalog, handle)
PY

before_model_hash="$(python3 - "${temp_dir}/before-swap-health.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["model_hash"])
PY
)"

kill -HUP "${daemon_pid}"

for _ in $(seq 1 120); do
  health_json "${port}" >"${temp_dir}/after-swap-health.json"
  after_model_hash="$(python3 - "${temp_dir}/after-swap-health.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["model_hash"])
PY
)"
  prior_reload_count_after="$(grep -c 'runtime_prior_catalog_loaded' "${daemon_log}" || true)"
  if [[ "${after_model_hash}" != "${before_model_hash}" ]] && (( prior_reload_count_after > prior_reload_count_before )); then
    break
  fi
  sleep 0.05
done

sample_feature_vector_json | predict_json "${port}" >"${temp_dir}/after-swap-predict.json"

"${PYTHON_BIN}" - \
  "${temp_dir}/before-swap-health.json" \
  "${temp_dir}/after-swap-health.json" \
  "${temp_dir}/before-swap-predict.json" \
  "${temp_dir}/after-swap-predict.json" \
  "${prior_reload_count_before}" \
  "$(grep -c 'runtime_prior_catalog_loaded' "${daemon_log}" || true)" <<'PY'
import json
import sys

(
    before_health_path,
    after_health_path,
    before_predict_path,
    after_predict_path,
    before_prior_count,
    after_prior_count,
) = sys.argv[1:7]

with open(before_health_path, encoding="utf-8") as handle:
    before_health = json.load(handle)
with open(after_health_path, encoding="utf-8") as handle:
    after_health = json.load(handle)
with open(before_predict_path, encoding="utf-8") as handle:
    before_predict = json.load(handle)
with open(after_predict_path, encoding="utf-8") as handle:
    after_predict = json.load(handle)

assert after_health["state"] == "Running", after_health
assert after_health["model_hash"] != before_health["model_hash"], (
    before_health,
    after_health,
)
assert int(after_prior_count) > int(before_prior_count), (
    before_prior_count,
    after_prior_count,
)
assert after_predict["model_hash"] != before_predict["model_hash"], (
    before_predict,
    after_predict,
)
assert after_predict["threat_score"] != before_predict["threat_score"], (
    before_predict,
    after_predict,
)
PY

echo "PASS: rejected reload kept the live config; same-path model reload refreshed runtime priors"
