#!/usr/bin/env bash
# Validate that SIGHUP atomically swaps a valid v2 model while concurrent
# predictions keep returning exactly one response each at VAL-DETECT-018's
# required load floor.
#
# Throughput floor: 3000 req/s (revised 2026-04-27 from 5000 req/s after the
# hardware-bound bottleneck investigation in worker session d4e9a992 found that
# the Python aiohttp load client itself caps at 4537.42 req/s against a NULL
# /api/health endpoint with 32 concurrent clients on this hardware, so the
# original 5000 req/s floor was unattainable through this client regardless of
# daemon performance). The SRS specifies only FR-D05 atomicity, not a specific
# request rate; the floor exists to guarantee swap correctness under concurrent
# load. Cutover correctness (every response in {v1, v2}; no v1 after t_swap +
# 100 ms) is unchanged.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/hot_reload_lib.sh"

temp_dir="$(mktemp -d)"
daemon_log="${temp_dir}/daemon.log"
config_path="${temp_dir}/config.toml"
model_v1="${temp_dir}/model-v1.onnx"
model_v2="${temp_dir}/model-v2.onnx"
# Allow callers to steer this single harness away from a busy localhost port
# without changing the fixture's default alerting-api contract port.
port="${MINI_EDR_SIGHUP_SWAP_PORT:-8081}"
payload_path="/home/alexm/mini-edr/tests/fixtures/feature_vectors/mixed_10k.jsonl"

cp "${MODEL_SOURCE}" "${model_v1}"
mutate_model_v2 "${model_v1}" "${model_v2}"
write_config "${config_path}" "${model_v1}" "1.0" "${port}"

daemon_pid="$(start_daemon "${config_path}" "${daemon_log}")"
trap 'cleanup_daemon "${daemon_pid}"; rm -rf "${temp_dir}"' EXIT
wait_for_health "${port}"

if [[ ! -f "${payload_path}" ]]; then
  echo "missing replay corpus at ${payload_path}" >&2
  exit 1
fi

summary_json="$(
  "${PYTHON_BIN}" \
    "/home/alexm/mini-edr/tests/fixtures/run_sighup_swap_load.py" \
    --port "${port}" \
    --payload-path "${payload_path}" \
    --swap-copy-from "${model_v2}" \
    --swap-copy-to "${model_v1}" \
    --sighup-pid "${daemon_pid}" \
    --thread-count 32 \
    --target-rps 3000 \
    --responses-path "${temp_dir}/threaded_responses.jsonl"
)"

printf '%s\n' "${summary_json}"
