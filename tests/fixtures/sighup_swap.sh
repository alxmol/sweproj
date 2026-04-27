#!/usr/bin/env bash
# Validate that SIGHUP atomically swaps a valid v2 model while concurrent
# predictions keep returning exactly one response each.

set -euo pipefail

source "/home/alexm/mini-edr/tests/fixtures/hot_reload_lib.sh"

temp_dir="$(mktemp -d)"
daemon_log="${temp_dir}/daemon.log"
config_path="${temp_dir}/config.toml"
model_v1="${temp_dir}/model-v1.onnx"
model_v2="${temp_dir}/model-v2.onnx"
port=8081
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

"${PYTHON_BIN}" - "${port}" "${payload_path}" "${temp_dir}/threaded_responses.jsonl" <<'PY' &
import json
import sys
import threading
import time
import urllib.request

port = int(sys.argv[1])
payloads_path = sys.argv[2]
output_path = sys.argv[3]
url = f"http://127.0.0.1:{port}/internal/predict"
lock = threading.Lock()
rows = [json.loads(line) for line in open(payloads_path, encoding="utf-8") if line.strip()]
responses = []
errors = []
thread_count = 32

def worker(thread_id: int) -> None:
    local = []
    for request_id in range(thread_id, len(rows), thread_count):
        request = urllib.request.Request(
            url,
            data=json.dumps(rows[request_id]).encode(),
            headers={"content-type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                body = json.loads(response.read())
        except Exception as exc:  # noqa: BLE001
            local.append(json.dumps({
                "thread_id": thread_id,
                "request_id": request_id,
                "error": repr(exc),
            }))
            continue
        body["thread_id"] = thread_id
        body["request_id"] = request_id
        local.append(json.dumps(body))
    with lock:
        responses.extend(local)

threads = [threading.Thread(target=worker, args=(index,)) for index in range(thread_count)]
for thread in threads:
    thread.start()
time.sleep(0.2)
for thread in threads:
    thread.join()
with open(output_path, "w", encoding="utf-8") as handle:
    for line in responses:
        handle.write(f"{line}\n")
PY
client_pid=$!

sleep 0.02
cp "${model_v2}" "${model_v1}"
kill -HUP "${daemon_pid}"
wait "${client_pid}"

health_json "${port}" >"${temp_dir}/health.json"

"${PYTHON_BIN}" - "${temp_dir}/threaded_responses.jsonl" "${temp_dir}/health.json" <<'PY'
import json
import sys

responses_path, health_path = sys.argv[1:3]
with open(responses_path, encoding="utf-8") as handle:
    rows = [json.loads(line) for line in handle if line.strip()]
with open(health_path, encoding="utf-8") as handle:
    health = json.load(handle)

errors = [row for row in rows if "error" in row]
assert not errors, f"observed request failures: {errors[:3]}"
assert len(rows) == 10_000, f"expected 10000 responses, saw {len(rows)}"
hashes = {row["model_hash"] for row in rows}
assert len(hashes) == 2, f"expected both v1 and v2 hashes, saw {hashes}"
first_v2 = min(row["emitted_at_ns"] for row in rows if row["model_hash"] == health["model_hash"])
late_v1 = [
    row for row in rows
    if row["model_hash"] != health["model_hash"] and row["emitted_at_ns"] > first_v2 + 100_000_000
]
assert not late_v1, f"observed {len(late_v1)} late v1 responses after v2 cutover"
assert health["model_hash"] in hashes, "health endpoint did not converge to v2"
assert health["state"] == "Running", f"daemon left Running: {health['state']}"
PY
