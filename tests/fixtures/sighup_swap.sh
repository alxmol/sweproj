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

cp "${MODEL_SOURCE}" "${model_v1}"
mutate_model_v2 "${model_v1}" "${model_v2}"
write_config "${config_path}" "${model_v1}" "1.0" "${port}"

daemon_pid="$(start_daemon "${config_path}" "${daemon_log}")"
trap 'cleanup_daemon "${daemon_pid}"; rm -rf "${temp_dir}"' EXIT
wait_for_health "${port}"

: >"${temp_dir}/responses.jsonl"
for _ in $(seq 1 10); do
  sample_feature_vector_json | predict_json "${port}" >>"${temp_dir}/responses.jsonl"
  printf '\n' >>"${temp_dir}/responses.jsonl"
done

"${PYTHON_BIN}" - "${port}" "${temp_dir}/threaded_responses.jsonl" <<'PY' &
import json
import sys
import threading
import time
import urllib.request

port = int(sys.argv[1])
output_path = sys.argv[2]
payload = json.dumps({
    "pid": 4242,
    "window_start_ns": 1713000000000000000,
    "window_end_ns": 1713000005000000000,
    "total_syscalls": 128,
    "execve_count": 1,
    "openat_count": 100,
    "connect_count": 3,
    "clone_count": 2,
    "execve_ratio": 0.0078125,
    "openat_ratio": 0.78125,
    "connect_ratio": 0.0234375,
    "clone_ratio": 0.015625,
    "bigrams": {"__process_positive_rate__": 0.65, "__event_positive_rate__": 0.15},
    "trigrams": {"__path_positive_rate__": 0.35},
    "path_entropy": 1.5,
    "unique_ips": 2,
    "unique_files": 12,
    "child_spawn_count": 2,
    "avg_inter_syscall_time_ns": 1500000.0,
    "min_inter_syscall_time_ns": 10000.0,
    "max_inter_syscall_time_ns": 9000000.0,
    "stddev_inter_syscall_time_ns": 500000.0,
    "wrote_etc": True,
    "wrote_tmp": True,
    "wrote_dev": False,
    "read_sensitive_file_count": 4,
    "write_sensitive_file_count": 2,
    "outbound_connection_count": 3,
    "loopback_connection_count": 1,
    "distinct_ports": 2,
    "failed_syscall_count": 1,
    "short_lived": False,
    "window_duration_ns": 5000000000,
    "events_per_second": 25.6,
}).encode()
url = f"http://127.0.0.1:{port}/internal/predict"
lock = threading.Lock()
errors = []

def worker(thread_id: int) -> None:
    local = []
    for request_id in range(120):
        request = urllib.request.Request(
            url,
            data=payload,
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            body = json.loads(response.read())
        body["thread_id"] = thread_id
        body["request_id"] = request_id
        local.append(json.dumps(body))
        time.sleep(0.002)
    with lock:
        errors.extend(local)

threads = [threading.Thread(target=worker, args=(index,)) for index in range(16)]
for thread in threads:
    thread.start()
time.sleep(0.2)
for thread in threads:
    thread.join()
with open(output_path, "w", encoding="utf-8") as handle:
    for line in errors:
        handle.write(f"{line}\n")
PY
client_pid=$!

sleep 0.02
cp "${model_v2}" "${model_v1}"
kill -HUP "${daemon_pid}"
wait "${client_pid}"
cat "${temp_dir}/threaded_responses.jsonl" >>"${temp_dir}/responses.jsonl"

health_json "${port}" >"${temp_dir}/health.json"

"${PYTHON_BIN}" - "${temp_dir}/responses.jsonl" "${temp_dir}/health.json" <<'PY'
import json
import sys

responses_path, health_path = sys.argv[1:3]
with open(responses_path, encoding="utf-8") as handle:
    rows = [json.loads(line) for line in handle if line.strip()]
with open(health_path, encoding="utf-8") as handle:
    health = json.load(handle)

assert len(rows) == 10 + 16 * 120, f"expected 1930 responses, saw {len(rows)}"
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
