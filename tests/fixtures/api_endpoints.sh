#!/usr/bin/env bash
# Validate the local API endpoint set over both localhost HTTP and the Unix socket.

set -euo pipefail

source "/home/directory/mini-edr/tests/fixtures/fixture_runtime_lib.sh"

temp_dir="$(mktemp -d /tmp/mini-edr-api-endpoints-XXXXXX)"
stream_capture_path="${temp_dir}/alerts-stream.jsonl"

cleanup() {
  if [[ -n "${stream_pid:-}" ]]; then
    fixture_stop_alert_stream "${stream_pid}"
  fi
  if [[ -n "${daemon_pid:-}" ]]; then
    cleanup_daemon "${daemon_pid}"
  fi
}
trap cleanup EXIT

read -r daemon_pid daemon_port _config_path _log_path daemon_socket < <(fixture_start_isolated_daemon "${temp_dir}" 0.7)
stream_pid="$(fixture_start_alert_stream "${daemon_socket}" "${stream_capture_path}")"

curl -fsS "http://127.0.0.1:${daemon_port}/health" >"${temp_dir}/health.json"
curl -fsS "http://127.0.0.1:${daemon_port}/telemetry" >"${temp_dir}/telemetry.json"
curl --unix-socket "${daemon_socket}" -fsS "http://localhost/health" >"${temp_dir}/unix-health.json"

start_line="$(fixture_stream_line_count "${stream_capture_path}")"
curl -fsS \
  -H 'content-type: application/json' \
  -d @"/home/directory/mini-edr/tests/fixtures/feature_vectors/high_085.json" \
  "http://127.0.0.1:${daemon_port}/internal/predict" >"${temp_dir}/predict.json"

alert_count="$(fixture_wait_for_alert_count \
  "${stream_capture_path}" \
  "/home/directory/mini-edr/tests/fixtures/feature_vectors/high_085.json" \
  "${start_line}" \
  2)"

"${FIXTURE_PYTHON_BIN}" - \
  "${temp_dir}/health.json" \
  "${temp_dir}/telemetry.json" \
  "${temp_dir}/unix-health.json" \
  "${temp_dir}/predict.json" \
  "${alert_count}" \
  "/home/directory/mini-edr/tests/fixtures/feature_vectors/THRESHOLD_FIXTURES.md" <<'PY'
import json
import sys
from pathlib import Path

health_path, telemetry_path, unix_health_path, predict_path, alert_count, threshold_doc_path = sys.argv[1:7]
health = json.load(open(health_path, encoding="utf-8"))
telemetry = json.load(open(telemetry_path, encoding="utf-8"))
unix_health = json.load(open(unix_health_path, encoding="utf-8"))
predict = json.load(open(predict_path, encoding="utf-8"))

contracts = {}
for line in Path(threshold_doc_path).read_text(encoding="utf-8").splitlines():
    stripped = line.strip()
    if not stripped.startswith("|"):
        continue
    cells = [cell.strip() for cell in stripped.strip("|").split("|")]
    if len(cells) < 4 or cells[0] in {"fixture", "---"} or cells[0].startswith("---"):
        continue
    contracts[cells[0]] = {
        "natural_score": float(cells[1]),
        "band_low": float(cells[2]),
        "band_high": float(cells[3]),
    }

high_fixture = contracts["high_085"]

assert health == unix_health, "HTTP and Unix-socket health payloads diverged"
assert health["state"] == "Running", health
assert telemetry["events_per_second"] >= 0.0, telemetry
assert telemetry["ring_buffer_util"] >= 0.0, telemetry
assert telemetry["inference_latency_p99_ms"] >= 0.0, telemetry
assert telemetry["uptime_seconds"] >= 0, telemetry
assert telemetry["rss_bytes"] >= 0, telemetry
assert int(alert_count) == 1, f"expected exactly one streamed alert, saw {alert_count}"
score = float(predict["threat_score"])
assert high_fixture["band_low"] <= score <= high_fixture["band_high"], predict
PY

ss -lnt | rg "127\\.0\\.0\\.1:${daemon_port}\\b" >/dev/null
external_ip="$(hostname -I | tr ' ' '\n' | grep -v '^127\.' | head -n 1 || true)"
if [[ -n "${external_ip}" ]]; then
  if curl --max-time 1 -fsS "http://${external_ip}:${daemon_port}/health" >/dev/null 2>&1; then
    echo "unexpectedly reached local API through non-loopback address ${external_ip}:${daemon_port}" >&2
    exit 1
  fi
fi
