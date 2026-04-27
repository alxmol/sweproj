#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8081}"
SESSION="${SESSION:-mini-edr-health-overview-$$}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
PREDICTOR_PID=""

cleanup() {
  if [[ -n "$PREDICTOR_PID" ]] && kill -0 "$PREDICTOR_PID" 2>/dev/null; then
    kill "$PREDICTOR_PID" 2>/dev/null || true
    wait "$PREDICTOR_PID" 2>/dev/null || true
  fi
  cleanup_dashboard_tree_test
}

trap cleanup EXIT

start_dashboard_daemon
open_dashboard

agent-browser --session "$SESSION" click "#health-tab-button" >/dev/null
agent-browser --session "$SESSION" wait "[data-metric='events-per-second']" >/dev/null

python3 - "$PORT" \
  "$ROOT_DIR/tests/fixtures/feature_vectors/high_085.json" \
  "$ROOT_DIR/tests/fixtures/feature_vectors/below_threshold.json" <<'PY' &
import json
import sys
import time
import urllib.request

port = int(sys.argv[1])
payload_paths = sys.argv[2:]
payloads = [json.load(open(path, encoding="utf-8")) for path in payload_paths]
deadline = time.monotonic() + 4.0
index = 0
while time.monotonic() < deadline:
    payload = payloads[index % len(payloads)]
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/internal/predict",
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        if response.status != 200:
            raise SystemExit(f"predict returned {response.status}")
        response.read()
    index += 1
    time.sleep(0.05 if index % 2 == 0 else 0.08)
PY
PREDICTOR_PID=$!

sleep 0.5

METRICS_BEFORE="$(browser_eval "JSON.stringify(Object.fromEntries(Array.from(document.querySelectorAll('[data-metric]')).map((node) => [node.dataset.metric, Number(node.dataset.rawValue)])))")"
agent-browser --session "$SESSION" wait 2200 >/dev/null
METRICS_AFTER="$(browser_eval "JSON.stringify(Object.fromEntries(Array.from(document.querySelectorAll('[data-metric]')).map((node) => [node.dataset.metric, Number(node.dataset.rawValue)])))")"

python3 - "$METRICS_BEFORE" "$METRICS_AFTER" <<'PY'
import json
import sys

before = json.loads(sys.argv[1])
after = json.loads(sys.argv[2])
required = [
    "events-per-second",
    "ring-buffer-utilization",
    "inference-latency",
    "uptime",
    "memory",
]
missing = [name for name in required if name not in before or name not in after]
if missing:
    raise SystemExit(f"missing required health metrics: {missing}")

changed = [name for name in required if before[name] != after[name]]
if len(changed) < 3:
    raise SystemExit(
        f"expected at least 3 health metrics to change over 2 seconds, got {changed}; before={before} after={after}"
    )

if after["uptime"] <= before["uptime"]:
    raise SystemExit(f"expected uptime to increase, got before={before['uptime']} after={after['uptime']}")
PY

HEALTH_PANEL_VISIBLE="$(browser_eval "String(!document.getElementById('health-tab-panel').hidden)")"
[[ "$HEALTH_PANEL_VISIBLE" == "true" ]] || {
  echo "expected the health tab panel to be visible after selecting it" >&2
  exit 1
}

assert_browser_text_contains "#health-tab-panel" "Events/s"
assert_browser_text_contains "#health-tab-panel" "Ring buffer utilization"
assert_browser_text_contains "#health-tab-panel" "Inference latency"
assert_browser_text_contains "#health-tab-panel" "Uptime"
assert_browser_text_contains "#health-tab-panel" "Memory"
assert_no_browser_errors
