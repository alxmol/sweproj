#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8081}"
SESSION="${SESSION:-mini-edr-ws-realtime-$$}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon

LISTENER_JSON="$WORK_DIR/ws-fast.json"
python3 "$ROOT_DIR/tests/web/ws_client.py" listen --port "$PORT" --count 10 --timeout 15 \
  >"$LISTENER_JSON" &
LISTENER_PID=$!
sleep 0.5

SNAPSHOT_PATH="$WORK_DIR/realtime-alerts.json"
python3 - "$SNAPSHOT_PATH" <<'PY'
import datetime as dt
import json
import sys

destination = sys.argv[1]
now = dt.datetime.now(dt.timezone.utc)
alerts = []
for index in range(10):
    alerts.append(
        {
            "alert_id": 40_000 + index,
            "timestamp": (now + dt.timedelta(milliseconds=index)).isoformat().replace("+00:00", "Z"),
            "pid": 40_000 + index,
            "process_name": f"realtime-{index}",
            "binary_path": f"/tmp/realtime-{index}",
            "ancestry_chain": [
                {
                    "pid": 1,
                    "process_name": "systemd",
                    "binary_path": "/usr/lib/systemd/systemd",
                }
            ],
            "threat_score": 0.95,
            "top_features": [{"feature_name": "entropy", "contribution_score": 0.95}],
            "summary": f"realtime alert {index}",
        }
    )

with open(destination, "w", encoding="utf-8") as handle:
    json.dump({"alerts": alerts}, handle)
PY

emit_alert_snapshot "$SNAPSHOT_PATH"
wait "$LISTENER_PID"

python3 - "$LISTENER_JSON" <<'PY'
import datetime as dt
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
alerts = report["alerts"]
if report["status_code"] != 101:
    raise SystemExit(f"expected WebSocket upgrade status 101, got {report['status_code']}")
if report["received_count"] != 10:
    raise SystemExit(f"expected 10 alerts over /ws, got {report['received_count']}")

latencies = []
for alert in alerts:
    sent_at = dt.datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00")).timestamp() * 1000.0
    latencies.append(alert["receive_ms"] - sent_at)

maximum = max(latencies)
mean = sum(latencies) / len(latencies)
if maximum >= 2000.0:
    raise SystemExit(f"max WebSocket latency {maximum:.2f}ms exceeded 2000ms")
if mean >= 1000.0:
    raise SystemExit(f"mean WebSocket latency {mean:.2f}ms exceeded 1000ms")
PY
