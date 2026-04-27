#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8081}"
SESSION="${SESSION:-mini-edr-ws-reconnect-$$}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon
open_dashboard

agent-browser --session "$SESSION" wait --fn "Boolean(window.__miniEdrDebug) && window.__miniEdrDebug.transport.openCount >= 1" >/dev/null
INITIAL_OPEN_COUNT="$(browser_eval "String(window.__miniEdrDebug.transport.openCount)")"

kill "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""
sleep 0.5
start_dashboard_daemon

agent-browser --session "$SESSION" wait --fn "window.__miniEdrDebug.transport.openCount >= 2" --timeout 10000 >/dev/null
UPDATED_OPEN_COUNT="$(browser_eval "String(window.__miniEdrDebug.transport.openCount)")"
[[ "$UPDATED_OPEN_COUNT" -gt "$INITIAL_OPEN_COUNT" ]] || {
  echo "WebSocket open count did not increase after the daemon restart" >&2
  exit 1
}

SNAPSHOT_PATH="$WORK_DIR/reconnect-alert.json"
python3 - "$SNAPSHOT_PATH" <<'PY'
import datetime as dt
import json
import sys

destination = sys.argv[1]
alert = {
    "alert_id": 50_001,
    "timestamp": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "pid": 50_001,
    "process_name": "post-restart-alert",
    "binary_path": "/tmp/post-restart-alert",
    "ancestry_chain": [
        {
            "pid": 1,
            "process_name": "systemd",
            "binary_path": "/usr/lib/systemd/systemd",
        }
    ],
    "threat_score": 0.95,
    "top_features": [{"feature_name": "entropy", "contribution_score": 0.95}],
    "summary": "alert emitted after daemon restart",
}
with open(destination, "w", encoding="utf-8") as handle:
    json.dump({"alerts": [alert]}, handle)
PY

emit_alert_snapshot "$SNAPSHOT_PATH"
agent-browser --session "$SESSION" wait ".alert-row[data-alert-id='50001']" --timeout 5000 >/dev/null

TRANSPORT_MODE="$(browser_eval "String(window.__miniEdrDebug.transport.mode)")"
[[ "$TRANSPORT_MODE" == "websocket" ]] || {
  echo "expected the dashboard to reconnect over WebSocket, got ${TRANSPORT_MODE}" >&2
  exit 1
}

assert_no_browser_errors
