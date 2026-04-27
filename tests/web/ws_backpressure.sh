#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8081}"
SESSION="${SESSION:-mini-edr-ws-backpressure-$$}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon

FAST_JSON="$WORK_DIR/ws-fast.json"
SLOW_JSON="$WORK_DIR/ws-slow.json"
ZOMBIE_JSON="$WORK_DIR/ws-zombie.json"

python3 "$ROOT_DIR/tests/web/ws_client.py" listen --port "$PORT" --count 50000 --timeout 90 \
  >"$FAST_JSON" &
FAST_PID=$!
python3 "$ROOT_DIR/tests/web/ws_client.py" listen --port "$PORT" --count 10 --timeout 20 \
  --mode slow --delay-seconds 1 --hold-seconds 12 >"$SLOW_JSON" &
SLOW_PID=$!
python3 "$ROOT_DIR/tests/web/ws_client.py" listen --port "$PORT" --mode zombie --hold-seconds 12 \
  >"$ZOMBIE_JSON" &
ZOMBIE_PID=$!
sleep 1

SNAPSHOT_PATH="$WORK_DIR/backpressure-alerts.json"
python3 - "$SNAPSHOT_PATH" <<'PY'
import datetime as dt
import json
import sys

destination = sys.argv[1]
now = dt.datetime.now(dt.timezone.utc)
alerts = []
for index in range(50_000):
    alerts.append(
        {
            "alert_id": 60_000 + index,
            "timestamp": (now + dt.timedelta(milliseconds=index)).isoformat().replace("+00:00", "Z"),
            "pid": 60_000 + index,
            "process_name": f"pressure-{index}",
            "binary_path": f"/tmp/pressure-{index}",
            "ancestry_chain": [
                {
                    "pid": 1,
                    "process_name": "systemd",
                    "binary_path": "/usr/lib/systemd/systemd",
                }
            ],
            "threat_score": 0.95,
            "top_features": [{"feature_name": "entropy", "contribution_score": 0.95}],
            "summary": "x" * 256,
        }
    )

with open(destination, "w", encoding="utf-8") as handle:
    json.dump({"alerts": alerts}, handle, separators=(",", ":"))
PY

emit_alert_snapshot "$SNAPSHOT_PATH"
wait "$FAST_PID"
wait "$SLOW_PID"
wait "$ZOMBIE_PID"

python3 - "$FAST_JSON" "$SLOW_JSON" <<'PY'
import json
import sys

fast = json.load(open(sys.argv[1], encoding="utf-8"))
slow = json.load(open(sys.argv[2], encoding="utf-8"))

if fast["status_code"] != 101:
    raise SystemExit(f"fast client expected status 101, got {fast['status_code']}")
if fast["received_count"] < 49_500:
    raise SystemExit(f"fast client received only {fast['received_count']} alerts")

if slow["status_code"] != 101:
    raise SystemExit(f"slow client expected status 101, got {slow['status_code']}")
if slow["received_count"] > 12:
    raise SystemExit(f"slow client read faster than its 1 alert/s budget: {slow['received_count']}")
PY

RSS_BYTES="$(curl -fsS "http://127.0.0.1:${PORT}/telemetry/summary" | jq -r '.rss_bytes')"
[[ "$RSS_BYTES" -lt 268435456 ]] || {
  echo "resident set size exceeded 256 MiB: ${RSS_BYTES}" >&2
  exit 1
}

grep -q 'ws_client_dropped' "$DAEMON_LOG" || {
  echo "expected the daemon log to record a dropped WebSocket client" >&2
  exit 1
}
