#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8081}"
SESSION="${SESSION:-mini-edr-ws-storm-$$}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon

BASELINE_JSON="$WORK_DIR/ws-baseline.json"
STORM_JSON="$WORK_DIR/ws-storm.json"

python3 "$ROOT_DIR/tests/web/ws_client.py" listen --port "$PORT" --count 1 --timeout 15 \
  >"$BASELINE_JSON" &
BASELINE_PID=$!
sleep 0.5

python3 "$ROOT_DIR/tests/web/ws_client.py" storm --port "$PORT" --connections 1000 --timeout 5 \
  --hold-seconds 4 >"$STORM_JSON" &
STORM_PID=$!
sleep 1

SNAPSHOT_PATH="$WORK_DIR/storm-alert.json"
python3 - "$SNAPSHOT_PATH" <<'PY'
import datetime as dt
import json
import sys

destination = sys.argv[1]
alert = {
    "alert_id": 70_001,
    "timestamp": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "pid": 70_001,
    "process_name": "storm-baseline",
    "binary_path": "/tmp/storm-baseline",
    "ancestry_chain": [
        {
            "pid": 1,
            "process_name": "systemd",
            "binary_path": "/usr/lib/systemd/systemd",
        }
    ],
    "threat_score": 0.95,
    "top_features": [{"feature_name": "entropy", "contribution_score": 0.95}],
    "summary": "baseline alert during connection storm",
}
with open(destination, "w", encoding="utf-8") as handle:
    json.dump({"alerts": [alert]}, handle)
PY

emit_alert_snapshot "$SNAPSHOT_PATH"
wait "$BASELINE_PID"
wait "$STORM_PID"

python3 - "$BASELINE_JSON" "$STORM_JSON" <<'PY'
import json
import sys

baseline = json.load(open(sys.argv[1], encoding="utf-8"))
storm = json.load(open(sys.argv[2], encoding="utf-8"))

if baseline["status_code"] != 101:
    raise SystemExit(f"baseline client expected status 101, got {baseline['status_code']}")
if baseline["received_count"] != 1:
    raise SystemExit(f"baseline client expected one alert during the storm, got {baseline['received_count']}")

accepted = storm["accepted"]
rejected = storm["rejected"]
if accepted > 64:
    raise SystemExit(f"storm accepted too many additional clients: {accepted}")
if accepted < 55:
    raise SystemExit(f"storm accepted unexpectedly few additional clients: {accepted}")
if rejected < 935:
    raise SystemExit(f"storm rejected too few excess clients: {rejected}")
PY

RSS_BYTES="$(curl -fsS "http://127.0.0.1:${PORT}/telemetry/summary" | jq -r '.rss_bytes')"
[[ "$RSS_BYTES" -lt 268435456 ]] || {
  echo "resident set size exceeded 256 MiB during the connection storm: ${RSS_BYTES}" >&2
  exit 1
}
