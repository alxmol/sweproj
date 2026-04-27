#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8081}"
SESSION="${SESSION:-mini-edr-time-filter-$$}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon

SNAPSHOT_PATH="$WORK_DIR/time-alerts.json"
python3 - "$SNAPSHOT_PATH" <<'PY'
import datetime as dt
import json
import sys

destination = sys.argv[1]
now = dt.datetime.now(dt.timezone.utc)
alerts = []
entries = [
    (1, 5, 0.75),
    (2, 12, 0.85),
    (3, 20, 0.95),
    (4, 45, 0.75),
    (5, 75, 0.85),
    (6, 110, 0.95),
]
for alert_id, minutes_ago, score in entries:
    alerts.append(
        {
            "alert_id": 20_000 + alert_id,
            "timestamp": (now - dt.timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z"),
            "pid": 20_000 + alert_id,
            "process_name": f"time-alert-{alert_id}",
            "binary_path": f"/tmp/time-alert-{alert_id}",
            "ancestry_chain": [
                {
                    "pid": 1,
                    "process_name": "systemd",
                    "binary_path": "/usr/lib/systemd/systemd",
                }
            ],
            "threat_score": score,
            "top_features": [{"feature_name": "entropy", "contribution_score": score}],
            "summary": f"alert generated {minutes_ago} minutes ago",
        }
    )

with open(destination, "w", encoding="utf-8") as handle:
    json.dump({"alerts": alerts}, handle)
PY

post_alert_snapshot "$SNAPSHOT_PATH"
open_dashboard
agent-browser --session "$SESSION" wait ".alert-row[data-alert-id='20001']" >/dev/null
agent-browser --session "$SESSION" select "#time-filter" "last_30m" >/dev/null
agent-browser --session "$SESSION" wait 250 >/dev/null

FILTERED_COUNT="$(browser_eval "String(document.querySelectorAll('.alert-row').length)")"
[[ "$FILTERED_COUNT" == "3" ]] || {
  echo "expected 3 alert rows inside the last 30 minutes, got ${FILTERED_COUNT}" >&2
  exit 1
}

ONLY_RECENT="$(browser_eval "String(Array.from(document.querySelectorAll('.alert-row')).every((row) => Date.now() - Number(row.dataset.timestamp) <= 30 * 60 * 1000))")"
[[ "$ONLY_RECENT" == "true" ]] || {
  echo "time-filter left an alert older than 30 minutes visible" >&2
  exit 1
}
