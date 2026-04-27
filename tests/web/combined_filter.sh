#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8081}"
SESSION="${SESSION:-mini-edr-combined-filter-$$}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon

SNAPSHOT_PATH="$WORK_DIR/combined-alerts.json"
python3 - "$SNAPSHOT_PATH" <<'PY'
import datetime as dt
import json
import sys

destination = sys.argv[1]
now = dt.datetime.now(dt.timezone.utc)
alerts = []
entries = [
    ("recent-low-1", 10, 0.75),
    ("recent-low-2", 15, 0.76),
    ("recent-medium-1", 8, 0.85),
    ("recent-medium-2", 25, 0.86),
    ("recent-high-1", 5, 0.95),
    ("recent-high-2", 20, 0.96),
    ("old-medium-1", 45, 0.84),
    ("old-medium-2", 70, 0.88),
    ("old-high-1", 90, 0.93),
    ("old-high-2", 120, 0.97),
]
for index, (label, minutes_ago, score) in enumerate(entries, start=1):
    alerts.append(
        {
            "alert_id": 30_000 + index,
            "timestamp": (now - dt.timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z"),
            "pid": 30_000 + index,
            "process_name": label,
            "binary_path": f"/tmp/{label}",
            "ancestry_chain": [
                {
                    "pid": 1,
                    "process_name": "systemd",
                    "binary_path": "/usr/lib/systemd/systemd",
                }
            ],
            "threat_score": score,
            "top_features": [{"feature_name": "entropy", "contribution_score": score}],
            "summary": f"{label} summary",
        }
    )

with open(destination, "w", encoding="utf-8") as handle:
    json.dump({"alerts": alerts}, handle)
PY

post_alert_snapshot "$SNAPSHOT_PATH"
open_dashboard
agent-browser --session "$SESSION" wait ".alert-row[data-alert-id='30001']" >/dev/null
agent-browser --session "$SESSION" select "#severity-filter" "medium+" >/dev/null
agent-browser --session "$SESSION" select "#time-filter" "last_30m" >/dev/null
agent-browser --session "$SESSION" wait 250 >/dev/null

FILTERED_COUNT="$(browser_eval "String(document.querySelectorAll('.alert-row').length)")"
[[ "$FILTERED_COUNT" == "4" ]] || {
  echo "expected 4 alert rows after combined filtering, got ${FILTERED_COUNT}" >&2
  exit 1
}

INTERSECTION_OK="$(browser_eval "String(Array.from(document.querySelectorAll('.alert-row')).every((row) => ['medium', 'high'].includes(row.dataset.severity) && Date.now() - Number(row.dataset.timestamp) <= 30 * 60 * 1000))")"
[[ "$INTERSECTION_OK" == "true" ]] || {
  echo "combined filters did not produce the expected intersection" >&2
  exit 1
}
