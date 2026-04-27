#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8081}"
SESSION="${SESSION:-mini-edr-severity-filter-$$}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon

SNAPSHOT_PATH="$WORK_DIR/severity-alerts.json"
python3 - "$SNAPSHOT_PATH" <<'PY'
import datetime as dt
import json
import sys

destination = sys.argv[1]
now = dt.datetime.now(dt.timezone.utc)
alerts = []
alert_id = 10_000
for label, score in (("low", 0.75), ("medium", 0.85), ("high", 0.95)):
    for offset in range(4):
        alert_id += 1
        alerts.append(
            {
                "alert_id": alert_id,
                "timestamp": (now - dt.timedelta(minutes=offset)).isoformat().replace("+00:00", "Z"),
                "pid": alert_id,
                "process_name": f"{label}-process-{offset}",
                "binary_path": f"/tmp/{label}-process-{offset}",
                "ancestry_chain": [
                    {
                        "pid": 1,
                        "process_name": "systemd",
                        "binary_path": "/usr/lib/systemd/systemd",
                    }
                ],
                "threat_score": score,
                "top_features": [
                    {"feature_name": "entropy", "contribution_score": score},
                ],
                "summary": f"{label} threat alert {offset}",
            }
        )

with open(destination, "w", encoding="utf-8") as handle:
    json.dump({"alerts": alerts}, handle)
PY

post_alert_snapshot "$SNAPSHOT_PATH"
open_dashboard
agent-browser --session "$SESSION" wait ".alert-row[data-severity='low']" >/dev/null

INITIAL_COUNT="$(browser_eval "String(document.querySelectorAll('.alert-row').length)")"
[[ "$INITIAL_COUNT" == "12" ]] || {
  echo "expected 12 alert rows before filtering, got ${INITIAL_COUNT}" >&2
  exit 1
}

agent-browser --session "$SESSION" select "#severity-filter" "medium+" >/dev/null
agent-browser --session "$SESSION" wait 250 >/dev/null

FILTERED_COUNT="$(browser_eval "String(document.querySelectorAll('.alert-row').length)")"
[[ "$FILTERED_COUNT" == "8" ]] || {
  echo "expected 8 alert rows after medium+ filtering, got ${FILTERED_COUNT}" >&2
  exit 1
}

ONLY_MEDIUM_AND_HIGH="$(browser_eval "String(Array.from(document.querySelectorAll('.alert-row')).every((row) => ['medium', 'high'].includes(row.dataset.severity)))")"
[[ "$ONLY_MEDIUM_AND_HIGH" == "true" ]] || {
  echo "severity-filter left a non-medium/high alert row visible" >&2
  exit 1
}
