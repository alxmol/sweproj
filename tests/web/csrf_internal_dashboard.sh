#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8081}"
SESSION="${SESSION:-mini-edr-internal-csrf-$$}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon

SNAPSHOT_PATH="$WORK_DIR/internal-dashboard-alert.json"
python3 - "$SNAPSHOT_PATH" <<'PY'
import json
import sys

destination = sys.argv[1]
with open(destination, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "alerts": [
                {
                    "alert_id": 51_001,
                    "timestamp": "2026-04-27T10:00:00Z",
                    "pid": 51_001,
                    "process_name": "csrf-internal-alert",
                    "binary_path": "/tmp/csrf-internal-alert",
                    "ancestry_chain": [
                        {
                            "pid": 1,
                            "process_name": "systemd",
                            "binary_path": "/usr/lib/systemd/systemd",
                        }
                    ],
                    "threat_score": 0.96,
                    "top_features": [
                        {"feature_name": "entropy", "contribution_score": 0.96}
                    ],
                    "summary": "csrf internal dashboard alert",
                }
            ]
        },
        handle,
    )
PY

open_dashboard
assert_browser_text_contains "[data-panel='alert-timeline']" "No threats detected"

INITIAL_COUNT="$(browser_eval "String(document.querySelectorAll('.alert-row').length)")"
[[ "$INITIAL_COUNT" == "0" ]] || {
  echo "expected the dashboard timeline to start empty, got ${INITIAL_COUNT} rows" >&2
  exit 1
}

FORGED_STATUS="$(curl -sS -o "$WORK_DIR/forged.json" -w '%{http_code}' \
  -H 'content-type: application/json' \
  -H 'Origin: http://evil.example' \
  --data @"$SNAPSHOT_PATH" \
  "http://127.0.0.1:${PORT}/internal/dashboard/alerts/emit")"
[[ "$FORGED_STATUS" == "403" || "$FORGED_STATUS" == "400" ]] || {
  echo "expected forged dashboard emit to fail with 403/400, got ${FORGED_STATUS}" >&2
  exit 1
}

FORGED_ERROR="$(jq -r '.error' "$WORK_DIR/forged.json")"
[[ "$FORGED_ERROR" == "cross-origin requests are forbidden" || "$FORGED_ERROR" == "missing CSRF token" ]] || {
  echo "unexpected forged dashboard emit error payload: ${FORGED_ERROR}" >&2
  exit 1
}

UNCHANGED_COUNT="$(browser_eval "String(document.querySelectorAll('.alert-row').length)")"
[[ "$UNCHANGED_COUNT" == "0" ]] || {
  echo "forged dashboard emit should not add visible alert rows, got ${UNCHANGED_COUNT}" >&2
  exit 1
}

SERVER_COUNT_AFTER_FORGED="$(curl -fsS "http://127.0.0.1:${PORT}/api/dashboard/alerts" | jq '.alerts | length')"
[[ "$SERVER_COUNT_AFTER_FORGED" == "0" ]] || {
  echo "forged dashboard emit should leave server-side alert state unchanged, got ${SERVER_COUNT_AFTER_FORGED} alerts" >&2
  exit 1
}

TOKEN="$(fetch_csrf_token)"
[[ -n "$TOKEN" ]] || {
  echo "failed to retrieve the dashboard CSRF token" >&2
  exit 1
}

SUCCESS_STATUS="$(curl -sS -o "$WORK_DIR/success.json" -w '%{http_code}' \
  -H 'content-type: application/json' \
  -H "Origin: $(dashboard_origin)" \
  -H "x-csrf-token: ${TOKEN}" \
  --data @"$SNAPSHOT_PATH" \
  "http://127.0.0.1:${PORT}/internal/dashboard/alerts/emit")"
[[ "$SUCCESS_STATUS" == 2* ]] || {
  echo "expected same-origin dashboard emit with CSRF token to succeed, got ${SUCCESS_STATUS}" >&2
  exit 1
}

agent-browser --session "$SESSION" wait ".alert-row" >/dev/null
assert_browser_text_contains ".alert-row" "csrf internal dashboard alert"

UPDATED_COUNT="$(browser_eval "String(document.querySelectorAll('.alert-row').length)")"
[[ "$UPDATED_COUNT" == "1" ]] || {
  echo "expected one visible alert row after the valid dashboard emit, got ${UPDATED_COUNT}" >&2
  exit 1
}

SERVER_COUNT_AFTER_SUCCESS="$(curl -fsS "http://127.0.0.1:${PORT}/api/dashboard/alerts" | jq '.alerts | length')"
[[ "$SERVER_COUNT_AFTER_SUCCESS" == "1" ]] || {
  echo "expected server-side alert state to contain one alert after the valid emit, got ${SERVER_COUNT_AFTER_SUCCESS}" >&2
  exit 1
}

assert_no_browser_errors
