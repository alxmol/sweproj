#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8081}"
SESSION="${SESSION:-mini-edr-csrf-$$}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon

TOKEN="$(fetch_csrf_token)"
[[ -n "$TOKEN" ]] || {
  echo "failed to retrieve the dashboard CSRF token" >&2
  exit 1
}

FOREIGN_STATUS="$(curl -sS -o "$WORK_DIR/foreign.json" -w '%{http_code}' \
  -H 'content-type: application/json' \
  -H 'Origin: http://evil.example' \
  -d '{"alert_threshold":0.6}' \
  "http://127.0.0.1:${PORT}/settings/threshold")"
[[ "$FOREIGN_STATUS" == "403" ]] || {
  echo "expected a 403 for the cross-origin threshold update, got ${FOREIGN_STATUS}" >&2
  exit 1
}

CURRENT_THRESHOLD="$(curl -fsS "http://127.0.0.1:${PORT}/health" | jq -r '.alert_threshold')"
[[ "$CURRENT_THRESHOLD" == "0.7" ]] || {
  echo "foreign request unexpectedly changed the threshold to ${CURRENT_THRESHOLD}" >&2
  exit 1
}

SUCCESS_STATUS="$(curl -sS -o "$WORK_DIR/success.json" -w '%{http_code}' \
  -H 'content-type: application/json' \
  -H "Origin: http://127.0.0.1:${PORT}" \
  -H "x-csrf-token: ${TOKEN}" \
  -d '{"alert_threshold":0.6}' \
  "http://127.0.0.1:${PORT}/settings/threshold")"
[[ "$SUCCESS_STATUS" == "200" ]] || {
  echo "expected a 200 for the same-origin threshold update, got ${SUCCESS_STATUS}" >&2
  exit 1
}

UPDATED_THRESHOLD="$(curl -fsS "http://127.0.0.1:${PORT}/health" | jq -r '.alert_threshold')"
[[ "$UPDATED_THRESHOLD" == "0.6" ]] || {
  echo "expected the threshold to update to 0.6, got ${UPDATED_THRESHOLD}" >&2
  exit 1
}
