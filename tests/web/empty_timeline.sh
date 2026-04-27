#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8081}"
SESSION="${SESSION:-mini-edr-empty-timeline-$$}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon

SNAPSHOT_PATH="$WORK_DIR/empty-alerts.json"
printf '{"alerts":[]}\n' >"$SNAPSHOT_PATH"
post_alert_snapshot "$SNAPSHOT_PATH"

open_dashboard
assert_browser_text_contains "[data-panel='alert-timeline']" "No threats detected"

VISIBLE_COUNT="$(browser_eval "String(document.querySelectorAll('.alert-row').length)")"
[[ "$VISIBLE_COUNT" == "0" ]] || {
  echo "expected zero alert rows for the empty timeline, got ${VISIBLE_COUNT}" >&2
  exit 1
}

assert_no_browser_errors
