#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8081}"
SESSION="${SESSION:-mini-edr-degraded-badge-$$}"
export MINI_EDR_MODEL_PATH="${MINI_EDR_MODEL_PATH:-${TMPDIR:-/tmp}/mini-edr-missing-model-$$.onnx}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon
open_dashboard

agent-browser --session "$SESSION" wait --text "Daemon: Degraded" --timeout 5000 >/dev/null

BADGE_VISIBLE="$(browser_eval "String(!document.getElementById('degraded-badge').hidden)")"
[[ "$BADGE_VISIBLE" == "true" ]] || {
  echo "expected the degraded warning badge to be visible" >&2
  exit 1
}

assert_browser_text_contains "#daemon-status-badge" "Daemon: Degraded"
assert_browser_text_contains "#degraded-badge" "degraded mode"
assert_no_browser_errors
