#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8082}"
SESSION="mini-edr-utf8-render-$$"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon

SNAPSHOT_PATH="$WORK_DIR/utf8.json"
cat >"$SNAPSHOT_PATH" <<'EOF'
{
  "processes": [
    {
      "pid": 9001,
      "process_name": "мойбин-🔥",
      "binary_path": "/opt/demo/мойбин-🔥",
      "threat_score": 0.50,
      "depth": 3,
      "detail": {
        "ancestry_chain": [
          {
            "pid": 1,
            "process_name": "systemd",
            "binary_path": "/usr/lib/systemd/systemd"
          },
          {
            "pid": 9001,
            "process_name": "мойбин-🔥",
            "binary_path": "/opt/demo/мойбин-🔥"
          }
        ],
        "feature_vector": [
          { "label": "entropy", "value": "0.500" }
        ],
        "recent_syscalls": ["execve ×1"],
        "threat_score": 0.50,
        "top_features": [
          { "feature_name": "entropy", "contribution_score": 0.25 }
        ]
      },
      "exited": false
    }
  ]
}
EOF

post_process_tree_snapshot "$SNAPSHOT_PATH"
open_dashboard
agent-browser --session "$SESSION" wait ".process-row[data-pid='9001']" >/dev/null

ROW_NAME="$(browser_text ".process-row[data-pid='9001'] .process-row__name")"
[[ "$ROW_NAME" == "мойбин-🔥" ]] || {
  echo "expected UTF-8 process name to round-trip intact, got: ${ROW_NAME}" >&2
  exit 1
}

agent-browser --session "$SESSION" click ".process-row[data-pid='9001']" >/dev/null
assert_browser_text_contains "#process-detail-summary" "мойбин-🔥"
assert_no_browser_errors
