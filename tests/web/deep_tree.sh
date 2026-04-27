#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8084}"
SESSION="mini-edr-deep-tree-$$"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon

SNAPSHOT_PATH="$WORK_DIR/deep-tree.json"
python3 - <<'PY' >"$SNAPSHOT_PATH"
import json

processes = []
for depth in range(1200):
    pid = 5000 + depth
    ancestry = [
        {
            "pid": 1,
            "process_name": "systemd",
            "binary_path": "/usr/lib/systemd/systemd",
        },
        {
            "pid": pid,
            "process_name": f"deep-node-{depth}",
            "binary_path": f"/opt/deep/node-{depth}",
        },
    ]
    processes.append(
        {
            "pid": pid,
            "process_name": f"deep-node-{depth}",
            "binary_path": f"/opt/deep/node-{depth}",
            "threat_score": 0.9 if depth == 1199 else 0.1,
            "depth": depth,
            "detail": {
                "ancestry_chain": ancestry,
                "feature_vector": [{"label": "depth", "value": str(depth)}],
                "recent_syscalls": ["clone ×1", "execve ×1"],
                "threat_score": 0.9 if depth == 1199 else 0.1,
                "top_features": [
                    {"feature_name": "depth", "contribution_score": float(depth) / 1200.0}
                ],
            },
            "exited": False,
        }
    )

print(json.dumps({"processes": processes}))
PY

post_process_tree_snapshot "$SNAPSHOT_PATH"
open_dashboard
agent-browser --session "$SESSION" wait ".process-row[data-pid='6199']" --timeout 10000 >/dev/null
agent-browser --session "$SESSION" scrollintoview ".process-row[data-pid='6199']" >/dev/null
agent-browser --session "$SESSION" click ".process-row[data-pid='6199']" >/dev/null

VISIBLE_LEAF="$(browser_eval "String(Boolean(document.querySelector('.process-row[data-pid=\"6199\"]')))")"
[[ "$VISIBLE_LEAF" == "true" ]] || {
  echo "expected deepest process row to be present after scrolling" >&2
  exit 1
}

assert_browser_text_contains "#process-detail-summary" "deep-node-1199"
assert_no_browser_errors
