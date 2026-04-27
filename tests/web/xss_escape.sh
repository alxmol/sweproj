#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8083}"
SESSION="mini-edr-xss-escape-$$"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon
open_dashboard

browser_eval "window.__pwned = false; window.alert = () => { window.__pwned = true; };"

SNAPSHOT_PATH="$WORK_DIR/xss.json"
python3 - <<'PY' >"$SNAPSHOT_PATH"
import json

payload = {
    "processes": [
        {
            "pid": 31337,
            "process_name": "<script>alert(1)</script>\u0007\u001b[2J",
            "binary_path": "/tmp/<script>alert(1)</script>",
            "threat_score": 0.95,
            "depth": 1,
            "detail": {
                "ancestry_chain": [
                    {
                        "pid": 31337,
                        "process_name": "<script>alert(1)</script>\u0007\u001b[2J",
                        "binary_path": "/tmp/<script>alert(1)</script>",
                    }
                ],
                "feature_vector": [{"label": "entropy", "value": "0.950"}],
                "recent_syscalls": ["execve ×1"],
                "threat_score": 0.95,
                "top_features": [
                    {"feature_name": "entropy", "contribution_score": 0.55}
                ],
            },
            "exited": False,
        },
        {
            "pid": 31338,
            "process_name": "safe-neighbor",
            "binary_path": "/usr/bin/safe-neighbor",
            "threat_score": 0.10,
            "depth": 1,
            "detail": {
                "ancestry_chain": [
                    {
                        "pid": 31338,
                        "process_name": "safe-neighbor",
                        "binary_path": "/usr/bin/safe-neighbor",
                    }
                ],
                "feature_vector": [{"label": "entropy", "value": "0.100"}],
                "recent_syscalls": ["openat ×1"],
                "threat_score": 0.10,
                "top_features": [
                    {"feature_name": "entropy", "contribution_score": 0.05}
                ],
            },
            "exited": False,
        },
    ]
}

print(json.dumps(payload))
PY

post_process_tree_snapshot "$SNAPSHOT_PATH"
agent-browser --session "$SESSION" wait ".process-row[data-pid='31337']" >/dev/null

ROW_NAME="$(browser_text ".process-row[data-pid='31337'] .process-row__name")"
[[ "$ROW_NAME" == *"<script>alert(1)</script>"* ]] || {
  echo "expected escaped row text to preserve literal script tag text, got: ${ROW_NAME}" >&2
  exit 1
}

HAS_SCRIPT_NODE="$(browser_eval "String(Boolean(document.querySelector('.process-row[data-pid=\"31337\"] script')))")"
[[ "$HAS_SCRIPT_NODE" == "false" ]] || {
  echo "expected hostile process row to render as text, not a script element" >&2
  exit 1
}

PWNED="$(browser_eval "String(Boolean(window.__pwned))")"
[[ "$PWNED" == "false" ]] || {
  echo "hostile process name executed unexpected alert handler" >&2
  exit 1
}

agent-browser --session "$SESSION" click ".process-row[data-pid='31338']" >/dev/null
assert_browser_text_contains "#process-detail-summary" "safe-neighbor"
assert_no_browser_errors
