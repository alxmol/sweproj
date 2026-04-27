#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8081}"
SESSION="mini-edr-tree-drilldown-$$"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon

SNAPSHOT_PATH="$WORK_DIR/tree-drilldown.json"
cat >"$SNAPSHOT_PATH" <<'EOF'
{
  "processes": [
    {
      "pid": 1,
      "process_name": "systemd",
      "binary_path": "/usr/lib/systemd/systemd",
      "threat_score": 0.10,
      "depth": 0,
      "detail": {
        "ancestry_chain": [
          {
            "pid": 1,
            "process_name": "systemd",
            "binary_path": "/usr/lib/systemd/systemd"
          }
        ],
        "feature_vector": [
          { "label": "entropy", "value": "0.100" }
        ],
        "recent_syscalls": ["execve ×1"],
        "threat_score": 0.10,
        "top_features": [
          { "feature_name": "entropy", "contribution_score": 0.10 }
        ]
      },
      "exited": false
    },
    {
      "pid": 4242,
      "process_name": "suspicious-shell",
      "binary_path": "/usr/bin/suspicious-shell",
      "threat_score": 0.91,
      "depth": 2,
      "detail": {
        "ancestry_chain": [
          {
            "pid": 1,
            "process_name": "systemd",
            "binary_path": "/usr/lib/systemd/systemd"
          },
          {
            "pid": 111,
            "process_name": "bash",
            "binary_path": "/usr/bin/bash"
          },
          {
            "pid": 4242,
            "process_name": "suspicious-shell",
            "binary_path": "/usr/bin/suspicious-shell"
          }
        ],
        "feature_vector": [
          { "label": "entropy", "value": "0.910" },
          { "label": "unique_files", "value": "4" }
        ],
        "recent_syscalls": ["execve ×1", "openat ×4", "connect ×2"],
        "threat_score": 0.91,
        "top_features": [
          { "feature_name": "entropy", "contribution_score": 0.42 },
          { "feature_name": "connect_count", "contribution_score": 0.31 }
        ]
      },
      "exited": false
    }
  ]
}
EOF

post_process_tree_snapshot "$SNAPSHOT_PATH"
open_dashboard
agent-browser --session "$SESSION" wait ".process-row[data-pid='4242']" >/dev/null
agent-browser --session "$SESSION" click ".process-row[data-pid='4242']" >/dev/null
agent-browser --session "$SESSION" wait ".process-detail" >/dev/null

SECTION_COUNT="$(browser_eval "String(document.querySelectorAll('.process-detail .process-detail-section').length)")"
[[ "$SECTION_COUNT" == "5" ]] || {
  echo "expected 5 detail sections, got ${SECTION_COUNT}" >&2
  exit 1
}

assert_browser_text_contains ".process-detail" "Ancestry"
assert_browser_text_contains ".process-detail" "Feature Vector"
assert_browser_text_contains ".process-detail" "Recent Syscalls"
assert_browser_text_contains ".process-detail" "Threat Score"
assert_browser_text_contains ".process-detail" "Top Features"
assert_browser_text_contains ".process-detail" "suspicious-shell"
assert_no_browser_errors
