#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8085}"
SESSION="mini-edr-tree-optional-score-$$"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon

SNAPSHOT_PATH="$WORK_DIR/tree-optional-score.json"
cat >"$SNAPSHOT_PATH" <<'EOF'
{
  "processes": [
    {
      "pid": 9001,
      "process_name": "scored-low",
      "binary_path": "/usr/bin/scored-low",
      "threat_score": 0.25,
      "depth": 0,
      "detail": {
        "ancestry_chain": [
          {
            "pid": 9001,
            "process_name": "scored-low",
            "binary_path": "/usr/bin/scored-low"
          }
        ],
        "feature_vector": [{ "label": "entropy", "value": "0.250" }],
        "recent_syscalls": ["execve ×1"],
        "threat_score": 0.25,
        "top_features": [
          { "feature_name": "entropy", "contribution_score": 0.25 }
        ]
      },
      "exited": false
    },
    {
      "pid": 9002,
      "process_name": "scored-high",
      "binary_path": "/usr/bin/scored-high",
      "threat_score": 0.85,
      "depth": 1,
      "detail": {
        "ancestry_chain": [
          {
            "pid": 9002,
            "process_name": "scored-high",
            "binary_path": "/usr/bin/scored-high"
          }
        ],
        "feature_vector": [{ "label": "entropy", "value": "0.850" }],
        "recent_syscalls": ["execve ×1", "connect ×1"],
        "threat_score": 0.85,
        "top_features": [
          { "feature_name": "entropy", "contribution_score": 0.85 }
        ]
      },
      "exited": false
    },
    {
      "pid": 9003,
      "process_name": "unscored-child",
      "binary_path": "/usr/bin/unscored-child",
      "threat_score": null,
      "depth": 2,
      "detail": {
        "ancestry_chain": [
          {
            "pid": 9003,
            "process_name": "unscored-child",
            "binary_path": "/usr/bin/unscored-child"
          }
        ],
        "feature_vector": [{ "label": "entropy", "value": "pending" }],
        "recent_syscalls": ["clone ×1"],
        "threat_score": null,
        "top_features": []
      },
      "exited": false
    }
  ]
}
EOF

post_process_tree_snapshot "$SNAPSHOT_PATH"
open_dashboard
agent-browser --session "$SESSION" wait ".process-row[data-pid='9003']" >/dev/null
agent-browser --session "$SESSION" click ".process-row[data-pid='9003']" >/dev/null
agent-browser --session "$SESSION" wait ".process-detail" >/dev/null
agent-browser --session "$SESSION" screenshot --annotate "$WORK_DIR/tree-optional-score.png" >/dev/null

UNSCORED_BAND="$(browser_eval "document.querySelector(\".process-row[data-pid='9003']\")?.dataset.threatBand ?? ''")"
[[ "$UNSCORED_BAND" == "unscored" ]] || {
  echo "expected unscored row to expose data-threat-band='unscored', got ${UNSCORED_BAND}" >&2
  exit 1
}

UNSCORED_SCORE_TEXT="$(browser_eval "document.querySelector(\".process-row[data-pid='9003'] .process-row__score\")?.textContent?.trim() ?? ''")"
[[ "$UNSCORED_SCORE_TEXT" == "unscored" ]] || {
  echo "expected unscored row label to render 'unscored', got ${UNSCORED_SCORE_TEXT}" >&2
  exit 1
}

DETAIL_SCORE_TEXT="$(browser_text "#detail-threat-score")"
[[ "$DETAIL_SCORE_TEXT" == *"Score: —"* ]] || {
  echo "expected detail score list to render an em dash for the null score" >&2
  echo "actual detail text: ${DETAIL_SCORE_TEXT}" >&2
  exit 1
}

UNSCORED_COLOR="$(browser_eval "(() => { const row = document.querySelector(\".process-row[data-pid='9003']\"); return row ? getComputedStyle(row).color : ''; })()")"
HIGH_COLOR="$(browser_eval "(() => { const row = document.querySelector(\".process-row[data-pid='9002']\"); return row ? getComputedStyle(row).color : ''; })()")"
NEUTRAL_COLOR="$(browser_eval "(() => { const probe = document.createElement('span'); probe.style.color = 'var(--score-grey)'; document.body.appendChild(probe); const color = getComputedStyle(probe).color; probe.remove(); return color; })()")"

[[ "$UNSCORED_COLOR" == "$NEUTRAL_COLOR" ]] || {
  echo "expected unscored row color ${UNSCORED_COLOR} to match neutral token ${NEUTRAL_COLOR}" >&2
  exit 1
}

[[ "$UNSCORED_COLOR" != "$HIGH_COLOR" ]] || {
  echo "expected unscored row color to differ from high-severity red (${HIGH_COLOR})" >&2
  exit 1
}

ERRORS="$(agent-browser --session "$SESSION" errors || true)"
[[ "$ERRORS" != *".toFixed"* ]] || {
  echo "unexpected .toFixed error surfaced in the browser:" >&2
  echo "$ERRORS" >&2
  exit 1
}

assert_no_browser_errors
