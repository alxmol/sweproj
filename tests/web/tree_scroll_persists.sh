#!/usr/bin/env bash
set -euo pipefail

PORT="${MINI_EDR_WEB_PORT:-8086}"
SESSION="mini-edr-tree-scroll-persist-$$"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dashboard_tree_lib.sh"
trap cleanup_dashboard_tree_test EXIT

start_dashboard_daemon

INITIAL_SNAPSHOT_PATH="$WORK_DIR/tree-scroll-initial.json"
UPDATED_SNAPSHOT_PATH="$WORK_DIR/tree-scroll-updated.json"
TARGET_PID=5750

python3 - "$INITIAL_SNAPSHOT_PATH" "$UPDATED_SNAPSHOT_PATH" "$TARGET_PID" <<'PY'
import json
import sys

initial_path, updated_path, target_pid_raw = sys.argv[1:]
target_pid = int(target_pid_raw)


def build_snapshot(updated_score: float | None) -> dict:
    processes = []
    for depth in range(1500):
        pid = 5000 + depth
        score = 0.12
        if pid == target_pid:
            score = updated_score if updated_score is not None else 0.41
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
                "threat_score": score,
                "depth": depth,
                "detail": {
                    "ancestry_chain": ancestry,
                    "feature_vector": [{"label": "depth", "value": str(depth)}],
                    "recent_syscalls": ["clone ×1", "execve ×1"],
                    "threat_score": score,
                    "top_features": [
                        {"feature_name": "depth", "contribution_score": float(depth) / 1500.0}
                    ],
                },
                "exited": False,
            }
        )
    return {"processes": processes}


with open(initial_path, "w", encoding="utf-8") as handle:
    json.dump(build_snapshot(None), handle)

with open(updated_path, "w", encoding="utf-8") as handle:
    json.dump(build_snapshot(0.95), handle)
PY

post_process_tree_snapshot "$INITIAL_SNAPSHOT_PATH"
open_dashboard

agent-browser --session "$SESSION" wait --fn "document.querySelectorAll('.process-row').length === 1500 && Boolean(window.__miniEdrDebug.processTree.lastRender?.completed)" --timeout 15000 >/dev/null

browser_eval "(() => { const tree = document.getElementById('process-tree'); tree.scrollTop = 1000; return Math.round(tree.scrollTop); })()"
agent-browser --session "$SESSION" wait 200 >/dev/null

SELECTED_ROW_READY="$(browser_eval "(() => { const row = document.querySelector('.process-row[data-pid=\"${TARGET_PID}\"]'); window.__selectedRowBefore = row; row?.click(); return String(Boolean(row) && row.classList.contains('is-selected')); })()")"
[[ "$SELECTED_ROW_READY" == "true" ]] || {
  echo "expected target row ${TARGET_PID} to become selected before refresh" >&2
  exit 1
}

post_process_tree_snapshot "$UPDATED_SNAPSHOT_PATH"
agent-browser --session "$SESSION" wait --fn "document.querySelector('.process-row[data-pid=\"${TARGET_PID}\"] .process-row__score')?.textContent?.trim() === '0.95' && Boolean(window.__miniEdrDebug.processTree.lastRender?.completed)" --timeout 10000 >/dev/null

SCROLL_TOP_AFTER_REFRESH="$(browser_eval "String(Math.round(document.getElementById('process-tree').scrollTop))")"
if (( SCROLL_TOP_AFTER_REFRESH < 990 || SCROLL_TOP_AFTER_REFRESH > 1010 )); then
  echo "expected scrollTop to stay within ±10px of 1000, got ${SCROLL_TOP_AFTER_REFRESH}" >&2
  exit 1
fi

SELECTED_PERSISTS="$(browser_eval "String(document.querySelector('.process-row[data-pid=\"${TARGET_PID}\"]')?.classList.contains('is-selected') ?? false)")"
[[ "$SELECTED_PERSISTS" == "true" ]] || {
  echo "expected selected-row class to persist across refresh" >&2
  exit 1
}

ROW_WAS_REUSED="$(browser_eval "String(window.__selectedRowBefore === document.querySelector('.process-row[data-pid=\"${TARGET_PID}\"]'))")"
[[ "$ROW_WAS_REUSED" == "true" ]] || {
  echo "expected keyed diff to preserve the original DOM node for pid ${TARGET_PID}" >&2
  exit 1
}

MAX_CHUNK_DURATION_MS="$(browser_eval "(() => { const durations = window.__miniEdrDebug.processTree.lastRender?.chunkDurationsMs ?? []; return durations.length ? Math.max(...durations).toFixed(2) : '-1'; })()")"
python3 - "$MAX_CHUNK_DURATION_MS" <<'PY'
import sys

max_duration_ms = float(sys.argv[1])
if max_duration_ms >= 16.0:
    raise SystemExit(f"expected each render chunk to stay below 16ms, got {max_duration_ms:.2f}ms")
PY

UPDATED_SCORE="$(browser_eval "document.querySelector('.process-row[data-pid=\"${TARGET_PID}\"] .process-row__score')?.textContent?.trim() ?? ''")"
[[ "$UPDATED_SCORE" == "0.95" ]] || {
  echo "expected updated threat score text to render 0.95, got ${UPDATED_SCORE}" >&2
  exit 1
}

assert_no_browser_errors
