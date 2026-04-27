#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/mini-edr-web-tree.XXXXXX")}"
MODEL_PATH="${MINI_EDR_MODEL_PATH:-$ROOT_DIR/training/output/model.onnx}"
PORT="${PORT:?PORT must be set before sourcing dashboard_tree_lib.sh}"
SESSION="${SESSION:?SESSION must be set before sourcing dashboard_tree_lib.sh}"
SOCKET_PATH="${SOCKET_PATH:-$WORK_DIR/api.sock}"
CONFIG_PATH="${CONFIG_PATH:-$WORK_DIR/config.toml}"
DAEMON_LOG="${DAEMON_LOG:-$WORK_DIR/daemon.log}"
DAEMON_PID=""

cleanup_dashboard_tree_test() {
  agent-browser --session "$SESSION" close >/dev/null 2>&1 || true
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR"
}

start_dashboard_daemon() {
  if ss -tln | rg -q "127\\.0\\.0\\.1:${PORT}\\b"; then
    echo "refusing to start dashboard tree test because 127.0.0.1:${PORT} is already in use" >&2
    exit 1
  fi

  mkdir -p "$WORK_DIR/state"
  cat >"$CONFIG_PATH" <<EOF
alert_threshold = 0.7
web_port = ${PORT}
model_path = "${MODEL_PATH}"
log_file_path = "alerts.jsonl"
state_dir = "${WORK_DIR}/state"
EOF

  MINI_EDR_API_SOCKET="$SOCKET_PATH" \
    "$ROOT_DIR/target/debug/mini-edr-daemon" --config "$CONFIG_PATH" >"$DAEMON_LOG" 2>&1 &
  DAEMON_PID=$!

  for _ in $(seq 1 100); do
    if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
      return 0
    fi

    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
      cat "$DAEMON_LOG" >&2
      echo "mini-edr-daemon exited before the dashboard became ready" >&2
      exit 1
    fi

    sleep 0.1
  done

  cat "$DAEMON_LOG" >&2
  echo "dashboard did not become ready on port ${PORT}" >&2
  exit 1
}

post_process_tree_snapshot() {
  local snapshot_path="$1"
  dashboard_seed_post "/internal/dashboard/process-tree" "$snapshot_path"
}

post_alert_snapshot() {
  local snapshot_path="$1"
  dashboard_seed_post "/internal/dashboard/alerts" "$snapshot_path"
}

emit_alert_snapshot() {
  local snapshot_path="$1"
  dashboard_seed_post "/internal/dashboard/alerts/emit" "$snapshot_path"
}

dashboard_origin() {
  printf 'http://127.0.0.1:%s\n' "$PORT"
}

dashboard_seed_post() {
  local path="$1"
  local snapshot_path="$2"
  local token
  token="$(fetch_csrf_token)"
  [[ -n "$token" ]] || {
    echo "failed to retrieve the dashboard CSRF token" >&2
    exit 1
  }

  curl -fsS \
    -H "content-type: application/json" \
    -H "Origin: $(dashboard_origin)" \
    -H "x-csrf-token: ${token}" \
    --data @"$snapshot_path" \
    "http://127.0.0.1:${PORT}${path}" >/dev/null
}

fetch_csrf_token() {
  curl -fsS "http://127.0.0.1:${PORT}/api/settings/csrf" | jq -r '.token'
}

open_dashboard() {
  agent-browser --session "$SESSION" open "http://127.0.0.1:${PORT}/" >/dev/null
  agent-browser --session "$SESSION" wait "#process-tree" >/dev/null
  agent-browser --session "$SESSION" errors --clear >/dev/null || true
}

browser_text() {
  local selector="$1"
  agent-browser --session "$SESSION" get text "$selector"
}

browser_eval() {
  local script="$1"
  agent-browser --session "$SESSION" eval "$script" | python3 -c '
import json
import sys

data = sys.stdin.read().strip()
if not data:
    print("")
    raise SystemExit(0)

try:
    value = json.loads(data)
except json.JSONDecodeError:
    print(data)
else:
    if isinstance(value, bool):
        print("true" if value else "false")
    else:
        print(value)
'
}

assert_browser_text_contains() {
  local selector="$1"
  local expected="$2"
  local actual
  actual="$(browser_text "$selector")"
  if [[ "$actual" != *"$expected"* ]]; then
    echo "expected selector ${selector} to contain: ${expected}" >&2
    echo "actual text: ${actual}" >&2
    exit 1
  fi
}

assert_no_browser_errors() {
  local errors
  errors="$(agent-browser --session "$SESSION" errors || true)"
  if [[ -n "${errors//[[:space:]]/}" ]]; then
    echo "browser console/page errors were reported:" >&2
    echo "$errors" >&2
    exit 1
  fi
}
