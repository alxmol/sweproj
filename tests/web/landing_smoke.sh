#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mini-edr-web-smoke.XXXXXX")"
PORT="${MINI_EDR_WEB_PORT:-8080}"
SOCKET_PATH="${MINI_EDR_API_SOCKET:-$WORK_DIR/api.sock}"
MODEL_PATH="${MINI_EDR_MODEL_PATH:-$ROOT_DIR/training/output/model.onnx}"
CONFIG_PATH="$WORK_DIR/config.toml"
DAEMON_LOG="$WORK_DIR/daemon.log"
DAEMON_PID=""

cleanup() {
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR"
}

trap cleanup EXIT

if ss -tln | rg -q "127\\.0\\.0\\.1:${PORT}\\b"; then
  echo "refusing to start landing_smoke.sh because 127.0.0.1:${PORT} is already in use" >&2
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
    break
  fi

  if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    cat "$DAEMON_LOG" >&2
    echo "mini-edr-daemon exited before the dashboard became ready" >&2
    exit 1
  fi

  sleep 0.1
done

curl -fsS "http://127.0.0.1:${PORT}/" >"$WORK_DIR/index.html"
curl -fsS "http://127.0.0.1:${PORT}/health" >"$WORK_DIR/health.json"

grep -q "<title>Mini-EDR</title>" "$WORK_DIR/index.html"
grep -q "Mini-EDR" "$WORK_DIR/index.html"
grep -q 'aria-label="Settings"' "$WORK_DIR/index.html"
grep -q 'id="process-tree"' "$WORK_DIR/index.html"
jq -e '.state and .model_hash and .web_port == '"${PORT}"'' "$WORK_DIR/health.json" >/dev/null
ss -tln | rg "127\\.0\\.0\\.1:${PORT}\\b"
