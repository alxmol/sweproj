#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/alexm/mini-edr"
BINARY="${ROOT}/target/debug/examples/launch_smoke"
SESSION="mini-edr-tui-deep-$$"

cleanup() {
  tuistory close -s "${SESSION}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if ! grep -Fq "${needle}" <<<"${haystack}"; then
    printf 'expected snapshot to contain %q\n%s\n' "${needle}" "${haystack}" >&2
    exit 1
  fi
}

repeat_char() {
  local char="$1"
  local count="$2"
  python3 - "$char" "$count" <<'PY'
import sys

char = sys.argv[1]
count = int(sys.argv[2])
print(char * count, end="")
PY
}

cd "${ROOT}"
cargo build --quiet -p mini-edr-tui --example launch_smoke

tuistory launch "${BINARY}" \
  -s "${SESSION}" \
  --cwd "${ROOT}" \
  --cols 100 \
  --rows 28 \
  --env "MINI_EDR_TUI_SCENARIO=deep_tree" \
  --env "MINI_EDR_TUI_AUTOQUIT_MS=60000" \
  >/dev/null

sleep 1
top_snapshot="$(tuistory snapshot -s "${SESSION}" --trim)"
assert_contains "${top_snapshot}" "node-0000"

tuistory type -s "${SESSION}" "$(repeat_char j 1500)" >/dev/null
tuistory wait-idle -s "${SESSION}" --timeout 3000 >/dev/null
bottom_snapshot="$(tuistory snapshot -s "${SESSION}" --trim)"
assert_contains "${bottom_snapshot}" "node-1199"

tuistory type -s "${SESSION}" "$(repeat_char k 1500)" >/dev/null
tuistory wait-idle -s "${SESSION}" --timeout 3000 >/dev/null
reset_snapshot="$(tuistory snapshot -s "${SESSION}" --trim)"
assert_contains "${reset_snapshot}" "node-0000"

printf 'deep_tree.sh passed\n'
