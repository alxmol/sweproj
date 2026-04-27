#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/alexm/mini-edr"
BINARY="${ROOT}/target/debug/examples/launch_smoke"
SESSION="mini-edr-tui-control-$$"

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

cd "${ROOT}"
cargo build --quiet -p mini-edr-tui --example launch_smoke

tuistory launch "${BINARY}" \
  -s "${SESSION}" \
  --cwd "${ROOT}" \
  --cols 100 \
  --rows 28 \
  --env "MINI_EDR_TUI_SCENARIO=control_chars" \
  --env "MINI_EDR_TUI_AUTOQUIT_MS=10000" \
  >/dev/null

sleep 1
snapshot="$(tuistory snapshot -s "${SESSION}" --trim)"

assert_contains "${snapshot}" "benign-before"
assert_contains "${snapshot}" "benign-after"
assert_contains "${snapshot}" "pwn"

if grep -q $'\033\[' <<<"${snapshot}"; then
  printf 'expected sanitized snapshot without raw escape sequences\n%s\n' "${snapshot}" >&2
  exit 1
fi

printf 'control_chars.sh passed\n'
