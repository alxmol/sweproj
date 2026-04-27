#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/alexm/mini-edr"
BINARY="${ROOT}/target/debug/examples/launch_smoke"
SESSION="mini-edr-tui-detail-$$"

cleanup() {
  tuistory close -s "${SESSION}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

capture_snapshot() {
  tuistory snapshot -s "${SESSION}" --trim
}

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
  --cols 120 \
  --rows 30 \
  --env "MINI_EDR_TUI_SCENARIO=detail_view" \
  --env "MINI_EDR_TUI_AUTOQUIT_MS=12000" \
  >/dev/null

sleep 1.2
for key in down down enter; do
  tuistory press -s "${SESSION}" "${key}" >/dev/null
  tuistory wait-idle -s "${SESSION}" --timeout 2000 >/dev/null
done
snapshot="$(capture_snapshot)"

assert_contains "${snapshot}" "Ancestry Chain"
assert_contains "${snapshot}" "Feature Vector"
assert_contains "${snapshot}" "Recent Syscalls"
assert_contains "${snapshot}" "Threat Score"
assert_contains "${snapshot}" "Top Features"
assert_contains "${snapshot}" "python3-worker"
assert_contains "${snapshot}" "/usr/bin/python3"
assert_contains "${snapshot}" "entropy"
assert_contains "${snapshot}" "execve /tmp/payload"

printf 'detail_view.sh passed\n'
