#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/alexm/mini-edr"
BINARY="${ROOT}/target/debug/examples/launch_smoke"
SESSION="mini-edr-tui-timeline-$$"

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

collect_ids() {
  grep -oE '#[0-9]{4}' <<<"$1" | tr '\n' ' '
}

cd "${ROOT}"
cargo build --quiet -p mini-edr-tui --example launch_smoke

tuistory launch "${BINARY}" \
  -s "${SESSION}" \
  --cwd "${ROOT}" \
  --cols 100 \
  --rows 20 \
  --env "MINI_EDR_TUI_SCENARIO=timeline_scroll" \
  --env "MINI_EDR_TUI_AUTOQUIT_MS=15000" \
  >/dev/null

sleep 1
initial_snapshot="$(capture_snapshot)"
assert_contains "${initial_snapshot}" "#0020"
assert_contains "${initial_snapshot}" "#0011"

python3 - "${initial_snapshot}" <<'PY'
import re
import sys

ids = [int(match.group(1)) for match in re.finditer(r"#(\d{4})", sys.argv[1])]
if len(ids) < 10:
    raise SystemExit(f"expected at least 10 visible alerts, got {ids}")
if ids != sorted(ids, reverse=True):
    raise SystemExit(f"expected reverse-chronological order, got {ids}")
PY

tuistory press -s "${SESSION}" tab >/dev/null

all_ids="$(collect_ids "${initial_snapshot}")"
for _ in 1 2 3 4; do
  tuistory type -s "${SESSION}" "jjjjj" >/dev/null
  tuistory wait-idle -s "${SESSION}" --timeout 2000 >/dev/null
  snapshot="$(capture_snapshot)"
  all_ids="${all_ids} $(collect_ids "${snapshot}")"
done

python3 - "${all_ids}" <<'PY'
import re
import sys

ids = sorted({int(match.group(1)) for match in re.finditer(r"#(\d{4})", sys.argv[1])})
expected = list(range(1, 21))
if ids != expected:
    raise SystemExit(f"expected to observe all 20 alert ids, got {ids}")
PY

tuistory type -s "${SESSION}" "kkkkkkkkkkkkkkkkkkkk" >/dev/null
tuistory wait-idle -s "${SESSION}" --timeout 2000 >/dev/null
top_again="$(capture_snapshot)"
assert_contains "${top_again}" "#0020"

printf 'timeline_scroll.sh passed\n'
