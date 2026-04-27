#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/alexm/mini-edr"
BINARY="${ROOT}/target/debug/examples/launch_smoke"
SESSION="mini-edr-tui-color-$$"
ANSI_LOG="/tmp/mini-edr-tui-color-$$.ansi"

cleanup() {
  tuistory close -s "${SESSION}" >/dev/null 2>&1 || true
  rm -f "${ANSI_LOG}"
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

rm -f "${ANSI_LOG}"
tuistory launch "script -q -f ${ANSI_LOG} -c 'env MINI_EDR_TUI_SCENARIO=color_partition MINI_EDR_TUI_AUTOQUIT_MS=10000 ${BINARY}'" \
  -s "${SESSION}" \
  --cwd "${ROOT}" \
  --cols 100 \
  --rows 28 \
  >/dev/null

sleep 1

snapshot="$(tuistory snapshot -s "${SESSION}" --trim)"
assert_contains "${snapshot}" "pid  1001"
assert_contains "${snapshot}" "pid  1007"

python3 - "${ANSI_LOG}" <<'PY'
import re
import sys
from pathlib import Path

ansi_log = Path(sys.argv[1]).read_text("utf-8", errors="replace")

screen: dict[tuple[int, int], tuple[str, int | None]] = {}
row = 1
col = 1
fg: int | None = None
i = 0

while i < len(ansi_log):
    if ansi_log[i] != "\x1b":
        screen[(row, col)] = (ansi_log[i], fg)
        col += 1
        i += 1
        continue

    if i + 1 >= len(ansi_log) or ansi_log[i + 1] != "[":
        i += 1
        continue

    j = i + 2
    while j < len(ansi_log) and not ansi_log[j].isalpha():
        j += 1
    if j >= len(ansi_log):
        break

    command = ansi_log[j]
    params = ansi_log[i + 2 : j]
    i = j + 1

    if command == "H":
        row_text, col_text = (params.split(";", 1) + ["1"])[:2]
        row = int(row_text or "1")
        col = int(col_text or "1")
    elif command == "m":
        for raw_value in params.split(";"):
            if not raw_value:
                raw_value = "0"
            value = int(raw_value)
            if value in {0, 39}:
                fg = None
            elif value == 38:
                continue
            elif value == 5:
                continue
            elif value in {1, 2, 3}:
                fg = value
    elif command == "J":
        screen.clear()
        row = 1
        col = 1

rows: dict[int, list[tuple[int, str, int | None]]] = {}
for (r, c), (character, color) in screen.items():
    rows.setdefault(r, []).append((c, character, color))

rendered_rows: list[tuple[str, list[int | None]]] = []
for r in sorted(rows):
    ordered = sorted(rows[r])
    text = "".join(character for _, character, _ in ordered)
    colors = [color for _, _, color in ordered]
    rendered_rows.append((text, colors))

expected = {
    "pid  1001": 2,
    "pid  1002": 3,
    "pid  1003": 1,
    "pid  1004": 2,
    "pid  1005": 3,
    "pid  1006": 3,
    "pid  1007": 1,
}

for needle, expected_color in expected.items():
    for text, colors in rendered_rows:
        start = text.find(needle)
        if start == -1:
            continue
        observed = {color for color in colors[start : start + len(needle)]}
        if observed != {expected_color}:
            raise SystemExit(
                f"{needle} expected ANSI color {expected_color}, observed {sorted(observed)} in row: {text}"
            )
        break
    else:
        raise SystemExit(f"missing row for {needle!r}")
PY

printf 'color_partition.sh passed\n'
