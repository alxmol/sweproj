#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/alexm/mini-edr"
BINARY="${ROOT}/target/debug/examples/launch_smoke"
SESSION="mini-edr-tui-latency-$$"

cleanup() {
  tuistory close -s "${SESSION}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "${ROOT}"
cargo build --quiet -p mini-edr-tui --example launch_smoke

tuistory launch "${BINARY}" \
  -s "${SESSION}" \
  --cwd "${ROOT}" \
  --cols 80 \
  --rows 20 \
  --env "MINI_EDR_TUI_SCENARIO=detail_view" \
  --env "MINI_EDR_TUI_AUTOQUIT_MS=600000" \
  >/dev/null

sleep 1.2
tuistory press -s "${SESSION}" down >/dev/null
tuistory wait-idle -s "${SESSION}" --timeout 2000 >/dev/null

python3 - "${SESSION}" <<'PY'
import json
import math
import statistics
import subprocess
import sys

session = sys.argv[1]
sequence = ["down", "enter", "enter", "up", "tab", "tab", "down", "up"] * 125
latencies = []

for key in sequence:
    baseline = subprocess.check_output(
        ["tuistory", "snapshot", "-s", session, "--trim", "--immediate"],
        text=True,
    )
    frames = json.loads(
        subprocess.check_output(
            [
                "tuistory",
                "capture-frames",
                "-s",
                session,
                "--count",
                "12",
                "--interval",
                "8",
                key,
            ],
            text=True,
        )
    )

    changed_frame = next((index for index, frame in enumerate(frames) if frame != baseline), None)
    if changed_frame is None:
        raise SystemExit(f"key {key!r} did not change the rendered frame within 96 ms")

    latencies.append((changed_frame + 1) * 8)

sorted_latencies = sorted(latencies)
p50 = statistics.median(sorted_latencies)
p99_index = max(0, math.ceil(len(sorted_latencies) * 0.99) - 1)
p99 = sorted_latencies[p99_index]

if p50 >= 25:
    raise SystemExit(f"expected p50 < 25 ms, got {p50:.1f} ms")
if p99 >= 100:
    raise SystemExit(f"expected p99 < 100 ms, got {p99:.1f} ms")
if max(sorted_latencies) > 250:
    raise SystemExit(f"expected max <= 250 ms, got {max(sorted_latencies):.1f} ms")

print(
    json.dumps(
        {
            "samples": len(sorted_latencies),
            "p50_ms": p50,
            "p99_ms": p99,
            "max_ms": max(sorted_latencies),
        }
    )
)
PY

printf 'keyboard_latency.sh passed\n'
