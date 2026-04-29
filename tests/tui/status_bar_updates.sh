#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/directory/mini-edr"
BINARY="${ROOT}/target/debug/examples/launch_smoke"
SESSION="mini-edr-tui-status-$$"

cleanup() {
  tuistory close -s "${SESSION}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

capture_snapshot() {
  tuistory snapshot -s "${SESSION}" --trim
}

cd "${ROOT}"
cargo build --quiet -p mini-edr-tui --example launch_smoke

tuistory launch "${BINARY}" \
  -s "${SESSION}" \
  --cwd "${ROOT}" \
  --cols 100 \
  --rows 24 \
  --env "MINI_EDR_TUI_SCENARIO=status_updates" \
  --env "MINI_EDR_TUI_AUTOQUIT_MS=7000" \
  >/dev/null

sleep 1
snapshot_one="$(capture_snapshot)"
sleep 1.1
snapshot_two="$(capture_snapshot)"
sleep 1.1
snapshot_three="$(capture_snapshot)"

python3 - "${snapshot_one}" "${snapshot_two}" "${snapshot_three}" <<'PY'
import re
import sys

def parse_metrics(snapshot: str) -> dict[str, str]:
    metrics = {}
    for label in ("Events/s", "Ring Buffer", "Avg Inference", "Uptime"):
        match = re.search(rf"{re.escape(label)}:\s*([^│\n]+)", snapshot)
        if not match:
            raise SystemExit(f"missing {label} line in snapshot:\n{snapshot}")
        metrics[label] = match.group(1).strip()
    return metrics

snapshots = [parse_metrics(snapshot) for snapshot in sys.argv[1:]]
eps_values = []
ring_values = []
latency_values = []
uptime_values = []

for metrics in snapshots:
    eps = float(metrics["Events/s"])
    if not 950 <= eps <= 1050:
        raise SystemExit(f"events/s value {eps} outside 1000±5%")
    eps_values.append(metrics["Events/s"])
    ring_values.append(metrics["Ring Buffer"])
    latency_values.append(metrics["Avg Inference"])
    uptime_values.append(metrics["Uptime"])

if len(set(eps_values)) != len(eps_values):
    raise SystemExit(f"expected every events/s snapshot to update, got {eps_values}")
if len(set(ring_values)) != len(ring_values):
    raise SystemExit(f"expected ring buffer utilization to update, got {ring_values}")
if len(set(latency_values)) != len(latency_values):
    raise SystemExit(f"expected average inference latency to update, got {latency_values}")
if len(set(uptime_values)) != len(uptime_values):
    raise SystemExit(f"expected uptime to update, got {uptime_values}")
PY

printf 'status_bar_updates.sh passed\n'
