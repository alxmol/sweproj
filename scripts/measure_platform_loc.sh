#!/usr/bin/env bash
# Measure the daemon's host-dependent code footprint for NFR-PO04 / TC-59.
#
# The contract defines host-dependent code as either:
#   1. code isolated under the daemon's dedicated `platform` module, or
#   2. explicit `cfg(target_os = "linux")` / `cfg(target_arch = "...")` gates
#      elsewhere in daemon sources.
# Keeping this measurement scripted prevents the ratio from silently drifting as
# future features add Linux-specific logic.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DAEMON_SRC_DIR="${REPO_ROOT}/crates/mini-edr-daemon/src"

python3 - "$DAEMON_SRC_DIR" "${1:-}" <<'PY'
from __future__ import annotations

import pathlib
import re
import sys

daemon_src = pathlib.Path(sys.argv[1])
mode = sys.argv[2]

cfg_pattern = re.compile(r"cfg\s*\(\s*(?:all\(|any\()?(?:not\()?(?:target_os|target_arch)")


def count_effective_loc(path: pathlib.Path) -> int:
    total = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        total += 1
    return total


daemon_files = sorted(daemon_src.rglob("*.rs"))
if not daemon_files:
    raise SystemExit("error: no daemon Rust sources found")

total_loc = sum(count_effective_loc(path) for path in daemon_files)
platform_files = []
for path in daemon_files:
    relative = path.relative_to(daemon_src)
    if relative == pathlib.Path("platform.rs") or relative.parts[:1] == ("platform",):
        platform_files.append(path)

platform_loc = sum(count_effective_loc(path) for path in platform_files)
cfg_gate_files: dict[pathlib.Path, int] = {}
for path in daemon_files:
    if path in platform_files:
        continue
    matches = sum(
        1
        for line in path.read_text(encoding="utf-8").splitlines()
        if cfg_pattern.search(line)
    )
    if matches:
        cfg_gate_files[path] = matches
        platform_loc += matches

if total_loc == 0:
    raise SystemExit("error: daemon source contains zero effective LoC")

ratio = platform_loc / total_loc
status = "pass" if ratio <= 0.10 else "fail"

if mode == "--list":
    for path in platform_files:
        print(f"{path.relative_to(daemon_src.parent.parent)}:{count_effective_loc(path)}")
    for path, cfg_lines in sorted(cfg_gate_files.items()):
        print(f"{path.relative_to(daemon_src.parent.parent)}:{cfg_lines} cfg-gate-lines")
    raise SystemExit(0)

if mode not in ("", "--list"):
    raise SystemExit(f"error: unsupported argument `{mode}` (expected none or --list)")

print(f"platform_loc={platform_loc}")
print(f"total_loc={total_loc}")
print(f"ratio={ratio:.4f}")
print(f"status={status}")
print("gate=max_ratio<=0.10")

if status != "pass":
    raise SystemExit(1)
PY
