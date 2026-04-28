#!/usr/bin/env python3
"""Hold a cgroup near a target memory.current ratio without exceeding the cap.

The helper allocates and frees 1 MiB bytearrays to keep the enclosing cgroup's
memory.current value inside a narrow band around the requested target ratio. It
records one JSON sample per poll so the shell harness can prove the near-cap
window lasted long enough and that no `oom_kill` events were observed.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--memory-current-path", required=True)
    parser.add_argument("--memory-max-path", required=True)
    parser.add_argument("--memory-events-path", required=True)
    parser.add_argument("--target-ratio", required=True, type=float)
    parser.add_argument("--hold-seconds", required=True, type=int)
    parser.add_argument("--sample-interval-seconds", type=float, default=1.0)
    parser.add_argument("--chunk-mebibytes", type=int, default=1)
    parser.add_argument("--samples-path", required=True)
    parser.add_argument("--summary-path", required=True)
    return parser.parse_args()


def read_bytes(path: Path) -> int:
    return int(path.read_text(encoding="utf-8").strip())


def read_oom_kill_total(path: Path) -> int:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        key, value = line.split(maxsplit=1)
        values[key] = int(value)
    return values.get("oom_kill", 0)


def main() -> int:
    args = parse_args()
    if not (0.0 < args.target_ratio < 1.0):
        raise SystemExit("--target-ratio must be in the open interval (0, 1)")
    if args.hold_seconds <= 0:
        raise SystemExit("--hold-seconds must be greater than zero")

    memory_current_path = Path(args.memory_current_path)
    memory_max_path = Path(args.memory_max_path)
    memory_events_path = Path(args.memory_events_path)
    samples_path = Path(args.samples_path)
    summary_path = Path(args.summary_path)
    memory_max_raw = memory_max_path.read_text(encoding="utf-8").strip()
    if memory_max_raw == "max":
        raise SystemExit("memory.max is unlimited; the cgroup near-cap helper requires a finite limit")
    memory_max_bytes = int(memory_max_raw)
    target_bytes = int(memory_max_bytes * args.target_ratio)
    chunk_bytes = args.chunk_mebibytes * 1024 * 1024
    upper_bound_bytes = min(memory_max_bytes - chunk_bytes, target_bytes + 4 * chunk_bytes)
    start_oom_kill_total = read_oom_kill_total(memory_events_path)
    started_at = time.monotonic()
    blocks: list[bytearray] = []
    samples = []
    streak_seconds = 0
    max_streak_seconds = 0
    current_streak_start_seconds = None
    longest_streak_start_seconds = None
    longest_streak_end_seconds = None
    peak_memory_current_bytes = 0

    def allocate_chunk() -> None:
        block = bytearray(chunk_bytes)
        for offset in range(0, len(block), 4096):
            block[offset] = 1
        blocks.append(block)

    while True:
        elapsed_seconds = int(time.monotonic() - started_at)
        if elapsed_seconds >= args.hold_seconds:
            break
        current_bytes = read_bytes(memory_current_path)
        while current_bytes < target_bytes:
            allocate_chunk()
            current_bytes = read_bytes(memory_current_path)
        while current_bytes > upper_bound_bytes and blocks:
            blocks.pop()
            current_bytes = read_bytes(memory_current_path)

        peak_memory_current_bytes = max(peak_memory_current_bytes, current_bytes)
        above_target = current_bytes >= target_bytes
        if above_target:
            if current_streak_start_seconds is None:
                current_streak_start_seconds = elapsed_seconds
            streak_seconds += 1
            if streak_seconds > max_streak_seconds:
                max_streak_seconds = streak_seconds
                longest_streak_start_seconds = current_streak_start_seconds
                longest_streak_end_seconds = elapsed_seconds
        else:
            streak_seconds = 0
            current_streak_start_seconds = None

        samples.append(
            {
                "elapsed_seconds": elapsed_seconds,
                "memory_current_bytes": current_bytes,
                "above_target": above_target,
                "oom_kill_total": read_oom_kill_total(memory_events_path),
            }
        )
        time.sleep(args.sample_interval_seconds)

    samples_path.write_text(
        "\n".join(json.dumps(sample, sort_keys=True) for sample in samples) + "\n",
        encoding="utf-8",
    )
    end_oom_kill_total = read_oom_kill_total(memory_events_path)
    summary = {
        "memory_max_bytes": memory_max_bytes,
        "target_ratio": args.target_ratio,
        "target_bytes": target_bytes,
        "upper_bound_bytes": upper_bound_bytes,
        "chunk_bytes": chunk_bytes,
        "hold_seconds": args.hold_seconds,
        "sample_interval_seconds": args.sample_interval_seconds,
        "sample_count": len(samples),
        "peak_memory_current_bytes": peak_memory_current_bytes,
        "max_contiguous_seconds_at_or_above_target": max_streak_seconds,
        "longest_streak_start_seconds": longest_streak_start_seconds,
        "longest_streak_end_seconds": longest_streak_end_seconds,
        "oom_kill_delta": end_oom_kill_total - start_oom_kill_total,
        "samples_path": str(samples_path),
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
