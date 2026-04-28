#!/usr/bin/env python3
"""Spawn short-lived live-connect helpers at a controlled wall-clock cadence.

Each spawned helper executes exactly one `connect(2)` call and writes its own
PID/start timestamp JSON file. The availability harnesses can then match alerts
back to those concrete PIDs instead of relying on host-global counters.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper-bin", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int)
    parser.add_argument("--port-base", type=int)
    parser.add_argument("--events-per-second", required=True, type=float)
    parser.add_argument("--duration-seconds", required=True, type=float)
    parser.add_argument("--linger-ms", required=True, type=int)
    parser.add_argument("--metadata-dir", required=True)
    parser.add_argument("--report-path", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.port is None and args.port_base is None:
        raise SystemExit("either --port or --port-base is required")
    if args.port is not None and args.port_base is not None:
        raise SystemExit("pass either --port or --port-base, not both")
    if args.events_per_second <= 0:
        raise SystemExit("--events-per-second must be greater than zero")
    if args.duration_seconds <= 0:
        raise SystemExit("--duration-seconds must be greater than zero")
    if args.linger_ms < 0:
        raise SystemExit("--linger-ms cannot be negative")

    metadata_dir = Path(args.metadata_dir)
    metadata_dir.mkdir(parents=True, exist_ok=True)
    report_path = Path(args.report_path)
    interval_seconds = 1.0 / args.events_per_second
    planned_launch_count = int(args.duration_seconds * args.events_per_second)
    started_at = time.monotonic()
    deadline = started_at + args.duration_seconds
    launched = []
    failed_launches = []
    launch_index = 0

    while True:
        scheduled_at = started_at + launch_index * interval_seconds
        if scheduled_at >= deadline:
            break
        sleep_seconds = scheduled_at - time.monotonic()
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)

        metadata_path = metadata_dir / f"{launch_index:06}.json"
        assigned_port = (
            args.port_base + launch_index
            if args.port_base is not None
            else args.port
        )
        command = [
            args.helper_bin,
            args.host,
            str(assigned_port),
            str(args.linger_ms),
            str(metadata_path),
        ]
        try:
            process = subprocess.Popen(command)
        except OSError as error:
            failed_launches.append(
                {
                    "index": launch_index,
                    "command": command,
                    "error": str(error),
                }
            )
        else:
            launched.append(
                {
                    "index": launch_index,
                    "assigned_port": assigned_port,
                    "metadata_path": str(metadata_path),
                    "process": process,
                }
            )
        launch_index += 1

    nonzero_exit_codes = []
    for launched_process in launched:
        return_code = launched_process["process"].wait()
        if return_code != 0:
            nonzero_exit_codes.append(
                {
                    "index": launched_process["index"],
                    "assigned_port": launched_process["assigned_port"],
                    "return_code": return_code,
                }
            )

    elapsed_seconds = time.monotonic() - started_at
    report = {
        "helper_bin": args.helper_bin,
        "host": args.host,
        "port": args.port,
        "port_base": args.port_base,
        "events_per_second": args.events_per_second,
        "duration_seconds": args.duration_seconds,
        "linger_ms": args.linger_ms,
        "planned_launch_count": planned_launch_count,
        "launched_count": len(launched),
        "launches": [
            {
                "index": launched_process["index"],
                "assigned_port": launched_process["assigned_port"],
                "metadata_path": launched_process["metadata_path"],
            }
            for launched_process in launched
        ],
        "failed_launches": failed_launches,
        "nonzero_exit_codes": nonzero_exit_codes,
        "elapsed_seconds": elapsed_seconds,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    if failed_launches or nonzero_exit_codes:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
