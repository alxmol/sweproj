#!/usr/bin/env python3
"""Drive concurrent /internal/predict load through a mid-stream SIGHUP swap.

This helper centralizes the VAL-DETECT-018 load profile so the shell harness
and the Rust integration regression test both exercise the same throughput
measurement and cutover analysis logic.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import shutil
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for the shared SIGHUP load probe."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--payload-path", type=Path, required=True)
    parser.add_argument("--thread-count", type=int, default=32)
    parser.add_argument("--target-rps", type=float, required=True)
    parser.add_argument("--max-requests", type=int, default=0)
    parser.add_argument("--request-timeout-seconds", type=float, default=10.0)
    parser.add_argument("--swap-delay-ms", type=float, default=50.0)
    parser.add_argument("--swap-copy-from", type=Path)
    parser.add_argument("--swap-copy-to", type=Path)
    parser.add_argument("--sighup-pid", type=int)
    parser.add_argument("--responses-path", type=Path)
    return parser.parse_args()


def load_payloads(payload_path: Path, max_requests: int) -> list[bytes]:
    """Load JSONL feature vectors as raw request bodies.

    Reusing the fixture lines verbatim avoids spending CPU re-serializing each
    payload and keeps the measured rate focused on the daemon's HTTP/inference
    path rather than client-side JSON formatting overhead.
    """

    payloads = [
        line.strip().encode("utf-8")
        for line in payload_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not payloads:
        raise SystemExit(f"payload corpus {payload_path} contained no request bodies")
    if max_requests > 0:
        payloads = payloads[:max_requests]
    return payloads


def request_json(
    connection: http.client.HTTPConnection,
    path: str,
    body: bytes | None,
) -> dict[str, Any]:
    """Send one JSON request over a persistent HTTP/1.1 connection."""

    headers = {"content-type": "application/json"} if body is not None else {}
    connection.request("POST" if body is not None else "GET", path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    if response.status != 200:
        raise RuntimeError(
            f"{path} returned HTTP {response.status}: {raw[:200].decode('utf-8', 'replace')}"
        )
    return json.loads(raw)


def fetch_health(port: int, timeout_seconds: float) -> dict[str, Any]:
    """Fetch the daemon's health snapshot after the load phase finishes."""

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout_seconds)
    try:
        return request_json(connection, "/api/health", None)
    finally:
        connection.close()


def maybe_write_responses(path: Path | None, rows: list[dict[str, Any]]) -> None:
    """Persist per-response records when a caller wants debugging artifacts."""

    if path is None:
        return
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, separators=(",", ":")))
            handle.write("\n")


def main() -> int:
    """Run the shared load probe and print a JSON summary on success."""

    args = parse_args()
    payloads = load_payloads(args.payload_path, args.max_requests)
    if args.sighup_pid is not None and (
        args.swap_copy_from is None or args.swap_copy_to is None
    ):
        raise SystemExit(
            "--swap-copy-from and --swap-copy-to are required when --sighup-pid is set"
        )

    start_event = threading.Event()
    first_request_event = threading.Event()
    result_lock = threading.Lock()
    responses: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    def worker(thread_id: int) -> None:
        """Drive one persistent client loop across the shared request corpus."""

        connection = http.client.HTTPConnection(
            "127.0.0.1",
            args.port,
            timeout=args.request_timeout_seconds,
        )
        local_responses: list[dict[str, Any]] = []
        local_errors: list[dict[str, Any]] = []
        start_event.wait()
        for request_id in range(thread_id, len(payloads), args.thread_count):
            # The main thread waits for at least one worker to begin before it
            # copies v2 over v1 and sends SIGHUP, which guarantees the swap
            # lands during the measured load window rather than before it.
            first_request_event.set()
            try:
                body = request_json(connection, "/internal/predict", payloads[request_id])
            except Exception as exc:  # noqa: BLE001 - fixture should record exact failures
                local_errors.append(
                    {
                        "thread_id": thread_id,
                        "request_id": request_id,
                        "error": repr(exc),
                    }
                )
                try:
                    connection.close()
                finally:
                    connection = http.client.HTTPConnection(
                        "127.0.0.1",
                        args.port,
                        timeout=args.request_timeout_seconds,
                    )
                continue

            body["thread_id"] = thread_id
            body["request_id"] = request_id
            local_responses.append(body)

        with result_lock:
            responses.extend(local_responses)
            errors.extend(local_errors)
        connection.close()

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(args.thread_count)]
    for thread in threads:
        thread.start()

    load_started_ns = time.time_ns()
    start_event.set()

    swap_requested_ns: int | None = None
    if args.sighup_pid is not None:
        if not first_request_event.wait(timeout=5):
            raise SystemExit("concurrent client loops never began issuing requests")
        time.sleep(args.swap_delay_ms / 1000.0)
        swap_requested_ns = time.time_ns()
        shutil.copyfile(args.swap_copy_from, args.swap_copy_to)
        os.kill(args.sighup_pid, signal.SIGHUP)

    for thread in threads:
        thread.join()
    load_finished_ns = time.time_ns()

    maybe_write_responses(args.responses_path, responses + errors)

    total_requests = len(payloads)
    elapsed_seconds = (load_finished_ns - load_started_ns) / 1_000_000_000.0
    if elapsed_seconds <= 0.0:
        raise SystemExit(
            f"measured a non-positive load interval: start={load_started_ns} stop={load_finished_ns}"
        )
    achieved_rps = total_requests / elapsed_seconds

    if errors:
        raise SystemExit(f"observed request failures: {errors[:3]}")
    if len(responses) != total_requests:
        raise SystemExit(
            f"expected {total_requests} responses, saw {len(responses)} successful responses"
        )

    health = fetch_health(args.port, args.request_timeout_seconds)
    if health.get("state") != "Running":
        raise SystemExit(f"daemon left Running during load probe: {health}")

    observed_hashes = sorted({row["model_hash"] for row in responses})
    if args.sighup_pid is not None:
        if swap_requested_ns is None:
            raise SystemExit("internal error: swap was requested but no swap timestamp was recorded")
        if not (load_started_ns < swap_requested_ns < load_finished_ns):
            raise SystemExit(
                "SIGHUP swap did not happen during the measured load phase: "
                f"load_start={load_started_ns} swap={swap_requested_ns} load_stop={load_finished_ns}"
            )
        final_hash = health["model_hash"]
        if final_hash not in observed_hashes:
            raise SystemExit(
                f"health endpoint converged to {final_hash}, but the load responses saw {observed_hashes}"
            )
        if len(observed_hashes) != 2:
            raise SystemExit(f"expected exactly v1 and v2 model hashes, saw {observed_hashes}")
        first_v2_emitted_ns = min(
            row["emitted_at_ns"] for row in responses if row["model_hash"] == final_hash
        )
        late_v1 = [
            row
            for row in responses
            if row["model_hash"] != final_hash
            and row["emitted_at_ns"] > first_v2_emitted_ns + 100_000_000
        ]
        if late_v1:
            raise SystemExit(
                "observed v1 responses after the 100 ms post-cutover window: "
                f"cutover={first_v2_emitted_ns} count={len(late_v1)} sample={late_v1[:3]}"
            )
    else:
        late_v1 = []
        first_v2_emitted_ns = None

    if achieved_rps < args.target_rps:
        raise SystemExit(
            "achieved request rate "
            f"{achieved_rps:.2f} req/s below {args.target_rps:.2f} req/s target "
            f"(elapsed={elapsed_seconds:.6f}s total_requests={total_requests})"
        )

    summary = {
        "thread_count": args.thread_count,
        "total_requests": total_requests,
        "load_started_ns": load_started_ns,
        "load_finished_ns": load_finished_ns,
        "swap_requested_ns": swap_requested_ns,
        "first_v2_emitted_ns": first_v2_emitted_ns,
        "elapsed_seconds": elapsed_seconds,
        "achieved_rps": achieved_rps,
        "observed_hashes": observed_hashes,
        "late_v1_after_swap": len(late_v1),
        "health": health,
    }
    print(json.dumps(summary, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
