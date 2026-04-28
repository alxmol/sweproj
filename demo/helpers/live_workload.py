#!/usr/bin/env python3
"""Host-safe live workloads for the Mini-EDR demo.

The demo needs real syscalls that exercise the live sensor path without
touching anything outside the repo and `/tmp`. These subcommands generate the
benign sentinel, short-lived fork burst, suspicious-but-safe alert workload,
and small performance connect storm used by `demo/run_demo.sh`.
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any


def write_json(path: str, payload: dict[str, Any]) -> None:
    """Persist one JSON document with stable formatting."""

    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def start_loopback_listener(payload_path: str) -> tuple[socket.socket, threading.Thread, int]:
    """Create one localhost listener and return the server, thread, and port."""

    server = socket.create_server(("127.0.0.1", 0), backlog=1)
    server.settimeout(5.0)
    listener_port = server.getsockname()[1]
    thread = threading.Thread(
        target=listener_thread,
        args=(server, payload_path),
        daemon=True,
    )
    thread.start()
    return server, thread, listener_port


def run_benign_sentinel(args: argparse.Namespace) -> int:
    """Write the sentinel PID and keep one safe process-tree row warm."""

    pid_value = int(Path("/proc/self").resolve().name)
    Path(args.pid_file).write_text(f"{pid_value}\n", encoding="utf-8")

    payload_path = str(Path(args.summary_file).with_suffix(".listener.bin"))
    server, thread, listener_port = start_loopback_listener(payload_path)
    try:
        write_json(
            args.summary_file,
            {
                "listener_port": listener_port,
                "pid": pid_value,
            },
        )
        with socket.create_connection(("127.0.0.1", listener_port), timeout=2.0) as client:
            client.sendall(b"benign-sentinel\n")

        deadline = time.time() + args.sleep_seconds
        while time.time() < deadline:
            Path(args.marker_path).read_bytes()[:1]
            time.sleep(0.01)
    finally:
        server.close()
        thread.join(timeout=5.0)
    return 0


def spawn_short_lived_children(child_count: int) -> list[int]:
    """Spawn child_count `/bin/true` processes and return their PIDs."""

    child_pids: list[int] = []
    processes: list[subprocess.Popen[bytes]] = []
    for _ in range(child_count):
        process = subprocess.Popen(["/bin/true"])
        child_pids.append(process.pid)
        processes.append(process)
        time.sleep(0.05)
    for process in processes:
        process.wait(timeout=5.0)
    return child_pids


def run_short_lived_burst(args: argparse.Namespace) -> int:
    """Spawn a parent process that immediately creates and reaps short-lived children."""

    pid_value = int(Path("/proc/self").resolve().name)
    payload_path = str(Path(args.summary_file).with_suffix(".listener.bin"))
    server, thread, listener_port = start_loopback_listener(payload_path)
    with socket.create_connection(("127.0.0.1", listener_port), timeout=2.0) as client:
        client.sendall(b"short-lived-burst\n")
    for _ in range(1024):
        Path(args.marker_path).read_bytes()[:1]
    child_pids = spawn_short_lived_children(args.child_count)
    time.sleep(args.linger_seconds)
    server.close()
    thread.join(timeout=5.0)
    payload = {
        "parent_pid": pid_value,
        "child_pids": child_pids,
        "listener_port": listener_port,
        "marker_path": args.marker_path,
    }
    write_json(args.summary_file, payload)
    return 0


def listener_thread(server: socket.socket, payload_path: str) -> None:
    """Accept one loopback connection and persist the received transcript."""

    connection, _address = server.accept()
    with connection:
        received = connection.recv(4096)
        Path(payload_path).write_bytes(received)


def run_suspicious_workload(args: argparse.Namespace) -> int:
    """Perform repeated reads, short-lived forks, and one loopback connect."""

    pid_text = f"{Path('/proc/self').resolve().name}\n"
    Path(args.pid_file).write_text(pid_text, encoding="utf-8")

    with socket.create_server(("127.0.0.1", 0), backlog=1) as server:
        server.settimeout(5.0)
        listener_port = server.getsockname()[1]
        listener_payload = str(Path(args.summary_file).with_suffix(".listener.bin"))
        thread = threading.Thread(
            target=listener_thread,
            args=(server, listener_payload),
            daemon=True,
        )
        thread.start()
        write_json(
            args.summary_file,
            {
                "pid": int(pid_text.strip()),
                "listener_port": listener_port,
                "marker_path": args.marker_path,
                "read_count": args.read_count,
                "read_path": args.read_path,
                "child_pids": [],
            },
        )

        if args.marker_path:
            for _ in range(1024):
                Path(args.marker_path).read_bytes()[:1]

        for _ in range(args.read_count):
            Path(args.read_path).read_bytes()[:1]
            time.sleep(0.03)

        child_pids = spawn_short_lived_children(args.child_count)

        with socket.create_connection(("127.0.0.1", listener_port), timeout=2.0) as client:
            client.sendall(b"whoami\nid\nexit\n")

        time.sleep(args.linger_seconds)
        thread.join(timeout=5.0)

    payload = {
        "pid": int(pid_text.strip()),
        "listener_port": listener_port,
        "read_count": args.read_count,
        "read_path": args.read_path,
        "child_pids": child_pids,
    }
    write_json(args.summary_file, payload)
    return 0


def worker_connect_loop(host: str, port: int, deadline: float, counter: list[int]) -> None:
    """Issue best-effort `connect(2)` calls until the deadline elapses."""

    completed = 0
    while time.time() < deadline:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(0.05)
        try:
            client.connect_ex((host, port))
        finally:
            client.close()
        completed += 1
    counter.append(completed)


def run_connect_storm(args: argparse.Namespace) -> int:
    """Drive a small threaded loopback connect storm for the perf snapshot."""

    deadline = time.time() + args.duration_seconds
    counts: list[int] = []
    threads = [
        threading.Thread(
            target=worker_connect_loop,
            args=(args.host, args.port, deadline, counts),
            daemon=True,
        )
        for _ in range(args.thread_count)
    ]
    started_at = time.time()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = max(time.time() - started_at, 0.001)
    attempts = sum(counts)
    payload = {
        "attempted_connections_total": attempts,
        "duration_seconds": args.duration_seconds,
        "elapsed_seconds": elapsed,
        "host": args.host,
        "observed_connections_per_second": attempts / elapsed,
        "port": args.port,
        "thread_count": args.thread_count,
    }
    write_json(args.summary_file, payload)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI parser used by the bash demo runner."""

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    benign = subparsers.add_parser("benign-sentinel", help="run a long-lived benign process")
    benign.add_argument("--pid-file", required=True)
    benign.add_argument("--summary-file", required=True)
    benign.add_argument("--sleep-seconds", type=float, default=30.0)
    benign.add_argument("--marker-path", required=True)
    benign.set_defaults(func=run_benign_sentinel)

    burst = subparsers.add_parser("short-lived-burst", help="spawn short-lived children")
    burst.add_argument("--summary-file", required=True)
    burst.add_argument("--marker-path", required=True)
    burst.add_argument("--child-count", type=int, default=4)
    burst.add_argument("--linger-seconds", type=float, default=3.0)
    burst.set_defaults(func=run_short_lived_burst)

    suspicious = subparsers.add_parser(
        "suspicious-alert",
        help="perform the host-safe workload used for live alert correlation",
    )
    suspicious.add_argument("--pid-file", required=True)
    suspicious.add_argument("--summary-file", required=True)
    suspicious.add_argument("--marker-path")
    suspicious.add_argument("--read-path", default="/etc/passwd")
    suspicious.add_argument("--read-count", type=int, default=12)
    suspicious.add_argument("--child-count", type=int, default=3)
    suspicious.add_argument("--linger-seconds", type=float, default=3.0)
    suspicious.set_defaults(func=run_suspicious_workload)

    storm = subparsers.add_parser("connect-storm", help="run the perf snapshot workload")
    storm.add_argument("--summary-file", required=True)
    storm.add_argument("--host", default="127.0.0.1")
    storm.add_argument("--port", type=int, default=9)
    storm.add_argument("--duration-seconds", type=float, default=10.0)
    storm.add_argument("--thread-count", type=int, default=4)
    storm.set_defaults(func=run_connect_storm)

    return parser


def main() -> int:
    """Run the requested workload subcommand."""

    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
