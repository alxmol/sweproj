#!/usr/bin/env python3
"""Observe the Mini-EDR demo surfaces from shell-friendly subcommands.

This helper keeps the bash entrypoint small while preserving explicit, typed
JSON handling for the demo's health checks, process-tree lookups, alert-log
correlation, dashboard filtering, bpftool parsing, and performance summaries.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen


def read_json_from_url(url: str) -> Any:
    """Fetch and decode one JSON document from a localhost HTTP endpoint."""

    with urlopen(url, timeout=2.0) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_until(deadline: float, interval_seconds: float, predicate: callable) -> Any:
    """Poll a predicate until it returns a truthy value or the deadline passes."""

    while time.time() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(interval_seconds)
    raise TimeoutError("deadline elapsed before the requested condition became true")


def write_json(output_path: str | None, payload: Any) -> None:
    """Write formatted JSON to a file or stdout."""

    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if output_path:
        Path(output_path).write_text(serialized, encoding="utf-8")
    else:
        sys.stdout.write(serialized)


def find_free_port(start: int, end: int) -> int:
    """Return the first free localhost TCP port inside the inclusive range."""

    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            candidate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                candidate.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError(f"no free localhost port in {start}-{end}")


def load_json_file(path: str) -> Any:
    """Load one JSON document from disk."""

    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_alert_lines(path: str, start_line: int) -> list[dict[str, Any]]:
    """Load complete JSON alert lines from a log file after one-based start_line."""

    alert_path = Path(path)
    if not alert_path.exists():
        return []
    decoded: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        alert_path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if line_number <= start_line or not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            # Live writes can leave a trailing partial line while the daemon is
            # still flushing the file. Poll again instead of failing eagerly.
            continue
        payload["_line_number"] = line_number
        decoded.append(payload)
    return decoded


def read_rss_series(path: str) -> list[dict[str, Any]]:
    """Parse the JSON-lines RSS sample file emitted by run_demo.sh."""

    rss_path = Path(path)
    if not rss_path.exists():
        return []
    samples: list[dict[str, Any]] = []
    for line in rss_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        samples.append(json.loads(line))
    return samples


def health_cmd(args: argparse.Namespace) -> int:
    """Wait for `/api/health` to reach the requested lifecycle state."""

    deadline = time.time() + args.timeout
    url = f"http://127.0.0.1:{args.port}/api/health"

    def predicate() -> Any:
        try:
            payload = read_json_from_url(url)
        except (OSError, URLError, json.JSONDecodeError):
            return None
        if payload.get("state") == args.state:
            return payload
        return None

    payload = wait_until(deadline, 0.2, predicate)
    write_json(args.output, payload)
    return 0


def process_cmd(args: argparse.Namespace) -> int:
    """Wait for one process-tree row matching the requested filters."""

    deadline = time.time() + args.timeout
    url = f"http://127.0.0.1:{args.port}/api/processes"

    def predicate() -> Any:
        try:
            payload = read_json_from_url(url)
        except (OSError, URLError, json.JSONDecodeError):
            return None
        for process in payload.get("processes", []):
            if args.pid is not None and process.get("pid") != args.pid:
                continue
            if args.recent_syscall_substring:
                recent_syscalls = process.get("detail", {}).get("recent_syscalls", [])
                if not any(args.recent_syscall_substring in syscall for syscall in recent_syscalls):
                    continue
            if args.require_threat_score and process.get("threat_score") is None:
                continue
            if args.require_top_features and not process.get("detail", {}).get("top_features"):
                continue
            return process
        return None

    payload = wait_until(deadline, 0.2, predicate)
    write_json(args.output, payload)
    return 0


def events_cmd(args: argparse.Namespace) -> int:
    """Wait for a filtered `/api/events` view to contain enough matching rows."""

    deadline = time.time() + args.timeout
    url = f"http://127.0.0.1:{args.port}/api/events?limit={args.limit}"

    def predicate() -> Any:
        try:
            payload = read_json_from_url(url)
        except (OSError, URLError, json.JSONDecodeError):
            return None
        matches = []
        for event in payload:
            if args.pid is not None and event.get("pid") != args.pid:
                continue
            if args.syscall and event.get("syscall_type") != args.syscall:
                continue
            if args.filename and event.get("filename") != args.filename:
                continue
            if args.port_value is not None and event.get("port") != args.port_value:
                continue
            matches.append(event)
        if len(matches) >= args.minimum:
            return matches
        return None

    payload = wait_until(deadline, 0.2, predicate)
    write_json(args.output, payload)
    return 0


def alert_cmd(args: argparse.Namespace) -> int:
    """Wait for one alert-log record, optionally filtering by PID."""

    deadline = time.time() + args.timeout

    def predicate() -> Any:
        matches = [
            payload
            for payload in load_alert_lines(args.alerts_file, args.start_line)
            if args.pid is None or payload.get("pid") == args.pid
        ]
        return matches[-1] if matches else None

    payload = wait_until(deadline, 0.2, predicate)
    write_json(args.output, payload)
    return 0


def dashboard_cmd(args: argparse.Namespace) -> int:
    """Fetch dashboard alerts and optionally filter them by PID."""

    url = f"http://127.0.0.1:{args.port}/api/dashboard/alerts"
    payload = read_json_from_url(url)
    if args.pid is not None:
        payload = {
            "alerts": [
                alert for alert in payload.get("alerts", []) if alert.get("pid") == args.pid
            ]
        }
    write_json(args.output, payload)
    return 0


def log_cmd(args: argparse.Namespace) -> int:
    """Wait for one daemon log substring and emit the matching lines."""

    deadline = time.time() + args.timeout
    log_path = Path(args.log_path)

    def predicate() -> Any:
        if not log_path.exists():
            return None
        matches = [
            line
            for line in log_path.read_text(encoding="utf-8").splitlines()
            if args.substring in line
        ]
        return {"matches": matches} if matches else None

    payload = wait_until(deadline, 0.2, predicate)
    write_json(args.output, payload)
    return 0


def bpftool_cmd(args: argparse.Namespace) -> int:
    """Filter `bpftool prog list --json` output down to one daemon's probes."""

    payload = load_json_file(args.input)
    expected_names = {
        "sched_process_fork",
        "sched_process_exit",
        "sys_enter_execve",
        "sys_enter_openat",
        "sys_exit_openat",
        "sys_enter_connect",
        "sys_exit_connect",
        "sys_exit_clone",
    }
    matches = []
    for program in payload:
        pids = program.get("pids", []) or []
        if any(entry.get("pid") == args.daemon_pid for entry in pids):
            matches.append(program)
            continue
        if (
            program.get("type") == "tracepoint"
            and program.get("name") in expected_names
            and program.get("loaded_at", 0) >= args.loaded_after
        ):
            matches.append(program)
    write_json(args.output, matches)
    return 0


def perf_cmd(args: argparse.Namespace) -> int:
    """Summarize the demo perf snapshot from raw helper and daemon samples."""

    helper_report = load_json_file(args.helper_report)
    health_before = load_json_file(args.health_before)
    health_after = load_json_file(args.health_after)
    proc_before = load_json_file(args.proc_before)
    proc_after = load_json_file(args.proc_after)
    rss_samples = read_rss_series(args.rss_samples)

    ring_received_delta = (
        health_after["ring_events_received_total"] - health_before["ring_events_received_total"]
    )
    ring_dropped_delta = (
        health_after["ring_events_dropped_total"] - health_before["ring_events_dropped_total"]
    )
    total_ticks_delta = proc_after["total_ticks"] - proc_before["total_ticks"]
    daemon_ticks_delta = proc_after["daemon_ticks"] - proc_before["daemon_ticks"]
    cpu_percent_total = 0.0
    if total_ticks_delta > 0:
        cpu_percent_total = (daemon_ticks_delta / total_ticks_delta) * 100.0

    rss_values = [sample["rss_bytes"] for sample in rss_samples]
    rss_peak_bytes = max(rss_values) if rss_values else proc_before["rss_bytes"]
    summary = {
        "duration_seconds": helper_report["elapsed_seconds"],
        "generator_events_total": helper_report["attempted_connections_total"],
        "generator_events_per_second": helper_report["observed_connections_per_second"],
        "daemon_received_events_total": ring_received_delta,
        "daemon_received_events_per_second": ring_received_delta
        / max(helper_report["elapsed_seconds"], 0.001),
        "daemon_dropped_events_total": ring_dropped_delta,
        "daemon_cpu_percent_total": cpu_percent_total,
        "rss_start_mb": proc_before["rss_bytes"] / (1024 * 1024),
        "rss_peak_mb": rss_peak_bytes / (1024 * 1024),
        "rss_end_mb": proc_after["rss_bytes"] / (1024 * 1024),
        "state_before": health_before["state"],
        "state_after": health_after["state"],
    }
    write_json(args.output, summary)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI parser used by the shell demo entrypoint."""

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    free_port = subparsers.add_parser("find-free-port", help="find a free localhost port")
    free_port.add_argument("--start", type=int, default=8081)
    free_port.add_argument("--end", type=int, default=8099)
    free_port.set_defaults(func=lambda args: print(find_free_port(args.start, args.end)) or 0)

    health = subparsers.add_parser("wait-health", help="wait for /api/health")
    health.add_argument("--port", type=int, required=True)
    health.add_argument("--state", default="Running")
    health.add_argument("--timeout", type=float, default=20.0)
    health.add_argument("--output")
    health.set_defaults(func=health_cmd)

    process = subparsers.add_parser("wait-process", help="wait for one process-tree row")
    process.add_argument("--port", type=int, required=True)
    process.add_argument("--pid", type=int)
    process.add_argument("--recent-syscall-substring")
    process.add_argument("--timeout", type=float, default=20.0)
    process.add_argument("--require-threat-score", action="store_true")
    process.add_argument("--require-top-features", action="store_true")
    process.add_argument("--output")
    process.set_defaults(func=process_cmd)

    events = subparsers.add_parser("wait-events", help="wait for matching /api/events rows")
    events.add_argument("--port", type=int, required=True)
    events.add_argument("--pid", type=int)
    events.add_argument("--syscall")
    events.add_argument("--filename")
    events.add_argument("--port-value", type=int)
    events.add_argument("--limit", type=int, default=1024)
    events.add_argument("--minimum", type=int, default=1)
    events.add_argument("--timeout", type=float, default=20.0)
    events.add_argument("--output")
    events.set_defaults(func=events_cmd)

    alert = subparsers.add_parser("wait-alert", help="wait for one matching alert-log row")
    alert.add_argument("--alerts-file", required=True)
    alert.add_argument("--pid", type=int)
    alert.add_argument("--start-line", type=int, default=0)
    alert.add_argument("--timeout", type=float, default=20.0)
    alert.add_argument("--output")
    alert.set_defaults(func=alert_cmd)

    dashboard = subparsers.add_parser("dashboard-alerts", help="fetch dashboard alerts")
    dashboard.add_argument("--port", type=int, required=True)
    dashboard.add_argument("--pid", type=int)
    dashboard.add_argument("--output")
    dashboard.set_defaults(func=dashboard_cmd)

    log_parser = subparsers.add_parser("wait-log", help="wait for one daemon log substring")
    log_parser.add_argument("--log-path", required=True)
    log_parser.add_argument("--substring", required=True)
    log_parser.add_argument("--timeout", type=float, default=10.0)
    log_parser.add_argument("--output")
    log_parser.set_defaults(func=log_cmd)

    bpftool = subparsers.add_parser("filter-bpftool", help="filter bpftool JSON by daemon pid")
    bpftool.add_argument("--input", required=True)
    bpftool.add_argument("--daemon-pid", type=int, required=True)
    bpftool.add_argument("--loaded-after", type=int, default=0)
    bpftool.add_argument("--output")
    bpftool.set_defaults(func=bpftool_cmd)

    perf = subparsers.add_parser("summarize-perf", help="summarize the demo perf snapshot")
    perf.add_argument("--helper-report", required=True)
    perf.add_argument("--health-before", required=True)
    perf.add_argument("--health-after", required=True)
    perf.add_argument("--proc-before", required=True)
    perf.add_argument("--proc-after", required=True)
    perf.add_argument("--rss-samples", required=True)
    perf.add_argument("--output")
    perf.set_defaults(func=perf_cmd)

    return parser


def main() -> int:
    """Run the requested subcommand."""

    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
