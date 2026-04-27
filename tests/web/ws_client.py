#!/usr/bin/env python3
"""Minimal WebSocket harnesses for Mini-EDR dashboard integration checks."""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import socket
import sys
import time
from typing import Any


def read_exact(sock: socket.socket, length: int) -> bytes:
    """Read exactly ``length`` bytes or raise when the peer closes early."""

    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise ConnectionError("socket closed before the frame was complete")
        chunks.extend(chunk)
    return bytes(chunks)


def perform_handshake(host: str, port: int, path: str, timeout_seconds: float) -> tuple[socket.socket, int, str]:
    """Open a raw TCP socket and perform the RFC6455 HTTP upgrade handshake."""

    sock = socket.create_connection((host, port), timeout=timeout_seconds)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("ascii")
    sock.sendall(request)

    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4_096)
        if not chunk:
            raise ConnectionError("socket closed during the WebSocket handshake")
        response.extend(chunk)
    header_text = response.decode("iso-8859-1")
    status_line = header_text.splitlines()[0]
    status_code = int(status_line.split()[1])
    return sock, status_code, header_text


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    """Read one server-to-client WebSocket frame and return ``(opcode, payload)``."""

    first, second = read_exact(sock, 2)
    opcode = first & 0x0F
    payload_length = second & 0x7F
    masked = bool(second & 0x80)

    if payload_length == 126:
        payload_length = int.from_bytes(read_exact(sock, 2), "big")
    elif payload_length == 127:
        payload_length = int.from_bytes(read_exact(sock, 8), "big")

    mask = read_exact(sock, 4) if masked else b""
    payload = bytearray(read_exact(sock, payload_length))
    if masked:
        for index, value in enumerate(payload):
            payload[index] = value ^ mask[index % 4]
    return opcode, bytes(payload)


def command_listen(args: argparse.Namespace) -> int:
    """Connect once, optionally consume frames, and print a JSON summary."""

    started_at_ms = time.time() * 1_000.0
    sock, status_code, _headers = perform_handshake(args.host, args.port, args.path, args.timeout)
    result: dict[str, Any] = {
        "status_code": status_code,
        "received_count": 0,
        "alerts": [],
        "mode": args.mode,
        "started_at_ms": started_at_ms,
    }
    if status_code != 101:
        sock.close()
        print(json.dumps(result))
        return 0

    try:
        if args.mode == "zombie":
            time.sleep(args.hold_seconds)
            result["held_seconds"] = args.hold_seconds
            print(json.dumps(result))
            return 0

        deadline = time.monotonic() + args.timeout
        while result["received_count"] < args.count and time.monotonic() < deadline:
            remaining = max(0.1, deadline - time.monotonic())
            sock.settimeout(remaining)
            opcode, payload = read_frame(sock)
            if opcode == 0x8:
                result["closed"] = True
                break
            if opcode != 0x1:
                continue

            alert = json.loads(payload.decode("utf-8"))
            result["alerts"].append(
                {
                    "alert_id": alert.get("alert_id"),
                    "timestamp": alert.get("timestamp"),
                    "receive_ms": time.time() * 1_000.0,
                }
            )
            result["received_count"] += 1
            if args.mode == "slow":
                time.sleep(args.delay_seconds)
    except TimeoutError:
        result["timed_out"] = True
    except OSError as error:
        result["socket_error"] = str(error)
    finally:
        sock.close()

    print(json.dumps(result))
    return 0


async def open_one_connection(host: str, port: int, path: str, timeout_seconds: float) -> tuple[int, asyncio.StreamWriter | None]:
    """Open one TCP connection, attempt the HTTP upgrade, and classify the result."""

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout_seconds,
        )
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        writer.write(request)
        await writer.drain()
        headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout_seconds)
        status_code = int(headers.decode("iso-8859-1").splitlines()[0].split()[1])
        if status_code == 101:
            return status_code, writer
        writer.close()
        await writer.wait_closed()
        return status_code, None
    except Exception:
        return 0, None


async def command_storm_async(args: argparse.Namespace) -> int:
    """Attempt many concurrent upgrades and print aggregate acceptance counts."""

    tasks = [
        open_one_connection(args.host, args.port, args.path, args.timeout)
        for _ in range(args.connections)
    ]
    results = await asyncio.gather(*tasks)
    accepted_writers = [writer for status_code, writer in results if status_code == 101 and writer]
    counts = {
        "accepted": sum(1 for status_code, _writer in results if status_code == 101),
        "rejected": sum(1 for status_code, _writer in results if status_code == 503),
        "other": sum(1 for status_code, _writer in results if status_code not in {101, 503}),
    }
    if args.hold_seconds > 0:
        await asyncio.sleep(args.hold_seconds)
    for writer in accepted_writers:
        writer.close()
    await asyncio.gather(*(writer.wait_closed() for writer in accepted_writers), return_exceptions=True)
    print(json.dumps(counts))
    return 0


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for the listen and storm modes."""

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    listen = subparsers.add_parser("listen", help="Open one connection and consume frames")
    listen.add_argument("--host", default="127.0.0.1")
    listen.add_argument("--port", type=int, required=True)
    listen.add_argument("--path", default="/ws")
    listen.add_argument("--count", type=int, default=1)
    listen.add_argument("--timeout", type=float, default=10.0)
    listen.add_argument(
        "--mode",
        choices=("fast", "slow", "zombie"),
        default="fast",
    )
    listen.add_argument("--delay-seconds", type=float, default=1.0)
    listen.add_argument("--hold-seconds", type=float, default=8.0)

    storm = subparsers.add_parser("storm", help="Attempt many concurrent upgrades")
    storm.add_argument("--host", default="127.0.0.1")
    storm.add_argument("--port", type=int, required=True)
    storm.add_argument("--path", default="/ws")
    storm.add_argument("--connections", type=int, default=1_000)
    storm.add_argument("--timeout", type=float, default=5.0)
    storm.add_argument("--hold-seconds", type=float, default=2.0)

    return parser.parse_args()


def main() -> int:
    """Dispatch the chosen subcommand."""

    args = parse_args()
    if args.command == "listen":
        return command_listen(args)
    if args.command == "storm":
        return asyncio.run(command_storm_async(args))
    raise ValueError(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
