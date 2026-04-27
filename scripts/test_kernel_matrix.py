#!/usr/bin/env python3
"""Run the Mini-EDR kernel portability matrix in QEMU/KVM guests.

This harness proves three portability behaviors for `f8-portability-tests`:

1. A real Linux 5.4 guest is rejected by the daemon's runtime kernel gate.
2. The same release daemon binary boots and loads probes on Linux 5.8.
3. The same release daemon binary boots and loads probes on Linux 6.x.

The guests share the already-built host repository read-only via virtio-9p so
the *same* release binary and ONNX model are exercised on both supported
kernels without recompilation. A matching writable evidence share captures each
guest's JSON result and daemon logs for later inspection.
"""

from __future__ import annotations

import http.server
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import textwrap
import threading
import time
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "contrib" / "kernel-5.8" / "profiles.json"
CACHE_DIR = REPO_ROOT / "contrib" / "kernel-5.8" / "cache"
ARTIFACT_DIR = REPO_ROOT / "artifacts" / "kernel-matrix"
DAEMON_BINARY = REPO_ROOT / "target" / "release" / "mini-edr-daemon"
EBPF_OBJECT = (
    REPO_ROOT
    / "target"
    / "mini-edr-sensor-ebpf"
    / "bpfel-unknown-none"
    / "release"
    / "mini-edr-sensor-ebpf"
)
MODEL_PATH = REPO_ROOT / "training" / "output" / "model.onnx"
EXPECTED_PROBES = {"clone", "connect", "execve", "openat"}
QEMU_TIMEOUT_SECONDS = 480
PORT_RANGE = range(8010, 8099)


def log(message: str) -> None:
    """Print a step marker so the shell wrapper has readable progress."""

    print(f"[kernel-matrix] {message}", flush=True)


def require_file(path: Path, description: str) -> None:
    """Fail early with a useful error when a required input is missing."""

    if not path.exists():
        raise SystemExit(f"error: missing {description} at {path}")


def run(command: list[str], *, cwd: Path | None = None, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    """Run a subprocess with captured text output and fail on non-zero exit."""

    return subprocess.run(
        command,
        cwd=cwd,
        timeout=timeout,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def download(url: str, destination: Path) -> Path:
    """Cache a remote kernel/rootfs artifact locally for reuse across runs."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        log(f"reusing cached {destination.name}")
        return destination

    log(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as response:
        destination.write_bytes(response.read())
    return destination


def allocate_port() -> int:
    """Pick an unused localhost port inside the mission's allowed HTTP range."""

    for port in PORT_RANGE:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free localhost port available in 8010-8098 for cloud-init")


class QuietHttpServer:
    """Serve a cloud-init directory to the guest over localhost."""

    def __init__(self, directory: Path, port: int) -> None:
        self.directory = directory
        self.port = port
        handler = lambda *args, **kwargs: http.server.SimpleHTTPRequestHandler(  # noqa: E731
            *args, directory=str(directory), **kwargs
        )
        class ReusableTcpServer(socketserver.TCPServer):
            allow_reuse_address = True

        self.httpd = ReusableTcpServer(("127.0.0.1", port), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self) -> "QuietHttpServer":
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


def cloud_init_user_data(profile: dict[str, str], payload_port: int) -> str:
    """Build the guest's cloud-init document with an embedded verification script."""

    guest_script = f"""#!/usr/bin/env python3
import json
import os
import pathlib
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request

PROFILE = {json.dumps(profile, sort_keys=True)}
EXPECTED_PROBES = {json.dumps(sorted(EXPECTED_PROBES))}
PAYLOAD_BASE_URL = "http://10.0.2.2:{payload_port}/payload"
PAYLOAD_DIR = pathlib.Path("/tmp/mini-edr-payload")
DAEMON_BINARY = PAYLOAD_DIR / "mini-edr-daemon"
EBPF_OBJECT = PAYLOAD_DIR / "mini-edr-sensor-ebpf"
MODEL_PATH = PAYLOAD_DIR / "model.onnx"
CONFIG_PATH = pathlib.Path("/tmp/mini-edr-kernel-matrix.toml")
DAEMON_STDOUT = pathlib.Path("/tmp/mini-edr-daemon-stdout.log")
DAEMON_STDERR = pathlib.Path("/tmp/mini-edr-daemon-stderr.log")


def write_result(status: str, **payload: object) -> None:
    result = {{
        "profile": PROFILE["name"],
        "status": status,
        **payload,
    }}
    print("RESULT_JSON:" + json.dumps(result, sort_keys=True), flush=True)


def daemon_log_tail(path: pathlib.Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")[-4000:]


def download_payload() -> None:
    PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)
    for name, destination in [
        ("mini-edr-daemon", DAEMON_BINARY),
        ("mini-edr-sensor-ebpf", EBPF_OBJECT),
        ("model.onnx", MODEL_PATH),
    ]:
        with urllib.request.urlopen(f"{{PAYLOAD_BASE_URL}}/{{name}}", timeout=30) as response:
            destination.write_bytes(response.read())
    os.chmod(DAEMON_BINARY, 0o755)
    os.chmod(EBPF_OBJECT, 0o755)


def fetch_json(url: str) -> object:
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_for_health() -> dict[str, object]:
    deadline = time.time() + 90
    last_error = None
    while time.time() < deadline:
        try:
            payload = fetch_json("http://127.0.0.1:8080/api/health")
            if isinstance(payload, dict):
                return payload
        except Exception as error:  # pragma: no cover - guest-only path
            last_error = str(error)
        time.sleep(1)
    raise RuntimeError(f"daemon never became healthy: {{last_error}}")


def generate_workload() -> None:
    subprocess.run(["/bin/true"], check=True)
    with open("/etc/hosts", "rb") as handle:
        handle.read(1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect(("127.0.0.1", 9))
    except OSError:
        pass
    finally:
        sock.close()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - child branch inside guest
        os._exit(0)
    os.waitpid(pid, 0)
    time.sleep(2)


def main() -> None:
    actual_release = subprocess.check_output(["uname", "-r"], text=True).strip()
    download_payload()
    if not actual_release.startswith(PROFILE["release_expectation"]):
        write_result(
            "fail",
            reason="kernel release expectation mismatch",
            actual_release=actual_release,
            expected_prefix=PROFILE["release_expectation"],
        )
        return

    CONFIG_PATH.write_text(
        "\\n".join(
            [
                "alert_threshold = 0.7",
                "web_port = 8080",
                f'model_path = "{{MODEL_PATH}}"',
                'log_file_path = "/tmp/logs/mini-edr-kernel-matrix-alerts.jsonl"',
                'state_dir = "/tmp/mini-edr-kernel-matrix-state"',
            ]
        )
        + "\\n",
        encoding="utf-8",
    )

    if PROFILE["mode"] == "reject":
        rejected = subprocess.run(
            [str(DAEMON_BINARY), "--config", str(CONFIG_PATH)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        write_result(
            "pass" if rejected.returncode != 0 and "requires Linux kernel >= 5.8" in rejected.stderr else "fail",
            actual_release=actual_release,
            returncode=rejected.returncode,
            stdout_tail=rejected.stdout[-2000:],
            stderr_tail=rejected.stderr[-2000:],
        )
        return

    env = os.environ.copy()
    env["MINI_EDR_API_SOCKET"] = "/tmp/mini-edr-kernel-matrix.sock"
    env["MINI_EDR_EBPF_OBJECT"] = str(EBPF_OBJECT)
    with open(DAEMON_STDOUT, "w", encoding="utf-8") as stdout_handle, open(
        DAEMON_STDERR, "w", encoding="utf-8"
    ) as stderr_handle:
        daemon = subprocess.Popen(
            [str(DAEMON_BINARY), "--config", str(CONFIG_PATH)],
            env=env,
            stdout=stdout_handle,
            stderr=stderr_handle,
            text=True,
        )
        try:
            health = wait_for_health()
            generate_workload()
            health_after = fetch_json("http://127.0.0.1:8080/api/health")
            missing_probes = sorted(set(EXPECTED_PROBES) - set(health_after.get("active_probes", [])))
            received_delta = int(health_after.get("ring_events_received_total", 0)) - int(
                health.get("ring_events_received_total", 0)
            )
            daemon.send_signal(signal.SIGTERM)
            returncode = daemon.wait(timeout=30)
            if health_after.get("state") != "Running":
                raise RuntimeError(f"daemon state was {{health_after.get('state')}} instead of Running")
            if missing_probes:
                raise RuntimeError(f"missing active probes: {{missing_probes}}")
            if received_delta <= 0:
                raise RuntimeError(
                    f"ring_events_received_total did not increase after the workload (delta={{received_delta}})"
                )
            if returncode != 0:
                raise RuntimeError(f"daemon exited with status {{returncode}} instead of 0")
            write_result(
                "pass",
                actual_release=actual_release,
                health=health,
                health_after=health_after,
                ring_events_received_delta=received_delta,
                daemon_returncode=returncode,
                daemon_stdout_tail=daemon_log_tail(DAEMON_STDOUT),
                daemon_stderr_tail=daemon_log_tail(DAEMON_STDERR),
            )
        except Exception as error:  # pragma: no cover - guest-only path
            daemon.kill()
            daemon.wait(timeout=30)
            write_result(
                "fail",
                actual_release=actual_release,
                reason=str(error),
                daemon_stdout_tail=daemon_log_tail(DAEMON_STDOUT),
                daemon_stderr_tail=daemon_log_tail(DAEMON_STDERR),
            )


if __name__ == "__main__":
    main()
"""

    boot_script = """#!/usr/bin/env bash
set -euxo pipefail

/root/mini_edr_guest_check.py
poweroff -f
"""

    guest_script_block = textwrap.indent(guest_script.rstrip(), "      ")
    boot_script_block = textwrap.indent(boot_script.rstrip(), "      ")
    return "\n".join(
        [
            "#cloud-config",
            "package_update: false",
            "package_upgrade: false",
            "write_files:",
            "  - path: /root/mini_edr_guest_check.py",
            "    permissions: '0755'",
            "    content: |",
            guest_script_block,
            "  - path: /root/mini_edr_guest_boot.sh",
            "    permissions: '0755'",
            "    content: |",
            boot_script_block,
            "runcmd:",
            '  - [bash, -lc, "/root/mini_edr_guest_boot.sh"]',
            'final_message: "mini-edr kernel matrix guest finished"',
            "",
        ]
    )


def write_cloud_init(run_dir: Path, profile: dict[str, str], payload_port: int) -> Path:
    """Write a minimal NoCloud directory consumed by cloud-init over HTTP."""

    cloud_init_dir = run_dir / "cloud-init"
    cloud_init_dir.mkdir(parents=True, exist_ok=True)
    (cloud_init_dir / "meta-data").write_text(
        f"instance-id: mini-edr-{profile['name']}\nlocal-hostname: mini-edr-{profile['name']}\n",
        encoding="utf-8",
    )
    payload_dir = cloud_init_dir / "payload"
    payload_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(DAEMON_BINARY, payload_dir / "mini-edr-daemon")
    shutil.copy2(EBPF_OBJECT, payload_dir / "mini-edr-sensor-ebpf")
    shutil.copy2(MODEL_PATH, payload_dir / "model.onnx")
    (cloud_init_dir / "user-data").write_text(
        cloud_init_user_data(profile, payload_port),
        encoding="utf-8",
    )
    (cloud_init_dir / "vendor-data").write_text("#cloud-config\n{}\n", encoding="utf-8")
    return cloud_init_dir


def build_overlay(base_image: Path, destination: Path) -> None:
    """Create a disposable qcow2 overlay so each guest starts from a clean disk."""

    if destination.exists():
        destination.unlink()
    run(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            str(base_image),
            str(destination),
        ]
    )


def guest_qemu_command(run_dir: Path, profile: dict[str, str], port: int, overlay: Path, kernel: Path, initrd: Path) -> list[str]:
    """Construct the direct-kernel QEMU command line for one matrix row."""

    kvm_usable = os.access("/dev/kvm", os.R_OK | os.W_OK)
    accel = "kvm:tcg" if kvm_usable else "tcg"
    cpu = "host" if kvm_usable else "max"
    serial_log = run_dir / "serial.log"
    return [
        "qemu-system-x86_64",
        "-machine",
        f"accel={accel}",
        "-cpu",
        cpu,
        "-smp",
        "2",
        "-m",
        "4096",
        "-nographic",
        "-no-reboot",
        "-drive",
        f"if=virtio,format=qcow2,file={overlay}",
        "-kernel",
        str(kernel),
        "-initrd",
        str(initrd),
        "-append",
        f"root=/dev/vda1 console=ttyS0 rw ds=nocloud-net;s=http://10.0.2.2:{port}/",
        "-nic",
        "user,model=virtio-net-pci",
        "-serial",
        f"file:{serial_log}",
        "-monitor",
        "none",
    ]


def run_guest(rootfs: Path, profile: dict[str, str], kernel: Path, initrd: Path) -> dict[str, object]:
    """Boot one guest profile and return its captured JSON result."""

    run_dir = ARTIFACT_DIR / profile["name"]
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    overlay = run_dir / "overlay.qcow2"
    build_overlay(rootfs, overlay)
    port = allocate_port()
    cloud_init_dir = write_cloud_init(run_dir, profile, port)
    serial_log = run_dir / "serial.log"
    qemu_stdout = run_dir / "qemu-stdout.log"
    qemu_stderr = run_dir / "qemu-stderr.log"
    command = guest_qemu_command(run_dir, profile, port, overlay, kernel, initrd)

    with QuietHttpServer(cloud_init_dir, port):
        log(f"booting {profile['name']} on expected kernel prefix {profile['release_expectation']}")
        try:
            completed = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=QEMU_TIMEOUT_SECONDS,
            )
            qemu_stdout.write_text(completed.stdout, encoding="utf-8")
            qemu_stderr.write_text(completed.stderr, encoding="utf-8")
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                f"{profile['name']} timed out after {QEMU_TIMEOUT_SECONDS}s; serial log tail:\n"
                f"{serial_log.read_text(encoding='utf-8', errors='ignore')[-4000:]}"
            ) from error

    serial_text = serial_log.read_text(encoding="utf-8", errors="ignore")
    result_line = next(
        (
            line.split("RESULT_JSON:", 1)[1]
            for line in reversed(serial_text.splitlines())
            if "RESULT_JSON:" in line
        ),
        None,
    )
    if result_line is None:
        raise RuntimeError(
            f"{profile['name']} did not print a RESULT_JSON line; serial log tail:\n"
            f"{serial_text[-4000:]}\n"
            f"qemu stderr tail:\n{qemu_stderr.read_text(encoding='utf-8', errors='ignore')[-4000:]}"
        )
    result = json.loads(result_line)
    if result.get("status") != "pass":
        raise RuntimeError(
            f"{profile['name']} failed: {json.dumps(result, indent=2)}\n"
            f"serial log tail:\n{serial_text[-4000:]}"
        )
    return result


def main() -> None:
    """Build once, download the pinned assets, and exercise every kernel row."""

    require_file(MANIFEST_PATH, "kernel profile manifest")
    require_file(MODEL_PATH, "trained ONNX model")

    log("running host-side CO-RE preflight")
    run([str(REPO_ROOT / "scripts" / "test_core_portability.sh")], cwd=REPO_ROOT, timeout=600)
    require_file(EBPF_OBJECT, "prebuilt eBPF object from CO-RE preflight")

    log("building the release daemon binary once for all guest rows")
    run(["cargo", "build", "--release", "-p", "mini-edr-daemon"], cwd=REPO_ROOT, timeout=1800)
    require_file(DAEMON_BINARY, "release daemon binary")

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    rootfs_name = Path(manifest["rootfs"]["url"]).name
    rootfs = download(manifest["rootfs"]["url"], CACHE_DIR / rootfs_name)
    results: list[dict[str, object]] = []
    for profile in manifest["kernels"]:
        kernel = download(profile["kernel_url"], CACHE_DIR / f"{profile['name']}-vmlinuz")
        initrd = download(profile["initrd_url"], CACHE_DIR / f"{profile['name']}-initrd")
        result = run_guest(rootfs, profile, kernel, initrd)
        results.append(result)
        log(f"{profile['name']} passed ({result['actual_release']})")

    summary = {
        "binary": str(DAEMON_BINARY),
        "model": str(MODEL_PATH),
        "results": results,
    }
    summary_path = ARTIFACT_DIR / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    log(f"wrote summary to {summary_path}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.stderr.write(error.stdout or "")
        sys.stderr.write(error.stderr or "")
        raise
