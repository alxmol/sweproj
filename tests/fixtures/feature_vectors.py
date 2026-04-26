"""Generate synthetic FeatureVector payloads for fixture-driven daemon checks.

The current detection milestone exposes model scoring through the daemon's
``/internal/predict`` surface before the full live sensor -> alert stream is
wired. These helpers let the fixture scripts express controlled malicious and
benign workloads as deterministic ``FeatureVector`` JSON documents so the same
scripts can both perform a safe local behavior and score a representative
window against the trained model.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from training.schema import feature_manifest  # noqa: E402


def malware_fixture_names() -> tuple[str, ...]:
    """Return the supported malicious fixture identifiers."""

    return (
        'reverse_shell',
        'privesc_setuid',
        'cryptominer_emulator',
        'port_scan',
    )


def benign_fixture_names() -> tuple[str, ...]:
    """Return the supported benign fixture identifiers."""

    return (
        'kernel_compile',
        'nginx_serving',
        'idle_desktop',
    )


def fixture_category(name: str) -> str:
    """Return the category for one named fixture.

    Args:
        name: Fixture identifier.

    Returns:
        ``"malware"`` or ``"benign"``.

    Raises:
        KeyError: When ``name`` is unknown.
    """

    if name in malware_fixture_names():
        return 'malware'
    if name in benign_fixture_names():
        return 'benign'
    raise KeyError(f'unknown fixture: {name}')


def base_vector(pid: int, window_duration_ns: int) -> dict[str, Any]:
    """Build a stable baseline vector shared by every fixture.

    Args:
        pid: Synthetic process identifier recorded in the scored window.
        window_duration_ns: Duration represented by the fixture's process window.

    Returns:
        Dictionary containing every scalar field required by the Rust
        ``FeatureVector`` schema plus the two sparse namespaces.
    """

    end_ns = time.time_ns()
    start_ns = end_ns - window_duration_ns
    return {
        'pid': pid,
        'window_start_ns': start_ns,
        'window_end_ns': end_ns,
        'total_syscalls': 32,
        'execve_count': 1,
        'openat_count': 8,
        'connect_count': 0,
        'clone_count': 0,
        'execve_ratio': 1.0 / 32.0,
        'openat_ratio': 8.0 / 32.0,
        'connect_ratio': 0.0,
        'clone_ratio': 0.0,
        'path_entropy': 0.4,
        'unique_ips': 0,
        'unique_files': 8,
        'child_spawn_count': 0,
        'avg_inter_syscall_time_ns': 5_000_000.0,
        'min_inter_syscall_time_ns': 25_000.0,
        'max_inter_syscall_time_ns': 40_000_000.0,
        'stddev_inter_syscall_time_ns': 2_000_000.0,
        'wrote_etc': False,
        'wrote_tmp': False,
        'wrote_dev': False,
        'read_sensitive_file_count': 0,
        'write_sensitive_file_count': 0,
        'outbound_connection_count': 0,
        'loopback_connection_count': 0,
        'distinct_ports': 0,
        'failed_syscall_count': 0,
        'short_lived': False,
        'window_duration_ns': window_duration_ns,
        'events_per_second': 32.0 / max(window_duration_ns / 1_000_000_000.0, 1.0),
        'bigrams': {
            '__process_positive_rate__': 0.02,
            '__event_positive_rate__': 0.02,
        },
        'trigrams': {
            '__path_positive_rate__': 0.02,
        },
    }


def apply_overrides(vector: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """Apply scalar and sparse-map overrides to a baseline vector.

    Args:
        vector: Baseline feature vector to copy.
        **overrides: Replacement scalar values or nested ``bigrams``/``trigrams`` maps.

    Returns:
        A copied vector with the requested overrides applied.
    """

    updated = {
        **vector,
        'bigrams': dict(vector['bigrams']),
        'trigrams': dict(vector['trigrams']),
    }
    for key, value in overrides.items():
        if key in {'bigrams', 'trigrams'}:
            updated[key].update(value)
        else:
            updated[key] = value
    return updated


def ordered_vector_payload(vector: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministically ordered JSON payload.

    Args:
        vector: Completed feature vector dictionary.

    Returns:
        Ordered payload that matches the Rust field ordering for readability.
    """

    ordered = {name: vector[name] for name in feature_manifest() if name in vector}
    ordered['bigrams'] = vector['bigrams']
    ordered['trigrams'] = vector['trigrams']
    for key, value in vector.items():
        if key not in ordered:
            ordered[key] = value
    return ordered


def build_fixture_vector(name: str, pid: int, window_hours: float) -> dict[str, Any]:
    """Build the representative vector for one fixture.

    Args:
        name: Fixture identifier.
        pid: PID stamped into the synthetic window.
        window_hours: Benign workload window duration in hours. Malware fixtures
            treat this only as a sizing hint because their windows are short.

    Returns:
        Ordered JSON-serializable feature vector payload.

    Raises:
        KeyError: When ``name`` is not a known fixture.
    """

    malware_window_ns = 30 * 1_000_000_000
    benign_window_ns = int(window_hours * 3_600 * 1_000_000_000)
    category = fixture_category(name)
    vector = base_vector(pid, malware_window_ns if category == 'malware' else benign_window_ns)

    # Each template intentionally keeps the corpus-risk priors aligned with the
    # behavior family so the current ONNX classifier sees the same schema it was
    # trained on, while the scalar fields still document why the fixture is
    # considered suspicious or benign.
    templates: dict[str, dict[str, Any]] = {
        'reverse_shell': {
            'total_syscalls': 160,
            'openat_count': 36,
            'connect_count': 6,
            'clone_count': 2,
            'execve_ratio': 1.0 / 160.0,
            'openat_ratio': 36.0 / 160.0,
            'connect_ratio': 6.0 / 160.0,
            'clone_ratio': 2.0 / 160.0,
            'path_entropy': 2.1,
            'unique_ips': 1,
            'unique_files': 18,
            'child_spawn_count': 2,
            'avg_inter_syscall_time_ns': 1_200_000.0,
            'min_inter_syscall_time_ns': 8_000.0,
            'max_inter_syscall_time_ns': 6_000_000.0,
            'stddev_inter_syscall_time_ns': 450_000.0,
            'wrote_tmp': True,
            'read_sensitive_file_count': 2,
            'write_sensitive_file_count': 1,
            'outbound_connection_count': 6,
            'loopback_connection_count': 6,
            'distinct_ports': 1,
            'failed_syscall_count': 1,
            'events_per_second': 5.3,
            'bigrams': {
                '__process_positive_rate__': 0.95,
                '__event_positive_rate__': 0.92,
            },
            'trigrams': {
                '__path_positive_rate__': 0.88,
            },
        },
        'privesc_setuid': {
            'total_syscalls': 144,
            'openat_count': 52,
            'connect_count': 0,
            'clone_count': 1,
            'execve_ratio': 1.0 / 144.0,
            'openat_ratio': 52.0 / 144.0,
            'connect_ratio': 0.0,
            'clone_ratio': 1.0 / 144.0,
            'path_entropy': 1.8,
            'unique_files': 22,
            'child_spawn_count': 1,
            'avg_inter_syscall_time_ns': 1_600_000.0,
            'min_inter_syscall_time_ns': 10_000.0,
            'max_inter_syscall_time_ns': 8_000_000.0,
            'stddev_inter_syscall_time_ns': 500_000.0,
            'wrote_etc': True,
            'wrote_tmp': True,
            'read_sensitive_file_count': 6,
            'write_sensitive_file_count': 3,
            'failed_syscall_count': 2,
            'events_per_second': 4.8,
            'bigrams': {
                '__process_positive_rate__': 0.97,
                '__event_positive_rate__': 0.89,
            },
            'trigrams': {
                '__path_positive_rate__': 0.91,
            },
        },
        'cryptominer_emulator': {
            'total_syscalls': 5_200,
            'openat_count': 1_400,
            'connect_count': 0,
            'clone_count': 48,
            'execve_ratio': 1.0 / 5_200.0,
            'openat_ratio': 1_400.0 / 5_200.0,
            'connect_ratio': 0.0,
            'clone_ratio': 48.0 / 5_200.0,
            'path_entropy': 2.6,
            'unique_files': 64,
            'child_spawn_count': 48,
            'avg_inter_syscall_time_ns': 250_000.0,
            'min_inter_syscall_time_ns': 1_500.0,
            'max_inter_syscall_time_ns': 2_000_000.0,
            'stddev_inter_syscall_time_ns': 90_000.0,
            'wrote_tmp': True,
            'read_sensitive_file_count': 1,
            'write_sensitive_file_count': 4,
            'failed_syscall_count': 0,
            'events_per_second': 173.0,
            'bigrams': {
                '__process_positive_rate__': 0.93,
                '__event_positive_rate__': 0.86,
            },
            'trigrams': {
                '__path_positive_rate__': 0.82,
            },
        },
        'port_scan': {
            'total_syscalls': 280,
            'openat_count': 18,
            'connect_count': 64,
            'clone_count': 1,
            'execve_ratio': 1.0 / 280.0,
            'openat_ratio': 18.0 / 280.0,
            'connect_ratio': 64.0 / 280.0,
            'clone_ratio': 1.0 / 280.0,
            'path_entropy': 1.3,
            'unique_ips': 1,
            'unique_files': 6,
            'child_spawn_count': 1,
            'avg_inter_syscall_time_ns': 400_000.0,
            'min_inter_syscall_time_ns': 2_000.0,
            'max_inter_syscall_time_ns': 1_000_000.0,
            'stddev_inter_syscall_time_ns': 60_000.0,
            'outbound_connection_count': 64,
            'loopback_connection_count': 64,
            'distinct_ports': 64,
            'failed_syscall_count': 0,
            'events_per_second': 9.3,
            'bigrams': {
                '__process_positive_rate__': 0.96,
                '__event_positive_rate__': 0.94,
            },
            'trigrams': {
                '__path_positive_rate__': 0.79,
            },
        },
        'kernel_compile': {
            'total_syscalls': 4_096,
            'openat_count': 1_920,
            'connect_count': 0,
            'clone_count': 12,
            'execve_ratio': 12.0 / 4_096.0,
            'openat_ratio': 1_920.0 / 4_096.0,
            'connect_ratio': 0.0,
            'clone_ratio': 12.0 / 4_096.0,
            'path_entropy': 1.7,
            'unique_files': 420,
            'child_spawn_count': 12,
            'avg_inter_syscall_time_ns': 4_000_000.0,
            'min_inter_syscall_time_ns': 15_000.0,
            'max_inter_syscall_time_ns': 50_000_000.0,
            'stddev_inter_syscall_time_ns': 2_400_000.0,
            'events_per_second': 1.6,
            'bigrams': {
                '__process_positive_rate__': 0.04,
                '__event_positive_rate__': 0.05,
            },
            'trigrams': {
                '__path_positive_rate__': 0.03,
            },
        },
        'nginx_serving': {
            'total_syscalls': 2_048,
            'openat_count': 480,
            'connect_count': 120,
            'clone_count': 4,
            'execve_ratio': 2.0 / 2_048.0,
            'openat_ratio': 480.0 / 2_048.0,
            'connect_ratio': 120.0 / 2_048.0,
            'clone_ratio': 4.0 / 2_048.0,
            'path_entropy': 0.9,
            'unique_ips': 1,
            'unique_files': 48,
            'child_spawn_count': 4,
            'avg_inter_syscall_time_ns': 3_500_000.0,
            'min_inter_syscall_time_ns': 5_000.0,
            'max_inter_syscall_time_ns': 8_000_000.0,
            'stddev_inter_syscall_time_ns': 1_200_000.0,
            'outbound_connection_count': 0,
            'loopback_connection_count': 120,
            'distinct_ports': 1,
            'events_per_second': 0.6,
            'bigrams': {
                '__process_positive_rate__': 0.03,
                '__event_positive_rate__': 0.04,
            },
            'trigrams': {
                '__path_positive_rate__': 0.03,
            },
        },
        'idle_desktop': {
            'total_syscalls': 12,
            'openat_count': 4,
            'connect_count': 0,
            'clone_count': 0,
            'execve_ratio': 1.0 / 12.0,
            'openat_ratio': 4.0 / 12.0,
            'connect_ratio': 0.0,
            'clone_ratio': 0.0,
            'path_entropy': 0.2,
            'unique_files': 3,
            'child_spawn_count': 0,
            'avg_inter_syscall_time_ns': 30_000_000.0,
            'min_inter_syscall_time_ns': 1_000_000.0,
            'max_inter_syscall_time_ns': 240_000_000.0,
            'stddev_inter_syscall_time_ns': 8_500_000.0,
            'events_per_second': 0.003,
            'bigrams': {
                '__process_positive_rate__': 0.01,
                '__event_positive_rate__': 0.02,
            },
            'trigrams': {
                '__path_positive_rate__': 0.01,
            },
        },
    }

    if name not in templates:
        raise KeyError(f'unknown fixture: {name}')
    return ordered_vector_payload(apply_overrides(vector, **templates[name]))


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for vector generation."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', help='fixture name to materialize')
    parser.add_argument('--pid', type=int, default=4_242, help='PID to stamp into the vector')
    parser.add_argument(
        '--window-hours',
        type=float,
        default=6.0,
        help='duration represented by benign vectors (malware fixtures use short windows)',
    )
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint that prints a feature vector as JSON."""

    args = parse_args()
    payload = build_fixture_vector(args.fixture, args.pid, args.window_hours)
    print(json.dumps(payload, separators=(',', ':')))


if __name__ == '__main__':
    main()
