"""Shared schema helpers for the Mini-EDR training pipeline.

The Rust runtime owns the canonical ``FeatureVector`` layout in
``mini-edr-common``. The Python trainer mirrors the field names here so the
ONNX artifact and the later Rust inference loader can agree on a stable input
contract.
"""

from __future__ import annotations

from typing import Final, Iterable

# These names mirror the public fields on ``mini_edr_common::FeatureVector``.
SCALAR_FEATURE_NAMES: Final[list[str]] = [
    'pid',
    'window_start_ns',
    'window_end_ns',
    'total_syscalls',
    'execve_count',
    'openat_count',
    'connect_count',
    'clone_count',
    'execve_ratio',
    'openat_ratio',
    'connect_ratio',
    'clone_ratio',
    'path_entropy',
    'unique_ips',
    'unique_files',
    'child_spawn_count',
    'avg_inter_syscall_time_ns',
    'min_inter_syscall_time_ns',
    'max_inter_syscall_time_ns',
    'stddev_inter_syscall_time_ns',
    'wrote_etc',
    'wrote_tmp',
    'wrote_dev',
    'read_sensitive_file_count',
    'write_sensitive_file_count',
    'outbound_connection_count',
    'loopback_connection_count',
    'distinct_ports',
    'failed_syscall_count',
    'short_lived',
    'window_duration_ns',
    'events_per_second',
]

# The BETH archive is a labelled corpus rather than a live eBPF stream. We use
# three sparse numeric keys under the map namespaces so the model can ingest the
# corpus-derived process/event/path priors without mutating the Rust scalar
# schema. The later inference integration can materialize the same keys from the
# runtime context before flattening the ``FeatureVector``.
BIGRAM_PRIOR_KEYS: Final[list[str]] = [
    '__process_positive_rate__',
    '__event_positive_rate__',
]
TRIGRAM_PRIOR_KEYS: Final[list[str]] = [
    '__path_positive_rate__',
]


def feature_manifest() -> list[str]:
    """Return the ordered flattened model feature list.

    Returns:
        Ordered feature names used both for training matrices and for the ONNX
        metadata payload stored next to the model artifact.
    """

    return [
        *SCALAR_FEATURE_NAMES,
        *(f'bigrams.{name}' for name in BIGRAM_PRIOR_KEYS),
        *(f'trigrams.{name}' for name in TRIGRAM_PRIOR_KEYS),
    ]


def namespaced_map_keys(namespace: str, keys: Iterable[str]) -> list[str]:
    """Prefix sparse-map keys with their map namespace.

    Args:
        namespace: ``bigrams`` or ``trigrams``.
        keys: Bare sparse feature names.

    Returns:
        Namespaced keys matching ``feature_manifest()`` ordering.
    """

    return [f'{namespace}.{key}' for key in keys]
