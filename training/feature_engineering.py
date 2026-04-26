"""Feature engineering for the Mini-EDR BETH training pipeline.

The live Mini-EDR daemon emits ``FeatureVector`` values from sliding process
windows. The BETH archive, however, stores labelled syscall rows. To bridge the
shape mismatch without inventing Rust-only fields, this module synthesizes a
single-event ``FeatureVector`` per BETH row and injects three train-only sparse
priors through the existing map namespaces.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

import pandas as pd

from training.schema import (
    BIGRAM_PRIOR_KEYS,
    SCALAR_FEATURE_NAMES,
    TRIGRAM_PRIOR_KEYS,
    feature_manifest,
)
from training.split_hygiene import LABEL_MAPPING_EXPRESSION

# The four monitored syscall classes from ``mini-edr-common::SyscallType``.
EXECVE_EVENTS = {'execve', 'security_bprm_check'}
OPENAT_EVENTS = {
    'open',
    'openat',
    'security_file_open',
    'stat',
    'lstat',
    'fstat',
    'access',
    'getdents64',
    'unlink',
    'unlinkat',
}
CONNECT_EVENTS = {'accept', 'accept4', 'bind', 'connect', 'getsockname', 'listen', 'socket'}
CLONE_EVENTS = {'clone', 'dup', 'dup2', 'dup3', 'prctl', 'sched_process_exit'}

BETH_USECOLS = [
    'timestamp',
    'processId',
    'processName',
    'eventName',
    'returnValue',
    'args',
    'sus',
    'evil',
]


@dataclass(frozen=True)
class CorpusPriors:
    """Train-only positive-rate priors derived from the BETH training split.

    The persisted catalog must be fit on the labelled training split only so
    the later validation and testing rows cannot leak their label distribution
    into the model input space.
    """

    global_positive_rate: float
    process_positive_rate: dict[str, float]
    event_positive_rate: dict[str, float]
    path_positive_rate: dict[str, float]


@dataclass(frozen=True)
class FeatureMatrix:
    """Dense training matrix plus labels.

    Attributes:
        frame: Ordered numeric feature columns matching ``feature_manifest()``.
        labels: Binary labels extracted from the BETH ``sus``/``evil`` flags.
    """

    frame: pd.DataFrame
    labels: pd.Series


def load_beth_split(csv_path: Path) -> pd.DataFrame:
    """Load one labelled BETH split with only the columns this trainer needs.

    Args:
        csv_path: Path to a ``labelled_*_data.csv`` file.

    Returns:
        DataFrame with a normalized ``label`` column.
    """

    frame = pd.read_csv(csv_path, usecols=BETH_USECOLS)
    # Per SRS FR-D02 and Test Document TC-73, the deployed detector is a single
    # malicious-versus-benign classifier. The BETH archive exposes that ground
    # truth through the `sus` / `evil` bits, so any row with either bit set is
    # the positive class (`LABEL_MAPPING_EXPRESSION` documents the exact rule).
    frame['label'] = ((frame['evil'] == 1) | (frame['sus'] == 1)).astype(int)
    frame['path'] = frame['args'].map(extract_path)
    frame['path_prefix'] = frame['path'].map(path_prefix)
    return frame


def build_training_priors(training_frame: pd.DataFrame) -> CorpusPriors:
    """Build smoothed positive-rate priors from the training split only.

    Args:
        training_frame: The labelled training DataFrame.

    Returns:
        Smoothed prior tables keyed by process name, event name, and path prefix.
    """

    global_rate = float(training_frame['label'].mean())

    return CorpusPriors(
        global_positive_rate=global_rate,
        process_positive_rate=_smoothed_positive_rate(training_frame, 'processName', global_rate),
        event_positive_rate=_smoothed_positive_rate(training_frame, 'eventName', global_rate),
        path_positive_rate=_smoothed_positive_rate(training_frame, 'path_prefix', global_rate),
    )


def save_prior_catalog(priors: CorpusPriors, output_path: Path) -> None:
    """Persist the train-only prior catalog next to the model artifact.

    Args:
        priors: Train-only prior tables.
        output_path: JSON destination path.
    """

    output_path.write_text(
        json.dumps(
            {
                'format_version': 1,
                'source_split': 'labelled_training_data.csv',
                'label_mapping': LABEL_MAPPING_EXPRESSION,
                'global_positive_rate': priors.global_positive_rate,
                'process_positive_rate': priors.process_positive_rate,
                'event_positive_rate': priors.event_positive_rate,
                'path_positive_rate': priors.path_positive_rate,
            },
            indent=2,
            sort_keys=True,
        )
        + '\n',
        encoding='utf-8',
    )


def load_prior_catalog(catalog_path: Path) -> CorpusPriors:
    """Load the persisted train-only prior catalog from disk.

    Args:
        catalog_path: JSON file written by :func:`save_prior_catalog`.

    Returns:
        The train-only prior tables used during training/evaluation.
    """

    payload = json.loads(catalog_path.read_text(encoding='utf-8'))
    return CorpusPriors(
        global_positive_rate=float(payload['global_positive_rate']),
        process_positive_rate={str(key): float(value) for key, value in payload['process_positive_rate'].items()},
        event_positive_rate={str(key): float(value) for key, value in payload['event_positive_rate'].items()},
        path_positive_rate={str(key): float(value) for key, value in payload['path_positive_rate'].items()},
    )


def collect_split_token_sets(frame: pd.DataFrame) -> dict[str, set[str]]:
    """Collect the categorical token sets used by the saved prior catalog.

    Args:
        frame: Labelled BETH split with derived ``path_prefix`` column.

    Returns:
        Token sets keyed by the prior-family name used in leakage checks.
    """

    return {
        'process_name': set(frame['processName'].astype(str).unique()),
        'event_name': set(frame['eventName'].astype(str).unique()),
        'path_prefix': {str(value) for value in frame['path_prefix'].fillna('').astype(str).unique()},
    }


def build_feature_matrix(frame: pd.DataFrame, priors: CorpusPriors) -> FeatureMatrix:
    """Convert BETH rows into flattened ``FeatureVector``-shaped rows.

    Args:
        frame: One labelled BETH split.
        priors: Corpus-wide positive-rate priors.

    Returns:
        Dense numeric DataFrame ordered by ``training.schema.feature_manifest``.
    """

    rows = [flatten_feature_vector(synthesize_feature_vector(row, priors)) for row in frame.to_dict('records')]
    matrix = pd.DataFrame(rows, columns=feature_manifest())
    return FeatureMatrix(frame=matrix, labels=frame['label'].astype(int))


def synthesize_feature_vector(row: dict[str, Any], priors: CorpusPriors) -> dict[str, Any]:
    """Map one BETH row into a synthetic ``FeatureVector`` payload.

    Args:
        row: Raw BETH row represented as a dictionary.
        priors: Corpus-level positive-rate priors.

    Returns:
        Dictionary with scalar ``FeatureVector`` fields plus sparse ``bigrams``
        and ``trigrams`` maps.
    """

    timestamp_ns = int(float(row['timestamp']) * 1_000_000_000)
    event_name = str(row['eventName'])
    path = row.get('path') if isinstance(row.get('path'), str) else extract_path(row.get('args', ''))
    flags = extract_flags(row.get('args', ''))
    is_execve = int(event_name in EXECVE_EVENTS)
    is_openat = int(event_name in OPENAT_EVENTS)
    is_connect = int(event_name in CONNECT_EVENTS)
    is_clone = int(event_name in CLONE_EVENTS)
    sensitive_dir = classify_sensitive_dir(path)
    write_like = has_write_intent(flags)
    failed = int(int(row['returnValue']) < 0)

    scalar_values = {
        'pid': int(row['processId']),
        'window_start_ns': timestamp_ns,
        'window_end_ns': timestamp_ns + 1,
        'total_syscalls': 1,
        'execve_count': is_execve,
        'openat_count': is_openat,
        'connect_count': is_connect,
        'clone_count': is_clone,
        'execve_ratio': float(is_execve),
        'openat_ratio': float(is_openat),
        'connect_ratio': float(is_connect),
        'clone_ratio': float(is_clone),
        'path_entropy': 0.0,
        'unique_ips': int(is_connect),
        'unique_files': int(bool(path)),
        'child_spawn_count': is_clone,
        'avg_inter_syscall_time_ns': 0.0,
        'min_inter_syscall_time_ns': 0.0,
        'max_inter_syscall_time_ns': 0.0,
        'stddev_inter_syscall_time_ns': 0.0,
        'wrote_etc': int(sensitive_dir == 'etc' and write_like),
        'wrote_tmp': int(sensitive_dir == 'tmp' and write_like),
        'wrote_dev': int(sensitive_dir == 'dev' and write_like),
        'read_sensitive_file_count': int(bool(sensitive_dir) and not write_like),
        'write_sensitive_file_count': int(bool(sensitive_dir) and write_like),
        'outbound_connection_count': is_connect,
        'loopback_connection_count': int(is_connect and path == '127.0.0.1'),
        'distinct_ports': 0,
        'failed_syscall_count': failed,
        'short_lived': 1,
        'window_duration_ns': 1,
        'events_per_second': 1.0,
    }

    return {
        **scalar_values,
        'bigrams': {
            BIGRAM_PRIOR_KEYS[0]: priors.process_positive_rate.get(str(row['processName']), priors.global_positive_rate),
            BIGRAM_PRIOR_KEYS[1]: priors.event_positive_rate.get(event_name, priors.global_positive_rate),
        },
        'trigrams': {
            TRIGRAM_PRIOR_KEYS[0]: priors.path_positive_rate.get(path_prefix(path), priors.global_positive_rate),
        },
    }


def flatten_feature_vector(vector: dict[str, Any]) -> dict[str, float]:
    """Flatten a synthetic ``FeatureVector`` into the ONNX input row shape.

    Args:
        vector: Scalar-plus-sparse synthetic feature payload.

    Returns:
        Dense numeric row keyed by ``feature_manifest()``.
    """

    flattened: dict[str, float] = {name: float(vector[name]) for name in SCALAR_FEATURE_NAMES}
    for key in BIGRAM_PRIOR_KEYS:
        flattened[f'bigrams.{key}'] = float(vector['bigrams'].get(key, 0.0))
    for key in TRIGRAM_PRIOR_KEYS:
        flattened[f'trigrams.{key}'] = float(vector['trigrams'].get(key, 0.0))
    return flattened


def extract_path(raw_args: str) -> str | None:
    """Best-effort pathname extraction from the BETH ``args`` column.

    Args:
        raw_args: Stringified argument list emitted by BETH.

    Returns:
        Absolute or relative path string when present, otherwise ``None``.
    """

    for item in parse_args(raw_args):
        if item.get('name') in {'pathname', 'path'}:
            value = item.get('value')
            if isinstance(value, str):
                return value
    return None


def extract_flags(raw_args: str) -> str:
    """Extract textual open flags from the BETH ``args`` column.

    Args:
        raw_args: Stringified argument list emitted by BETH.

    Returns:
        Pipe-delimited flags string, or an empty string when unavailable.
    """

    for item in parse_args(raw_args):
        if item.get('name') == 'flags' and isinstance(item.get('value'), str):
            return item['value']
    return ''


def parse_args(raw_args: str) -> list[dict[str, Any]]:
    """Parse the BETH ``args`` column into Python dictionaries.

    Args:
        raw_args: Stringified list of dictionaries.

    Returns:
        Parsed argument dictionaries, or an empty list when parsing fails.
    """

    try:
        value = ast.literal_eval(raw_args)
    except (SyntaxError, ValueError):
        return []

    return value if isinstance(value, list) else []


def path_prefix(path: str | None) -> str:
    """Return a compact path prefix for the corpus path prior table.

    Args:
        path: Extracted pathname.

    Returns:
        ``/segment`` or ``/segment/subsegment`` prefix, or an empty string.
    """

    if not isinstance(path, str) or not path:
        return ''

    parts = [segment for segment in path.split('/') if segment]
    if not parts:
        return ''
    if len(parts) == 1:
        return f'/{parts[0]}'
    return f'/{parts[0]}/{parts[1]}'


def classify_sensitive_dir(path: str | None) -> str | None:
    """Classify a pathname into the FeatureVector sensitive-directory booleans.

    Args:
        path: Extracted pathname.

    Returns:
        ``'etc'``, ``'tmp'``, ``'dev'``, or ``None``.
    """

    if not path:
        return None
    if path == '/etc' or path.startswith('/etc/'):
        return 'etc'
    if path == '/tmp' or path.startswith('/tmp/'):
        return 'tmp'
    if path == '/dev' or path.startswith('/dev/'):
        return 'dev'
    return None


def has_write_intent(flags: str) -> bool:
    """Infer write intent from a textual BETH flag string.

    Args:
        flags: Pipe-delimited open flags such as ``O_RDONLY|O_CLOEXEC``.

    Returns:
        ``True`` when the flags indicate a write-like open intent.
    """

    return any(token in flags for token in ('O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_TRUNC', 'O_APPEND'))


def rust_feature_vector_fields(rust_source: str) -> list[str]:
    """Extract Rust ``FeatureVector`` field names for schema-parity tests.

    Args:
        rust_source: Text of ``mini-edr-common/src/lib.rs``.

    Returns:
        Ordered list of public field names inside the Rust ``FeatureVector``.
    """

    lines = rust_source.splitlines()
    in_struct = False
    fields: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('pub struct FeatureVector'):
            in_struct = True
            continue
        if in_struct and stripped == '}':
            break
        if in_struct and stripped.startswith('pub '):
            field = stripped.removeprefix('pub ').split(':', maxsplit=1)[0].strip()
            fields.append(field)
    return fields


def _smoothed_positive_rate(frame: pd.DataFrame, column: str, global_rate: float) -> dict[str, float]:
    """Compute a lightly smoothed positive-rate table for one categorical key.

    Args:
        frame: Concatenated corpus frame.
        column: Group-by column name.
        global_rate: Global positive rate used as the smoothing prior.

    Returns:
        Dictionary mapping the category to a smoothed positive rate.
    """

    grouped = frame.groupby(column)['label'].agg(['sum', 'count'])
    smoothing_weight = 5.0
    grouped['rate'] = (grouped['sum'] + global_rate * smoothing_weight) / (grouped['count'] + smoothing_weight)
    return grouped['rate'].to_dict()
