"""Materialize deterministic FeatureVector payloads for fixture-driven checks.

The local API assertions rely on checked-in vectors whose scores are stable
against the deployed ONNX artifact. The JSON templates live under
``tests/fixtures/feature_vectors/`` so shell harnesses, Rust integration tests,
and ad-hoc operator curls all exercise the exact same payloads.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from training.schema import feature_manifest  # noqa: E402

TEMPLATE_DIRECTORY = REPO_ROOT / 'tests' / 'fixtures' / 'feature_vectors'


def template_file_names() -> dict[str, str]:
    """Map fixture identifiers to their checked-in JSON templates."""

    return {
        'reverse_shell': 'reverse_shell.json',
        'privesc_setuid': 'privesc_setuid.json',
        'cryptominer_emulator': 'cryptominer_emulator.json',
        'port_scan': 'port_scan.json',
        'kernel_compile': 'kernel_compile.json',
        'nginx_serving': 'nginx_serving.json',
        'idle_desktop': 'idle_desktop.json',
        'high_085': 'high_085.json',
        'exact_threshold': 'exact_threshold.json',
        'below_threshold': 'below_threshold.json',
        'threshold_065': 'threshold_065.json',
    }


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


def template_path(name: str) -> Path:
    """Return the checked-in JSON template path for one fixture identifier."""

    try:
        file_name = template_file_names()[name]
    except KeyError as error:
        raise KeyError(f'unknown fixture: {name}') from error
    return TEMPLATE_DIRECTORY / file_name


def load_template(name: str) -> dict[str, Any]:
    """Load one checked-in JSON template from disk."""

    return json.loads(template_path(name).read_text(encoding='utf-8'))

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


def build_fixture_vector(name: str, _pid: int, _window_hours: float) -> dict[str, Any]:
    """Load one deterministic fixture template and return it in schema order.

    The checked-in templates intentionally keep their baked-in ``pid`` and
    timing fields because the deployed ONNX artifact still buckets on those
    scalar values. Rewriting them at runtime would move the vector onto a
    different score plateau and invalidate the fixture contract.
    """

    return ordered_vector_payload(load_template(name))


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for vector generation."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', help='fixture name to materialize')
    parser.add_argument(
        '--pid',
        type=int,
        default=4_242,
        help='retained for backwards-compatible CLI shape; score-stable templates keep their checked-in pid',
    )
    parser.add_argument(
        '--window-hours',
        type=float,
        default=6.0,
        help='retained for backwards-compatible CLI shape; score-stable templates keep their checked-in timing fields',
    )
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint that prints a feature vector as JSON."""

    args = parse_args()
    payload = build_fixture_vector(args.fixture, args.pid, args.window_hours)
    print(json.dumps(payload, separators=(',', ':')))


if __name__ == '__main__':
    main()
