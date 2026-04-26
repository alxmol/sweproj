"""Verify that the exported ONNX artifact preserves the expected feature schema."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    import onnx
except ModuleNotFoundError:
    fallback_python = (
        REPO_ROOT
        / 'crates/mini-edr-detection/training/.venv/bin/python'
    )
    os.execv(str(fallback_python), [str(fallback_python), __file__, *sys.argv[1:]])

from training.schema import feature_manifest  # noqa: E402


METADATA_KEY = 'mini_edr_feature_names'


def verify_schema(model_path: Path) -> None:
    """Assert that the ONNX artifact encodes the expected flattened feature list.

    Args:
        model_path: Path to the ONNX artifact.

    Raises:
        SystemExit: When the schema metadata is missing or mismatched.
    """

    model = onnx.load(str(model_path))
    metadata = {item.key: item.value for item in model.metadata_props}
    if METADATA_KEY not in metadata:
        raise SystemExit(f'missing ONNX metadata key {METADATA_KEY!r}')

    names = json.loads(metadata[METADATA_KEY])
    expected = feature_manifest()
    if names != expected:
        raise SystemExit('feature-name metadata does not match the trainer manifest')

    dims = model.graph.input[0].type.tensor_type.shape.dim
    width = dims[1].dim_value if len(dims) > 1 else 0
    if width != len(expected):
        raise SystemExit(f'expected input width {len(expected)}, found {width}')

    print(json.dumps({'input_width': width, 'feature_names': names}, indent=2))


def main() -> None:
    """CLI entrypoint used by the assigned verification step."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('model', type=Path)
    args = parser.parse_args()
    verify_schema(args.model)


if __name__ == '__main__':
    main()
