"""Verify that the exported ONNX artifact preserves the expected tree schema."""

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
TREE_ENSEMBLE_OP_TYPES = {'TreeEnsembleClassifier', 'TreeEnsembleRegressor'}


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

    ensemble_node = next((node for node in model.graph.node if node.op_type in TREE_ENSEMBLE_OP_TYPES), None)
    if ensemble_node is None:
        raise SystemExit('expected at least one TreeEnsembleClassifier or TreeEnsembleRegressor node')

    tree_count, node_count = summarize_tree_ensemble(ensemble_node)
    print(json.dumps({
        'ensemble_op_type': ensemble_node.op_type,
        'feature_names': names,
        'input_width': width,
        'node_count': node_count,
        'tree_count': tree_count,
    }, indent=2))


def summarize_tree_ensemble(node: onnx.NodeProto) -> tuple[int, int]:
    """Count trees and nodes from a TreeEnsemble ONNX node.

    Args:
        node: ``TreeEnsembleClassifier`` or ``TreeEnsembleRegressor`` node.

    Returns:
        ``(tree_count, node_count)`` for traceability in validator output.

    Raises:
        SystemExit: When the converter emitted a malformed tree ensemble.
    """

    attributes = {attribute.name: attribute for attribute in node.attribute}
    tree_ids = list(attributes.get('nodes_treeids', onnx.AttributeProto()).ints)
    node_ids = list(attributes.get('nodes_nodeids', onnx.AttributeProto()).ints)
    if not tree_ids or not node_ids:
        raise SystemExit('tree ensemble node is missing nodes_treeids/nodes_nodeids attributes')

    return len(set(tree_ids)), len(node_ids)


def main() -> None:
    """CLI entrypoint used by the assigned verification step."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('model', type=Path)
    args = parser.parse_args()
    verify_schema(args.model)


if __name__ == '__main__':
    main()
