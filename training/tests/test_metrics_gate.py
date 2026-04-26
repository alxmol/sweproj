"""Held-out metrics gate for the Mini-EDR training artifact."""

from __future__ import annotations

import json
from pathlib import Path

import onnx


TREE_ENSEMBLE_OP_TYPES = {'TreeEnsembleClassifier', 'TreeEnsembleRegressor'}


def test_metrics_gate_meets_val_detect_015_thresholds() -> None:
    """Assert the generated metrics.json satisfies the requested quality gate."""

    metrics_path = Path('training/output/metrics.json')
    assert metrics_path.exists(), 'run `make train` before the metrics gate test'

    metrics = json.loads(metrics_path.read_text(encoding='utf-8'))
    assert metrics['f1'] >= 0.90
    assert metrics['tpr'] >= 0.95
    assert metrics['fpr'] <= 0.05


def test_exported_onnx_contains_a_tree_ensemble_node() -> None:
    """Prevent regressions back to a hand-crafted non-tree ONNX graph."""

    model_path = Path('training/output/model.onnx')
    assert model_path.exists(), 'run `make train` before checking the ONNX graph'

    model = onnx.load(str(model_path))
    assert any(node.op_type in TREE_ENSEMBLE_OP_TYPES for node in model.graph.node)
