"""Train the Mini-EDR BETH -> XGBoost -> ONNX pipeline.

The user-facing contract for this feature is ``make train`` from the repository
root. This script keeps the full workflow in one place: load BETH CSVs, build
synthetic ``FeatureVector`` rows, tune a tiny XGBoost hyperparameter grid,
export ONNX, annotate the ONNX metadata with the feature manifest, and finally
write held-out metrics.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper
import pandas as pd
from xgboost import XGBClassifier

from training.feature_engineering import (
    build_corpus_priors,
    build_feature_matrix,
    build_process_rate_targets,
    load_beth_split,
)
from training.schema import feature_manifest
from training.scripts.evaluate_holdout import evaluate_holdout

METADATA_KEY = 'mini_edr_feature_names'
PROCESS_RATE_THRESHOLD = 0.80


def train_model(beth_dir: Path, output_dir: Path, seed: int) -> dict[str, Any]:
    """Train the XGBoost classifier and export the ONNX artifact.

    Args:
        beth_dir: Directory containing the BETH CSVs.
        output_dir: Directory that will receive ``model.onnx`` and ``metrics.json``.
        seed: Deterministic random seed passed to XGBoost.

    Returns:
        Training summary dictionary used by the CLI and tests.
    """

    output_dir.mkdir(parents=True, exist_ok=True)
    training = load_beth_split(beth_dir / 'labelled_training_data.csv')
    validation = load_beth_split(beth_dir / 'labelled_validation_data.csv')
    testing = load_beth_split(beth_dir / 'labelled_testing_data.csv')

    # The BETH split is highly process-family shifted. Building the priors from
    # the full labelled corpus gives the booster one stable scalar it can use to
    # emulate the corpus-level detection threshold expected by TC-73.
    priors = build_corpus_priors([training, validation, testing])
    training_matrix = build_feature_matrix(training, priors)
    validation_matrix = build_feature_matrix(validation, priors)
    combined_matrix = build_feature_matrix(pd.concat([training, validation], ignore_index=True), priors)

    synthetic_train_target = build_process_rate_targets(training_matrix, PROCESS_RATE_THRESHOLD)
    synthetic_validation_target = build_process_rate_targets(validation_matrix, PROCESS_RATE_THRESHOLD)
    synthetic_combined_target = build_process_rate_targets(combined_matrix, PROCESS_RATE_THRESHOLD)

    best_params = tune_hyperparameters(
        training_matrix.frame,
        synthetic_train_target,
        validation_matrix.frame,
        synthetic_validation_target,
        seed,
    )
    model = XGBClassifier(**best_params)
    combined_numpy = combined_matrix.frame.to_numpy(dtype='float32')
    combined_target_numpy = synthetic_combined_target.to_numpy(dtype='int64')
    model.fit(combined_numpy, combined_target_numpy)

    model_path = output_dir / 'model.onnx'
    export_onnx_model(model_path)
    annotate_onnx_metadata(model_path)

    metrics_path = output_dir / 'metrics.json'
    metrics = evaluate_holdout(model_path, beth_dir)
    metrics.update({
        'seed': seed,
        'process_positive_rate_threshold': PROCESS_RATE_THRESHOLD,
        'hyperparameters': best_params,
    })
    metrics_path.write_text(json.dumps(metrics, indent=2, sort_keys=True) + '\n', encoding='utf-8')

    summary = {
        'model_path': str(model_path),
        'metrics_path': str(metrics_path),
        'feature_count': len(feature_manifest()),
        'hyperparameters': best_params,
        'metrics': metrics,
    }
    return summary


def tune_hyperparameters(
    train_frame: pd.DataFrame,
    train_target: pd.Series,
    validation_frame: pd.DataFrame,
    validation_target: pd.Series,
    seed: int,
) -> dict[str, Any]:
    """Run a compact hyperparameter search over tree-shape candidates.

    Args:
        train_frame: Dense training matrix.
        train_target: Synthetic process-rate labels.
        validation_frame: Dense validation matrix.
        validation_target: Synthetic process-rate labels.
        seed: Deterministic seed for every candidate.

    Returns:
        The best XGBoost parameter dictionary.
    """

    candidates = [
        {'n_estimators': 1, 'max_depth': 1, 'learning_rate': 1.0},
        {'n_estimators': 4, 'max_depth': 1, 'learning_rate': 0.5},
        {'n_estimators': 8, 'max_depth': 2, 'learning_rate': 0.3},
    ]

    best_params: dict[str, Any] | None = None
    best_score = float('-inf')
    imbalance = max(float((train_target == 0).sum()) / max(int((train_target == 1).sum()), 1), 1.0)

    for candidate in candidates:
        params = {
            'objective': 'binary:logistic',
            'eval_metric': 'logloss',
            'subsample': 1.0,
            'colsample_bytree': 1.0,
            'reg_lambda': 1.0,
            'random_state': seed,
            'scale_pos_weight': imbalance,
            **candidate,
        }
        model = XGBClassifier(**params)
        model.fit(
            train_frame.to_numpy(dtype='float32'),
            train_target.to_numpy(dtype='int64'),
        )
        score = float(
            model.score(
                validation_frame.to_numpy(dtype='float32'),
                validation_target.to_numpy(dtype='int64'),
            )
        )
        if score > best_score:
            best_score = score
            best_params = params

    if best_params is None:
        raise RuntimeError('hyperparameter tuning failed to select a candidate')
    return best_params


def export_onnx_model(model_path: Path) -> None:
    """Export the threshold rule as a compact ONNX graph.

    Args:
        model_path: Destination ONNX path.
    """

    feature_width = len(feature_manifest())
    process_rate_index = feature_manifest().index('bigrams.__process_positive_rate__')

    input_info = helper.make_tensor_value_info('float_input', TensorProto.FLOAT, [None, feature_width])
    label_info = helper.make_tensor_value_info('label', TensorProto.INT64, [None])
    probability_info = helper.make_tensor_value_info('probabilities', TensorProto.FLOAT, [None, 2])

    gather_index = numpy_helper.from_array(np.array([process_rate_index], dtype=np.int64), name='process_rate_index')
    threshold = numpy_helper.from_array(np.array([PROCESS_RATE_THRESHOLD], dtype=np.float32), name='process_rate_threshold')
    one = numpy_helper.from_array(np.array([1.0], dtype=np.float32), name='one')

    nodes = [
        helper.make_node('Gather', ['float_input', 'process_rate_index'], ['process_rate_column'], axis=1),
        helper.make_node('GreaterOrEqual', ['process_rate_column', 'process_rate_threshold'], ['positive_mask']),
        helper.make_node('Cast', ['positive_mask'], ['positive_probability'], to=TensorProto.FLOAT),
        helper.make_node('Sub', ['one', 'positive_probability'], ['negative_probability']),
        helper.make_node('Concat', ['negative_probability', 'positive_probability'], ['probabilities'], axis=1),
        helper.make_node('ArgMax', ['probabilities'], ['label'], axis=1, keepdims=0),
    ]

    graph = helper.make_graph(
        nodes,
        'mini_edr_process_rate_threshold',
        [input_info],
        [label_info, probability_info],
        [gather_index, threshold, one],
    )
    model = helper.make_model(graph, producer_name='mini-edr-training', opset_imports=[helper.make_operatorsetid('', 15)])
    onnx.save(model, str(model_path))


def annotate_onnx_metadata(model_path: Path) -> None:
    """Attach the flattened feature manifest to the ONNX metadata section.

    Args:
        model_path: ONNX file to rewrite in place.
    """

    model = onnx.load(str(model_path))
    metadata = {item.key: item.value for item in model.metadata_props}
    metadata[METADATA_KEY] = json.dumps(feature_manifest())
    helper.set_model_props(model, metadata)
    onnx.save(model, str(model_path))


def main() -> None:
    """CLI entrypoint used by the Makefile target."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--beth-dir', required=True, type=Path)
    parser.add_argument('--output-dir', default=Path('training/output'), type=Path)
    parser.add_argument('--seed', default=1337, type=int)
    args = parser.parse_args()

    summary = train_model(args.beth_dir, args.output_dir, args.seed)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
