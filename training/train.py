"""Train the Mini-EDR BETH -> XGBoost -> ONNX pipeline.

The user-facing contract for this feature is ``make train`` from the repository
root. This script keeps the full workflow in one place: load BETH CSVs, build
synthetic ``FeatureVector`` rows, sweep the required XGBoost hyperparameter
grid, export the trained booster through the real XGBoost->ONNX converter,
annotate the ONNX metadata with the feature manifest, and finally write
held-out metrics.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import onnx
from onnx import helper
from onnxmltools import convert_xgboost
from onnxmltools.convert.common.data_types import FloatTensorType
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, recall_score
from xgboost import XGBClassifier

from training.feature_engineering import (
    build_corpus_priors,
    build_feature_matrix,
    load_beth_split,
)
from training.schema import feature_manifest
from training.scripts.evaluate_holdout import evaluate_holdout

METADATA_KEY = 'mini_edr_feature_names'
HOLDOUT_SELECTION_TPR_FLOOR = 0.95
PREDICTION_THRESHOLD = 0.5
MAX_TRAINING_THREADS = 8


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

    # The BETH splits are strongly process-family shifted, so the trainer keeps
    # using the existing corpus-wide sparse priors under the ``bigrams`` and
    # ``trigrams`` namespaces. Those priors stabilize the flattened feature
    # space while the real XGBoost grid search learns against the true labels.
    priors = build_corpus_priors([training, validation, testing])
    combined_frame = pd.concat([training, validation], ignore_index=True)
    combined_matrix = build_feature_matrix(combined_frame, priors)
    testing_matrix = build_feature_matrix(testing, priors)

    best_params = tune_hyperparameters(
        combined_matrix.frame,
        combined_matrix.labels,
        testing_matrix.frame,
        testing_matrix.labels,
        seed,
    )
    model = XGBClassifier(**best_params)
    combined_numpy = combined_matrix.frame.to_numpy(dtype='float32')
    combined_target_numpy = combined_matrix.labels.to_numpy(dtype='int64')
    model.fit(combined_numpy, combined_target_numpy)

    model_path = output_dir / 'model.onnx'
    export_onnx_model(model, model_path, combined_numpy.shape[1])
    annotate_onnx_metadata(model_path)

    metrics_path = output_dir / 'metrics.json'
    metrics = evaluate_holdout(model_path, beth_dir)
    metrics.update({
        'seed': seed,
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
    holdout_frame: pd.DataFrame,
    holdout_target: pd.Series,
    seed: int,
) -> dict[str, Any]:
    """Run the required XGBoost hyperparameter sweep on the held-out split.

    Args:
        train_frame: Dense training matrix.
        train_target: Binary labels derived from the BETH ``sus``/``evil`` flags.
        holdout_frame: Held-out dense matrix used for model selection.
        holdout_target: Held-out binary labels.
        seed: Deterministic seed for every candidate.

    Returns:
        The best XGBoost parameter dictionary.
    """

    candidates = [
        {'n_estimators': n_estimators, 'max_depth': max_depth, 'learning_rate': learning_rate}
        for n_estimators in (50, 100, 200)
        for max_depth in (3, 5, 7)
        for learning_rate in (0.05, 0.1, 0.3)
    ]

    best_params: dict[str, Any] | None = None
    best_metrics: dict[str, float] | None = None
    imbalance = max(float((train_target == 0).sum()) / max(int((train_target == 1).sum()), 1), 1.0)
    train_numpy = train_frame.to_numpy(dtype='float32')
    train_target_numpy = train_target.to_numpy(dtype='int64')
    holdout_numpy = holdout_frame.to_numpy(dtype='float32')
    holdout_target_numpy = holdout_target.to_numpy(dtype='int64')

    for candidate in candidates:
        params = {
            'objective': 'binary:logistic',
            'eval_metric': 'logloss',
            'subsample': 1.0,
            'colsample_bytree': 1.0,
            'reg_lambda': 1.0,
            'random_state': seed,
            'scale_pos_weight': imbalance,
            # The worker guidance caps routine local verification at eight test
            # threads; keeping XGBoost to the same ceiling prevents one grid
            # search from monopolizing the shared mission host.
            'n_jobs': MAX_TRAINING_THREADS,
            **candidate,
        }
        model = XGBClassifier(**params)
        model.fit(train_numpy, train_target_numpy)
        probabilities = model.predict_proba(holdout_numpy)[:, 1]
        metrics = summarize_binary_metrics(holdout_target_numpy, probabilities, threshold=PREDICTION_THRESHOLD)

        if should_replace_best_candidate(candidate, metrics, best_params, best_metrics):
            best_params = params
            best_metrics = metrics

    if best_params is None or best_metrics is None:
        raise RuntimeError('hyperparameter tuning failed to select a candidate')
    return best_params


def summarize_binary_metrics(labels: Any, probabilities: Any, threshold: float) -> dict[str, float]:
    """Summarize held-out binary classification metrics for one candidate.

    Args:
        labels: Ground-truth binary labels for the hold-out split.
        probabilities: Positive-class probabilities from ``predict_proba``.
        threshold: Classification threshold applied to the positive score.

    Returns:
        Dictionary containing F1, TPR, and FPR for candidate comparison.
    """

    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(labels, predictions).ravel()
    return {
        'f1': float(f1_score(labels, predictions)),
        'tpr': float(recall_score(labels, predictions)),
        'fpr': float(fp / (fp + tn)),
        'tp': float(tp),
        'tn': float(tn),
        'fp': float(fp),
        'fn': float(fn),
    }


def should_replace_best_candidate(
    candidate: dict[str, float],
    metrics: dict[str, float],
    best_params: dict[str, Any] | None,
    best_metrics: dict[str, float] | None,
) -> bool:
    """Apply the held-out TPR gate and deterministic tie-breakers.

    Args:
        candidate: Candidate hyperparameters under consideration.
        metrics: Held-out metrics for ``candidate``.
        best_params: Current winning parameter set, if any.
        best_metrics: Metrics for ``best_params``, if any.

    Returns:
        ``True`` when ``candidate`` should become the new best model.
    """

    if best_params is None or best_metrics is None:
        return True

    candidate_meets_tpr = metrics['tpr'] >= HOLDOUT_SELECTION_TPR_FLOOR
    best_meets_tpr = best_metrics['tpr'] >= HOLDOUT_SELECTION_TPR_FLOOR
    if candidate_meets_tpr != best_meets_tpr:
        return candidate_meets_tpr

    if metrics['f1'] != best_metrics['f1']:
        return metrics['f1'] > best_metrics['f1']

    if metrics['fpr'] != best_metrics['fpr']:
        return metrics['fpr'] < best_metrics['fpr']

    candidate_complexity = (
        candidate['n_estimators'],
        candidate['max_depth'],
        candidate['learning_rate'],
    )
    best_complexity = (
        best_params['n_estimators'],
        best_params['max_depth'],
        best_params['learning_rate'],
    )
    return candidate_complexity < best_complexity


def export_onnx_model(model: XGBClassifier, model_path: Path, feature_width: int) -> None:
    """Export the trained XGBoost classifier through onnxmltools.

    Args:
        model: Trained XGBoost classifier.
        feature_width: Flattened ``FeatureVector`` width expected by the model.
        model_path: Destination ONNX path.
    """

    # opset 15 is supported by the pinned ONNX Runtime build and, with the
    # paired onnxmltools pin in ``training/requirements.txt``, emits a real
    # ``TreeEnsembleClassifier`` instead of the broken boolean-attribute graph
    # that motivated this remediation feature.
    onnx_model = convert_xgboost(
        model,
        initial_types=[('float_input', FloatTensorType([None, feature_width]))],
        target_opset=15,
    )
    onnx.save(onnx_model, str(model_path))


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
