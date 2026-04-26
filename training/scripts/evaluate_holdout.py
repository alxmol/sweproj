"""Evaluate the trained Mini-EDR XGBoost/ONNX artifact on the BETH hold-out set."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import onnxruntime as ort
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, recall_score

from training.feature_engineering import (
    build_corpus_priors,
    build_feature_matrix,
    load_beth_split,
)
from training.schema import feature_manifest


DEFAULT_THRESHOLD = 0.5


def evaluate_holdout(model_path: Path, beth_dir: Path, threshold: float = DEFAULT_THRESHOLD) -> dict[str, Any]:
    """Run ONNX inference on the labelled BETH testing split.

    Args:
        model_path: Path to the ONNX artifact produced by ``training/train.py``.
        beth_dir: Directory containing the three labelled BETH CSVs.
        threshold: Binary decision threshold applied to the positive-class score.

    Returns:
        Dictionary of held-out metrics and bookkeeping fields.
    """

    training = load_beth_split(beth_dir / 'labelled_training_data.csv')
    validation = load_beth_split(beth_dir / 'labelled_validation_data.csv')
    testing = load_beth_split(beth_dir / 'labelled_testing_data.csv')
    priors = build_corpus_priors([training, validation, testing])
    test_matrix = build_feature_matrix(testing, priors)

    probabilities = predict_positive_scores(model_path, test_matrix.frame)
    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(test_matrix.labels, predictions).ravel()

    return {
        'f1': float(f1_score(test_matrix.labels, predictions)),
        'tpr': float(recall_score(test_matrix.labels, predictions)),
        'fpr': float(fp / (fp + tn)),
        'threshold': threshold,
        'tp': int(tp),
        'fp': int(fp),
        'tn': int(tn),
        'fn': int(fn),
        'n_train': int(len(training)),
        'n_validation': int(len(validation)),
        'n_test': int(len(testing)),
        'feature_count': len(feature_manifest()),
        'model_path': str(model_path),
    }


def predict_positive_scores(model_path: Path, frame: pd.DataFrame) -> np.ndarray:
    """Run ONNX Runtime inference and return positive-class scores.

    Args:
        model_path: ONNX file produced by the trainer.
        frame: Dense feature matrix ordered by ``feature_manifest()``.

    Returns:
        One probability-like score per input row.
    """

    session = ort.InferenceSession(str(model_path), providers=['CPUExecutionProvider'])
    input_name = session.get_inputs()[0].name

    # The converted XGBoost model returns a label tensor and a probability
    # tensor. We always consume the probability tensor so metric calculations do
    # not depend on any converter-specific hard decision threshold.
    outputs = session.run(None, {input_name: frame.to_numpy(dtype=np.float32)})
    probabilities = outputs[-1]
    probabilities = np.asarray(probabilities)

    if probabilities.ndim == 2 and probabilities.shape[1] == 2:
        return probabilities[:, 1]
    if probabilities.ndim == 1:
        return probabilities
    if probabilities.ndim == 2 and probabilities.shape[1] == 1:
        return probabilities[:, 0]
    raise ValueError(f'Unexpected ONNX probability shape: {probabilities.shape!r}')


def main() -> None:
    """CLI entrypoint used by ``make train`` and the metrics gate tests."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', required=True, type=Path)
    parser.add_argument('--beth-dir', required=True, type=Path)
    parser.add_argument('--threshold', type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()

    metrics = evaluate_holdout(args.model, args.beth_dir, threshold=args.threshold)
    rendered = json.dumps(metrics, indent=2, sort_keys=True)
    print(rendered)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
