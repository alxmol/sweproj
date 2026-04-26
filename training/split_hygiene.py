"""Split-hygiene helpers for the Mini-EDR BETH training pipeline.

This module centralizes the documented split boundaries so the trainer,
regression tests, and leakage-verification script all validate the same
methodology contract.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

TRAIN_SPLIT_NAME = "labelled_training_data.csv"
VALIDATION_SPLIT_NAME = "labelled_validation_data.csv"
TEST_SPLIT_NAME = "labelled_testing_data.csv"

# Per SRS FR-D02 and Test Document TC-73, the deployed model is a single binary
# maliciousness classifier. The BETH archive exposes that ground truth through
# the `sus` / `evil` flags, so any row with either flag set is treated as the
# positive class.
LABEL_MAPPING_EXPRESSION = "(df['evil'] == 1) | (df['sus'] == 1)"
LABEL_MAPPING_SOURCE = "Mini_EDR_SRS.docx.md FR-D02; Mini-EDR_Test_Document.docx.md TC-73"

HYPERPARAMETER_GRID: dict[str, list[float] | list[int]] = {
    "n_estimators": [50, 100, 200],
    "max_depth": [3, 5, 7],
    "learning_rate": [0.05, 0.1, 0.3],
}


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest for one file.

    Args:
        path: File whose bytes should be hashed.

    Returns:
        Lowercase SHA-256 hex digest.
    """

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_training_manifest(
    *,
    seed: int,
    model_path: Path,
    metrics_path: Path,
    prior_catalog_path: Path,
    best_hyperparameters: dict[str, Any],
    validation_metrics: dict[str, float],
    test_metrics: dict[str, float],
) -> dict[str, Any]:
    """Build the persisted manifest that documents split hygiene.

    Args:
        seed: Deterministic XGBoost seed.
        model_path: Exported ONNX artifact.
        metrics_path: Saved held-out metrics JSON.
        prior_catalog_path: Saved train-only prior catalog JSON.
        best_hyperparameters: Validation-selected XGBoost hyperparameters.
        validation_metrics: Metrics measured on the validation split.
        test_metrics: Metrics measured on the final held-out testing split.

    Returns:
        JSON-serializable manifest dictionary.
    """

    return {
        "format_version": 1,
        "seed": seed,
        "label_mapping": {
            "expression": LABEL_MAPPING_EXPRESSION,
            "source": LABEL_MAPPING_SOURCE,
        },
        "split_hygiene": {
            "prior_source_split": TRAIN_SPLIT_NAME,
            "grid_search_split": VALIDATION_SPLIT_NAME,
            "final_training_splits": [TRAIN_SPLIT_NAME, VALIDATION_SPLIT_NAME],
            "evaluation_split": TEST_SPLIT_NAME,
        },
        "hyperparameter_grid": HYPERPARAMETER_GRID,
        "best_hyperparameters": best_hyperparameters,
        "validation_metrics": validation_metrics,
        "test_metrics": test_metrics,
        "artifacts": {
            "model": {
                "path": model_path.name,
                "sha256": sha256_file(model_path),
            },
            "metrics": {
                "path": metrics_path.name,
                "sha256": sha256_file(metrics_path),
            },
            "prior_catalog": {
                "path": prior_catalog_path.name,
                "sha256": sha256_file(prior_catalog_path),
            },
        },
    }


def assert_manifest_split_hygiene(manifest: dict[str, Any]) -> None:
    """Assert that a persisted manifest documents the required split boundaries.

    Args:
        manifest: Parsed training manifest JSON.

    Raises:
        AssertionError: When any split boundary or label mapping drifts.
    """

    split_hygiene = manifest["split_hygiene"]
    assert split_hygiene["prior_source_split"] == TRAIN_SPLIT_NAME
    assert split_hygiene["grid_search_split"] == VALIDATION_SPLIT_NAME
    assert split_hygiene["evaluation_split"] == TEST_SPLIT_NAME
    assert split_hygiene["final_training_splits"] == [TRAIN_SPLIT_NAME, VALIDATION_SPLIT_NAME]
    assert manifest["label_mapping"]["expression"] == LABEL_MAPPING_EXPRESSION
