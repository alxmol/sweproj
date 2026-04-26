"""Regression tests for the detection split-hygiene remediation."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from training.feature_engineering import (
    build_training_priors,
    collect_split_token_sets,
    load_beth_split,
    load_prior_catalog,
    save_prior_catalog,
)
from training.split_hygiene import (
    TEST_SPLIT_NAME,
    TRAIN_SPLIT_NAME,
    VALIDATION_SPLIT_NAME,
    assert_manifest_split_hygiene,
    build_training_manifest,
)


def test_load_beth_split_uses_real_beth_labels_union_of_sus_and_evil(tmp_path: Path) -> None:
    """Any BETH row flagged by either ground-truth bit must be positive."""

    csv_path = tmp_path / TRAIN_SPLIT_NAME
    csv_path.write_text(
        "\n".join(
            [
                "timestamp,processId,processName,eventName,returnValue,args,sus,evil",
                '1.0,10,cron,execve,0,"[]",0,0',
                '2.0,11,cron,execve,0,"[]",1,0',
                '3.0,12,cron,execve,0,"[]",0,1',
                '4.0,13,cron,execve,0,"[]",1,1',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    frame = load_beth_split(csv_path)
    assert frame["label"].tolist() == [0, 1, 1, 1]


def test_train_only_prior_catalog_excludes_test_only_tokens(tmp_path: Path) -> None:
    """Saved priors must only contain vocabulary that appeared in the train split."""

    training = pd.DataFrame(
        [
            {
                "timestamp": 1.0,
                "processId": 10,
                "processName": "cron",
                "eventName": "execve",
                "returnValue": 0,
                "args": "[{'name': 'pathname', 'type': 'char *', 'value': '/tmp/train'}]",
                "sus": 0,
                "evil": 1,
            }
        ]
    )
    testing = pd.DataFrame(
        [
            {
                "timestamp": 2.0,
                "processId": 11,
                "processName": "test-only-process",
                "eventName": "test-only-event",
                "returnValue": 0,
                "args": "[{'name': 'pathname', 'type': 'char *', 'value': '/opt/test-only'}]",
                "sus": 1,
                "evil": 0,
            }
        ]
    )

    # Reuse the production loader semantics so derived columns match the real trainer.
    training_csv = tmp_path / TRAIN_SPLIT_NAME
    testing_csv = tmp_path / TEST_SPLIT_NAME
    training.to_csv(training_csv, index=False)
    testing.to_csv(testing_csv, index=False)
    train_frame = load_beth_split(training_csv)
    test_frame = load_beth_split(testing_csv)

    catalog_path = tmp_path / "prior_catalog.json"
    save_prior_catalog(build_training_priors(train_frame), catalog_path)
    catalog = load_prior_catalog(catalog_path)

    train_tokens = collect_split_token_sets(train_frame)
    test_tokens = collect_split_token_sets(test_frame)
    assert set(catalog.process_positive_rate).issubset(train_tokens["process_name"])
    assert set(catalog.event_positive_rate).issubset(train_tokens["event_name"])
    assert set(catalog.path_positive_rate).issubset(train_tokens["path_prefix"])
    assert set(catalog.process_positive_rate).isdisjoint(test_tokens["process_name"] - train_tokens["process_name"])
    assert set(catalog.event_positive_rate).isdisjoint(test_tokens["event_name"] - train_tokens["event_name"])
    assert set(catalog.path_positive_rate).isdisjoint(test_tokens["path_prefix"] - train_tokens["path_prefix"])


def test_training_manifest_records_validation_tuning_and_test_evaluation(tmp_path: Path) -> None:
    """The persisted manifest must document the non-leaky split boundaries."""

    model_path = tmp_path / "model.onnx"
    metrics_path = tmp_path / "metrics.json"
    prior_catalog_path = tmp_path / "prior_catalog.json"
    model_path.write_bytes(b"onnx")
    metrics_path.write_text("{}", encoding="utf-8")
    prior_catalog_path.write_text("{}", encoding="utf-8")

    manifest = build_training_manifest(
        seed=1337,
        model_path=model_path,
        metrics_path=metrics_path,
        prior_catalog_path=prior_catalog_path,
        best_hyperparameters={"n_estimators": 50, "max_depth": 3, "learning_rate": 0.05},
        validation_metrics={"f1": 0.95, "tpr": 0.96, "fpr": 0.01},
        test_metrics={"f1": 0.91, "tpr": 0.95, "fpr": 0.04},
    )

    assert manifest["split_hygiene"]["prior_source_split"] == TRAIN_SPLIT_NAME
    assert manifest["split_hygiene"]["grid_search_split"] == VALIDATION_SPLIT_NAME
    assert manifest["split_hygiene"]["evaluation_split"] == TEST_SPLIT_NAME
    assert manifest["split_hygiene"]["final_training_splits"] == [TRAIN_SPLIT_NAME, VALIDATION_SPLIT_NAME]
    assert_manifest_split_hygiene(manifest)


def test_manifest_guard_rejects_test_backed_grid_search() -> None:
    """The guardrail should fail fast if the manifest claims test-time tuning."""

    bad_manifest = {
        "split_hygiene": {
            "prior_source_split": TRAIN_SPLIT_NAME,
            "grid_search_split": TEST_SPLIT_NAME,
            "evaluation_split": TEST_SPLIT_NAME,
            "final_training_splits": [TRAIN_SPLIT_NAME, VALIDATION_SPLIT_NAME],
        }
    }

    with pytest.raises(AssertionError):
        assert_manifest_split_hygiene(bad_manifest)
