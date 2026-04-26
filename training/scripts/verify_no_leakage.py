"""Verify that the persisted Mini-EDR training artifacts honor split hygiene."""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    import onnx
except ModuleNotFoundError:
    fallback_python = REPO_ROOT / "crates/mini-edr-detection/training/.venv/bin/python"
    os.execv(str(fallback_python), [str(fallback_python), __file__, *sys.argv[1:]])

from training.feature_engineering import (  # noqa: E402
    collect_split_token_sets,
    load_beth_split,
    load_prior_catalog,
)
from training.scripts.evaluate_holdout import evaluate_holdout  # noqa: E402
from training.split_hygiene import (  # noqa: E402
    TEST_SPLIT_NAME,
    TRAIN_SPLIT_NAME,
    assert_manifest_split_hygiene,
    sha256_file,
)


def verify_no_leakage(
    *,
    beth_dir: Path,
    model_path: Path,
    prior_catalog_path: Path,
    metrics_path: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    """Run split-hygiene checks against the saved training artifacts.

    Args:
        beth_dir: Directory containing the labelled BETH CSV splits.
        model_path: Exported ONNX artifact.
        prior_catalog_path: Train-only prior catalog JSON.
        metrics_path: Saved held-out metrics JSON.
        manifest_path: Saved training manifest JSON.

    Returns:
        JSON-serializable summary of every assertion that passed.
    """

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    raw_prior_catalog = json.loads(prior_catalog_path.read_text(encoding="utf-8"))
    prior_catalog = load_prior_catalog(prior_catalog_path)
    assert_manifest_split_hygiene(manifest)
    assert raw_prior_catalog["source_split"] == TRAIN_SPLIT_NAME
    assert raw_prior_catalog["label_mapping"] == manifest["label_mapping"]["expression"]

    training = load_beth_split(beth_dir / TRAIN_SPLIT_NAME)
    testing = load_beth_split(beth_dir / TEST_SPLIT_NAME)
    train_tokens = collect_split_token_sets(training)
    test_tokens = collect_split_token_sets(testing)

    test_only_processes = test_tokens["process_name"] - train_tokens["process_name"]
    test_only_events = test_tokens["event_name"] - train_tokens["event_name"]
    test_only_paths = test_tokens["path_prefix"] - train_tokens["path_prefix"]

    assert set(prior_catalog.process_positive_rate).issubset(train_tokens["process_name"])
    assert set(prior_catalog.event_positive_rate).issubset(train_tokens["event_name"])
    assert set(prior_catalog.path_positive_rate).issubset(train_tokens["path_prefix"])
    assert set(prior_catalog.process_positive_rate).isdisjoint(test_only_processes)
    assert set(prior_catalog.event_positive_rate).isdisjoint(test_only_events)
    assert set(prior_catalog.path_positive_rate).isdisjoint(test_only_paths)

    saved_model_sha = manifest["artifacts"]["model"]["sha256"]
    assert sha256_file(model_path) == saved_model_sha

    # Load the ONNX artifact so this script still inspects the deployed model
    # rather than trusting only the manifest text.
    onnx_model = onnx.load(str(model_path))
    assert onnx_model.graph.node, "saved model.onnx is unexpectedly empty"

    reproduced_metrics = evaluate_holdout(
        model_path,
        beth_dir,
        prior_catalog_path,
        threshold=float(metrics["threshold"]),
    )
    for key in ("f1", "tpr", "fpr"):
        assert math.isclose(float(reproduced_metrics[key]), float(metrics[key]), rel_tol=0.0, abs_tol=1e-12)
    for key in ("tp", "tn", "fp", "fn"):
        assert int(reproduced_metrics[key]) == int(metrics[key])

    return {
        "manifest_split_hygiene": manifest["split_hygiene"],
        "label_mapping": manifest["label_mapping"],
        "model_sha256": saved_model_sha,
        "prior_catalog": {
            "path": str(prior_catalog_path),
            "source_split": raw_prior_catalog["source_split"],
            "process_token_count": len(prior_catalog.process_positive_rate),
            "event_token_count": len(prior_catalog.event_positive_rate),
            "path_token_count": len(prior_catalog.path_positive_rate),
        },
        "test_only_tokens": {
            "process_name_count": len(test_only_processes),
            "event_name_count": len(test_only_events),
            "path_prefix_count": len(test_only_paths),
        },
        "reproduced_metrics": {
            "f1": reproduced_metrics["f1"],
            "tpr": reproduced_metrics["tpr"],
            "fpr": reproduced_metrics["fpr"],
        },
    }


def main() -> None:
    """CLI entrypoint used by the feature verification step."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--beth-dir", type=Path, default=REPO_ROOT / "beth/archive")
    parser.add_argument("--model", type=Path, default=REPO_ROOT / "training/output/model.onnx")
    parser.add_argument(
        "--prior-catalog",
        type=Path,
        default=REPO_ROOT / "training/output/prior_catalog.json",
    )
    parser.add_argument("--metrics", type=Path, default=REPO_ROOT / "training/output/metrics.json")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=REPO_ROOT / "training/output/training_manifest.json",
    )
    args = parser.parse_args()

    summary = verify_no_leakage(
        beth_dir=args.beth_dir,
        model_path=args.model,
        prior_catalog_path=args.prior_catalog,
        metrics_path=args.metrics,
        manifest_path=args.manifest,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
