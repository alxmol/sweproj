"""Schema-parity tests for the Mini-EDR training pipeline."""

from __future__ import annotations

from pathlib import Path

from training.feature_engineering import rust_feature_vector_fields
from training.schema import BIGRAM_PRIOR_KEYS, SCALAR_FEATURE_NAMES, TRIGRAM_PRIOR_KEYS, feature_manifest


def test_scalar_schema_matches_rust_feature_vector() -> None:
    """The trainer's scalar field list must track the Rust ``FeatureVector``."""

    rust_source = Path('crates/mini-edr-common/src/lib.rs').read_text(encoding='utf-8')
    rust_fields = [
        field for field in rust_feature_vector_fields(rust_source) if field not in {'bigrams', 'trigrams'}
    ]
    assert rust_fields == SCALAR_FEATURE_NAMES


def test_sparse_prior_keys_stay_namespaced_under_existing_map_fields() -> None:
    """Extra trainer features must stay inside ``bigrams`` / ``trigrams`` names."""

    manifest = feature_manifest()
    for key in BIGRAM_PRIOR_KEYS:
        assert f'bigrams.{key}' in manifest
    for key in TRIGRAM_PRIOR_KEYS:
        assert f'trigrams.{key}' in manifest


def test_feature_manifest_width_is_stable() -> None:
    """The exported ONNX input width should stay deterministic for validators."""

    manifest = feature_manifest()
    assert len(manifest) == len(SCALAR_FEATURE_NAMES) + len(BIGRAM_PRIOR_KEYS) + len(TRIGRAM_PRIOR_KEYS)
