//! Regression coverage for the checked-in threshold fixtures.
//!
//! The production daemon must emit the model's raw score. These tests pin the
//! checked-in fixture payloads to their documented natural score bands so
//! future changes cannot silently reintroduce score remapping.

mod support;

use std::path::{Path, PathBuf};

use mini_edr_common::FeatureVector;
use mini_edr_detection::{InferenceModel, OnnxModel};

use crate::support::{
    assert_score_in_documented_band, load_threshold_fixture_contracts, threshold_fixture_payload,
};

#[test]
fn threshold_fixtures_score_inside_documented_bands() {
    let model = OnnxModel::load(&trained_model_path()).expect("onnx model loads");
    let contracts = load_threshold_fixture_contracts();

    for fixture_name in [
        "high_085",
        "exact_threshold",
        "below_threshold",
        "threshold_065",
    ] {
        let payload: FeatureVector = serde_json::from_str(&threshold_fixture_payload(fixture_name))
            .unwrap_or_else(|error| panic!("parse fixture `{fixture_name}` JSON: {error}"));
        let result = model
            .predict(&payload)
            .unwrap_or_else(|error| panic!("score fixture `{fixture_name}`: {error}"));
        assert_score_in_documented_band(fixture_name, result.threat_score);

        let contract = contracts
            .get(fixture_name)
            .unwrap_or_else(|| panic!("missing contract entry for `{fixture_name}`"));
        assert!(
            (result.threat_score - contract.natural_score).abs() <= 1.0e-6,
            "fixture `{fixture_name}` drifted away from its documented natural score"
        );
    }
}

fn trained_model_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../training/output/model.onnx")
        .canonicalize()
        .expect("training output model exists")
}
