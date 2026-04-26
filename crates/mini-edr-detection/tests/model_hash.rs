//! Regression test for per-inference model-hash traceability.

use std::path::{Path, PathBuf};

use mini_edr_detection::{InferenceModel, OnnxModel};

mod shared;

#[test]
fn inference_result_carries_the_model_hash_used_for_scoring() {
    let model = OnnxModel::load(&trained_model_path()).expect("onnx model loads");
    let result = model
        .predict(&shared::sample_feature_vector())
        .expect("prediction succeeds");
    assert_eq!(
        result.model_hash,
        model.model_hash(),
        "each inference result must report the artifact hash that produced it"
    );
}

fn trained_model_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../training/output/model.onnx")
        .canonicalize()
        .expect("training output model exists")
}
