//! Integration tests for the detection inference engine.
//!
//! These tests exercise the concrete startup, degraded-mode, corruption
//! rejection, score-bound, determinism, and reload behaviors that the mission's
//! detection milestone assigns to the inference crate.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use mini_edr_common::FeatureVector;
use mini_edr_detection::{
    InferenceError, InferenceModel, LoadFailureKind, ModelBackend, ModelManager, ModelStatus,
    OnnxModel, XgboostModel,
};
use onnx_pb::ModelProto;
use onnx_pb::{tensor_shape_proto, type_proto};
use prost::Message;
use rand::{Rng, SeedableRng, rngs::StdRng};
use tempfile::TempDir;

#[test]
fn startup_loads_valid_onnx_model_and_scores_sample_vector() {
    let model_path = trained_model_path();

    let manager = ModelManager::load_at_startup(&model_path, ModelBackend::OnnxRuntime);
    assert!(matches!(manager.status(), ModelStatus::Running { .. }));

    let result = manager
        .predict(&sample_feature_vector())
        .expect("model scores sample");
    assert!(
        (0.0..=1.0).contains(&result.threat_score),
        "threat scores must stay inside the inclusive contract"
    );
    assert!(
        !result.feature_importances.is_empty(),
        "predict() must return deterministic feature importance entries"
    );
}

#[test]
fn missing_model_path_enters_degraded_mode_without_panicking() {
    let manager = ModelManager::load_at_startup(
        Path::new("/definitely/missing/model.onnx"),
        ModelBackend::OnnxRuntime,
    );

    match manager.status() {
        ModelStatus::Degraded { failure_kind, .. } => {
            assert_eq!(failure_kind, LoadFailureKind::ModelPathMissing);
        }
        status @ ModelStatus::Running { .. } => {
            panic!("expected degraded startup state, got {status:?}");
        }
    }

    let error = manager
        .predict(&sample_feature_vector())
        .expect_err("degraded mode must skip scoring");
    assert!(matches!(
        error,
        InferenceError::DegradedMode {
            failure_kind: LoadFailureKind::ModelPathMissing,
            ..
        }
    ));
}

#[test]
fn malformed_model_variants_are_rejected_at_load_time() {
    let tempdir = TempDir::new().expect("tempdir");
    let valid_model = trained_model_path();

    let truncated = tempdir.path().join("truncated.onnx");
    let mut bytes = fs::read(&valid_model).expect("read valid model");
    bytes.truncate(bytes.len() / 2);
    fs::write(&truncated, bytes).expect("write truncated model");

    let wrong_opset = tempdir.path().join("wrong-opset.onnx");
    let mut wrong_opset_model = load_model_proto(&valid_model);
    let opset = wrong_opset_model
        .opset_import
        .iter_mut()
        .find(|entry| entry.domain == "ai.onnx.ml")
        .expect("model contains ai.onnx.ml opset");
    opset.version = 9;
    fs::write(&wrong_opset, encode_model_proto(&wrong_opset_model))
        .expect("write mutated opset model");

    let wrong_shape = tempdir.path().join("wrong-shape.onnx");
    let mut wrong_shape_model = load_model_proto(&valid_model);
    let input = wrong_shape_model
        .graph
        .as_mut()
        .expect("graph")
        .input
        .first_mut()
        .expect("one input");
    let shape = input
        .r#type
        .as_mut()
        .and_then(|input_type| input_type.value.as_mut())
        .and_then(|value| match value {
            type_proto::Value::TensorType(tensor_type) => tensor_type.shape.as_mut(),
            _ => None,
        })
        .expect("input has tensor shape");
    shape.dim.clear();
    shape.dim.push(tensor_shape_proto::Dimension {
        denotation: String::new(),
        value: Some(tensor_shape_proto::dimension::Value::DimParam(
            "batch".to_owned(),
        )),
    });
    shape.dim.push(tensor_shape_proto::Dimension {
        denotation: String::new(),
        value: Some(tensor_shape_proto::dimension::Value::DimValue(99)),
    });
    fs::write(&wrong_shape, encode_model_proto(&wrong_shape_model))
        .expect("write wrong shape model");

    assert_rejected_with_kind(&truncated, LoadFailureKind::ModelTruncated);
    assert_rejected_with_kind(&wrong_opset, LoadFailureKind::OpsetUnsupported);
    assert_rejected_with_kind(&wrong_shape, LoadFailureKind::TensorShapeInvalid);

    for (path, expected_kind) in [
        (&truncated, LoadFailureKind::ModelTruncated),
        (&wrong_opset, LoadFailureKind::OpsetUnsupported),
        (&wrong_shape, LoadFailureKind::TensorShapeInvalid),
    ] {
        let manager = ModelManager::load_at_startup(path, ModelBackend::OnnxRuntime);
        match manager.status() {
            ModelStatus::Degraded { failure_kind, .. } => assert_eq!(failure_kind, expected_kind),
            status @ ModelStatus::Running { .. } => {
                panic!("expected degraded status for {path:?}, got {status:?}");
            }
        }
    }
}

#[test]
fn onnx_and_xgboost_models_are_bounded_and_deterministic_for_ten_thousand_vectors() {
    let model_path = trained_model_path();
    let onnx_model = OnnxModel::load(&model_path).expect("onnx model loads");
    let xgboost_model = XgboostModel::load(&model_path).expect("xgboost-equivalent model loads");
    let mut rng = StdRng::seed_from_u64(0x5EED_F00D_u64);

    for _ in 0..10_000 {
        let vector = random_feature_vector(&mut rng);

        let onnx_first = onnx_model
            .predict(&vector)
            .expect("onnx prediction succeeds");
        let onnx_second = onnx_model
            .predict(&vector)
            .expect("onnx prediction is deterministic");
        assert!(
            approx_equal(onnx_first.threat_score, onnx_second.threat_score),
            "same input must yield the same score"
        );
        assert!((0.0..=1.0).contains(&onnx_first.threat_score));

        let xgboost_first = xgboost_model
            .predict(&vector)
            .expect("xgboost-equivalent prediction succeeds");
        let xgboost_second = xgboost_model
            .predict(&vector)
            .expect("xgboost-equivalent prediction is deterministic");
        assert!(approx_equal(
            xgboost_first.threat_score,
            xgboost_second.threat_score
        ));
        assert!((0.0..=1.0).contains(&xgboost_first.threat_score));

        let delta = (onnx_first.threat_score - xgboost_first.threat_score).abs();
        assert!(
            delta <= 1.0e-6,
            "runtime and equivalent tree-evaluator scores diverged by {delta}"
        );
    }
}

#[test]
fn reload_promotes_degraded_manager_and_rejects_bad_swap_without_losing_live_model() {
    let valid_path = trained_model_path();
    let manager = ModelManager::load_at_startup(
        Path::new("/definitely/missing/model.onnx"),
        ModelBackend::OnnxRuntime,
    );
    assert!(matches!(manager.status(), ModelStatus::Degraded { .. }));

    manager
        .reload(&valid_path)
        .expect("reload promotes degraded startup");
    let after_recovery = manager
        .predict(&sample_feature_vector())
        .expect("recovered model scores");
    assert!(matches!(manager.status(), ModelStatus::Running { .. }));

    let tempdir = TempDir::new().expect("tempdir");
    let truncated = tempdir.path().join("truncated.onnx");
    let mut bytes = fs::read(&valid_path).expect("read valid model");
    bytes.truncate(bytes.len() / 2);
    fs::write(&truncated, bytes).expect("write truncated model");

    let error = manager
        .reload(&truncated)
        .expect_err("bad reload must keep the existing live model");
    assert_eq!(error.failure_kind(), LoadFailureKind::ModelTruncated);
    assert!(matches!(manager.status(), ModelStatus::Running { .. }));

    let after_failed_reload = manager
        .predict(&sample_feature_vector())
        .expect("live model survives");
    assert!(
        approx_equal(
            after_recovery.threat_score,
            after_failed_reload.threat_score
        ),
        "failed reloads must not perturb the already-live model"
    );
}

#[test]
fn missing_model_reload_keeps_the_live_model_snapshot_unchanged() {
    let valid_path = trained_model_path();
    let manager = ModelManager::load_at_startup(&valid_path, ModelBackend::OnnxRuntime);
    let before_status = manager.status();
    let before_prediction = manager
        .predict(&sample_feature_vector())
        .expect("baseline prediction succeeds");

    let missing_path = Path::new("/definitely/missing/reload-model.onnx");
    let error = manager
        .reload(missing_path)
        .expect_err("missing reload candidate must keep the existing live model");
    assert_eq!(error.failure_kind(), LoadFailureKind::ModelPathMissing);
    assert_eq!(manager.status(), before_status);

    let after_prediction = manager
        .predict(&sample_feature_vector())
        .expect("live model survives missing-path reload");
    assert_eq!(after_prediction.model_hash, before_prediction.model_hash);
    assert!(
        approx_equal(
            before_prediction.threat_score,
            after_prediction.threat_score
        ),
        "missing-path reloads must not perturb the already-live model"
    );
}

fn trained_model_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../training/output/model.onnx")
        .canonicalize()
        .expect("training output model exists")
}

fn load_model_proto(model_path: &Path) -> ModelProto {
    ModelProto::decode(fs::read(model_path).expect("read model bytes").as_slice())
        .expect("model bytes parse as ONNX protobuf")
}

fn encode_model_proto(model: &ModelProto) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(model.encoded_len());
    model.encode(&mut encoded).expect("model proto encodes");
    encoded
}

fn assert_rejected_with_kind(model_path: &Path, expected_kind: LoadFailureKind) {
    match OnnxModel::load(model_path) {
        Ok(_) => panic!("expected {} to be rejected", model_path.display()),
        Err(error) => assert_eq!(error.failure_kind(), expected_kind),
    }
}

fn approx_equal(left: f64, right: f64) -> bool {
    (left - right).abs() <= f64::EPSILON
}

fn sample_feature_vector() -> FeatureVector {
    let mut bigrams = BTreeMap::new();
    bigrams.insert("__process_positive_rate__".to_owned(), 0.95);
    bigrams.insert("__event_positive_rate__".to_owned(), 0.30);

    let mut trigrams = BTreeMap::new();
    trigrams.insert("__path_positive_rate__".to_owned(), 0.80);

    FeatureVector {
        pid: 4_242,
        window_start_ns: 1_713_000_000_000_000_000,
        window_end_ns: 1_713_000_005_000_000_000,
        total_syscalls: 128,
        execve_count: 1,
        openat_count: 100,
        connect_count: 3,
        clone_count: 2,
        execve_ratio: 0.007_812_5,
        openat_ratio: 0.781_25,
        connect_ratio: 0.023_437_5,
        clone_ratio: 0.015_625,
        bigrams,
        trigrams,
        path_entropy: 1.5,
        unique_ips: 2,
        unique_files: 12,
        child_spawn_count: 2,
        avg_inter_syscall_time_ns: 1_500_000.0,
        min_inter_syscall_time_ns: 10_000.0,
        max_inter_syscall_time_ns: 9_000_000.0,
        stddev_inter_syscall_time_ns: 500_000.0,
        wrote_etc: true,
        wrote_tmp: true,
        wrote_dev: false,
        read_sensitive_file_count: 4,
        write_sensitive_file_count: 2,
        outbound_connection_count: 3,
        loopback_connection_count: 1,
        distinct_ports: 2,
        failed_syscall_count: 1,
        short_lived: false,
        window_duration_ns: 5_000_000_000,
        events_per_second: 25.6,
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "The test fixture deliberately exercises large integer counters and timestamps that the real model encoder later narrows into floating-point tensors."
)]
fn random_feature_vector(rng: &mut StdRng) -> FeatureVector {
    let total_syscalls = rng.gen_range(1_u64..=10_000);
    let execve_count = rng.gen_range(0..=total_syscalls);
    let remaining_after_execve = total_syscalls - execve_count;
    let openat_count = rng.gen_range(0..=remaining_after_execve);
    let remaining_after_openat = remaining_after_execve - openat_count;
    let connect_count = rng.gen_range(0..=remaining_after_openat);
    let clone_count = total_syscalls - execve_count - openat_count - connect_count;

    let window_start_ns = rng.gen_range(1_700_000_000_000_000_000_u64..1_900_000_000_000_000_000);
    let window_duration_ns = rng.gen_range(1_u64..=120_000_000_000);
    let window_end_ns = window_start_ns + window_duration_ns;

    let mut bigrams = BTreeMap::new();
    bigrams.insert(
        "__process_positive_rate__".to_owned(),
        rng.gen_range(0.0..=1.0),
    );
    bigrams.insert(
        "__event_positive_rate__".to_owned(),
        rng.gen_range(0.0..=1.0),
    );

    let mut trigrams = BTreeMap::new();
    trigrams.insert(
        "__path_positive_rate__".to_owned(),
        rng.gen_range(0.0..=1.0),
    );

    FeatureVector {
        pid: rng.gen_range(1_u32..=u32::MAX - 1),
        window_start_ns,
        window_end_ns,
        total_syscalls,
        execve_count,
        openat_count,
        connect_count,
        clone_count,
        execve_ratio: execve_count as f64 / total_syscalls as f64,
        openat_ratio: openat_count as f64 / total_syscalls as f64,
        connect_ratio: connect_count as f64 / total_syscalls as f64,
        clone_ratio: clone_count as f64 / total_syscalls as f64,
        bigrams,
        trigrams,
        path_entropy: rng.gen_range(0.0..=8.0),
        unique_ips: rng.gen_range(0_u64..=128),
        unique_files: rng.gen_range(0_u64..=2_048),
        child_spawn_count: rng.gen_range(0_u64..=128),
        avg_inter_syscall_time_ns: rng.gen_range(0.0..=1_000_000_000.0),
        min_inter_syscall_time_ns: rng.gen_range(0.0..=10_000_000.0),
        max_inter_syscall_time_ns: rng.gen_range(10_000_000.0..=5_000_000_000.0),
        stddev_inter_syscall_time_ns: rng.gen_range(0.0..=500_000_000.0),
        wrote_etc: rng.gen_bool(0.1),
        wrote_tmp: rng.gen_bool(0.4),
        wrote_dev: rng.gen_bool(0.05),
        read_sensitive_file_count: rng.gen_range(0_u64..=128),
        write_sensitive_file_count: rng.gen_range(0_u64..=64),
        outbound_connection_count: rng.gen_range(0_u64..=128),
        loopback_connection_count: rng.gen_range(0_u64..=32),
        distinct_ports: rng.gen_range(0_u64..=32),
        failed_syscall_count: rng.gen_range(0_u64..=total_syscalls),
        short_lived: rng.gen_bool(0.2),
        window_duration_ns,
        events_per_second: total_syscalls as f64 / (window_duration_ns as f64 / 1_000_000_000.0),
    }
}
