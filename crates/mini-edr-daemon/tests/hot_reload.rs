//! Regression tests for daemon-owned SIGHUP hot reload behavior.
//!
//! These tests lock in the feature contract for `f4-hot-reload`: valid model
//! swaps become visible on subsequent inferences, invalid candidates roll back
//! without a state transition, out-of-range thresholds are rejected, and
//! partial config writes are retried until the writer closes the file.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use mini_edr_common::FeatureVector;
use mini_edr_daemon::{DaemonLifecycleState, HotReloadDaemon, ReloadOutcome};
use onnx_pb::ModelProto;
use prost::Message;
use tempfile::TempDir;

#[tokio::test]
async fn valid_reload_swaps_model_hash_and_updates_threshold_for_new_predictions() {
    let tempdir = TempDir::new().expect("tempdir");
    let model_v1 = copy_model(trained_model_path(), tempdir.path().join("model-v1.onnx"));
    let model_v2 = mutate_model_hash(&model_v1, tempdir.path().join("model-v2.onnx"));
    let config_path = tempdir.path().join("config.toml");
    write_config(&config_path, &model_v1, 1.0);

    let daemon = HotReloadDaemon::load_for_tests(&config_path).expect("daemon loads");
    let before = daemon
        .predict(&sample_feature_vector())
        .await
        .expect("prediction succeeds");
    assert!(before.model_hash.len() >= 32);
    assert!(approx_equal(before.threshold, 1.0));
    assert!(
        before.threat_score < 1.0,
        "the fixture should stay strictly below the maximum threshold so a later lower threshold changes the alert decision"
    );
    assert!(!before.would_alert);
    let reloaded_threshold = (before.threat_score - 0.05).max(0.0);

    write_config(&config_path, &model_v2, reloaded_threshold);
    let outcome = daemon.reload_once().expect("reload finishes");
    assert!(matches!(outcome, ReloadOutcome::Applied { .. }));

    let after = daemon
        .predict(&sample_feature_vector())
        .await
        .expect("prediction succeeds after reload");
    assert_ne!(after.model_hash, before.model_hash);
    assert!(approx_equal(after.threshold, reloaded_threshold));
    assert!(after.would_alert);

    let health = daemon.health_snapshot();
    assert_eq!(health.state, DaemonLifecycleState::Running);
    assert!(
        health
            .state_history
            .iter()
            .any(|transition| transition.state == DaemonLifecycleState::Reloading),
        "successful reloads must surface the Running -> Reloading -> Running history"
    );
}

#[tokio::test]
async fn invalid_model_rolls_back_without_state_transition_or_hash_change() {
    let tempdir = TempDir::new().expect("tempdir");
    let model_v1 = copy_model(trained_model_path(), tempdir.path().join("model-v1.onnx"));
    let bad_model = tempdir.path().join("model-bad.onnx");
    fs::write(&bad_model, b"not-a-valid-onnx-model").expect("write bad model");
    let config_path = tempdir.path().join("config.toml");
    write_config(&config_path, &model_v1, 1.0);

    let daemon = HotReloadDaemon::load_for_tests(&config_path).expect("daemon loads");
    let before_health = daemon.health_snapshot();

    write_config(&config_path, &bad_model, 0.7);
    let outcome = daemon
        .reload_once()
        .expect("reload returns rollback outcome");
    assert!(matches!(outcome, ReloadOutcome::RejectedModel { .. }));

    let after_health = daemon.health_snapshot();
    assert_eq!(after_health.state, DaemonLifecycleState::Running);
    assert_eq!(after_health.model_hash, before_health.model_hash);
    assert_eq!(
        after_health.state_history, before_health.state_history,
        "invalid model candidates must not append a Reloading transition"
    );
}

#[tokio::test]
async fn invalid_threshold_is_rejected_and_previous_value_is_retained() {
    let tempdir = TempDir::new().expect("tempdir");
    let model_v1 = copy_model(trained_model_path(), tempdir.path().join("model-v1.onnx"));
    let config_path = tempdir.path().join("config.toml");
    write_config(&config_path, &model_v1, 1.0);

    let daemon = HotReloadDaemon::load_for_tests(&config_path).expect("daemon loads");

    write_config(&config_path, &model_v1, 2.0);
    let outcome = daemon
        .reload_once()
        .expect("reload returns threshold rejection");
    assert!(
        matches!(
            outcome,
            ReloadOutcome::RejectedThreshold { retained_threshold, attempted_threshold }
                if (retained_threshold - 1.0).abs() <= f64::EPSILON
                    && (attempted_threshold - 2.0).abs() <= f64::EPSILON
        ),
        "unexpected reload outcome: {outcome:?}"
    );

    let prediction = daemon
        .predict(&sample_feature_vector())
        .await
        .expect("prediction succeeds");
    assert!(approx_equal(prediction.threshold, 1.0));
}

#[tokio::test]
async fn partial_config_write_retries_until_the_final_file_closes() {
    let tempdir = TempDir::new().expect("tempdir");
    let model_v1 = copy_model(trained_model_path(), tempdir.path().join("model-v1.onnx"));
    let model_v2 = mutate_model_hash(&model_v1, tempdir.path().join("model-v2.onnx"));
    let config_path = tempdir.path().join("config.toml");
    write_config(&config_path, &model_v1, 0.7);

    let daemon = HotReloadDaemon::load_for_tests(&config_path).expect("daemon loads");

    let final_config = config_contents(&model_v2, 0.6);
    fs::write(&config_path, "alert_threshold = ").expect("write partial config");
    let writer_path = config_path.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(25));
        fs::write(&writer_path, final_config).expect("finish config write");
    });

    let outcome = daemon
        .reload_until_stable(Duration::from_millis(5), 20)
        .await
        .expect("reload eventually succeeds");
    assert!(matches!(outcome, ReloadOutcome::Applied { .. }));

    let prediction = daemon
        .predict(&sample_feature_vector())
        .await
        .expect("prediction succeeds after retry");
    assert!(approx_equal(prediction.threshold, 0.6));

    let health = daemon.health_snapshot();
    assert!(
        health.config_reload_partial_total > 0,
        "partial writes must increment the transient-reload counter"
    );
    assert_eq!(health.config_reload_success_total, 1);
}

fn trained_model_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../training/output/model.onnx")
        .canonicalize()
        .expect("training output model exists")
}

fn copy_model(source: PathBuf, destination: PathBuf) -> PathBuf {
    fs::copy(source, &destination).expect("copy model");
    destination
}

fn mutate_model_hash(source: &Path, destination: PathBuf) -> PathBuf {
    let mut model =
        ModelProto::decode(fs::read(source).expect("read model").as_slice()).expect("decode ONNX");
    "mini-edr-hot-reload-v2".clone_into(&mut model.producer_name);
    let mut encoded = Vec::with_capacity(model.encoded_len());
    model.encode(&mut encoded).expect("encode ONNX");
    fs::write(&destination, encoded).expect("write mutated model");
    destination
}

fn write_config(config_path: &Path, model_path: &Path, threshold: f64) {
    fs::write(config_path, config_contents(model_path, threshold)).expect("write config");
}

fn config_contents(model_path: &Path, threshold: f64) -> String {
    format!(
        "alert_threshold = {threshold}\nweb_port = 0\nmodel_path = \"{}\"\nlog_file_path = \"alerts.json\"\n",
        model_path.display()
    )
}

fn sample_feature_vector() -> FeatureVector {
    let mut bigrams = BTreeMap::new();
    bigrams.insert("__process_positive_rate__".to_owned(), 0.65);
    bigrams.insert("__event_positive_rate__".to_owned(), 0.15);

    let mut trigrams = BTreeMap::new();
    trigrams.insert("__path_positive_rate__".to_owned(), 0.35);

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

fn approx_equal(left: f64, right: f64) -> bool {
    (left - right).abs() <= f64::EPSILON
}
