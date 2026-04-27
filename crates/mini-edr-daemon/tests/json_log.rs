//! Regression tests for the daemon-owned JSON alert and operational logs.
//!
//! These tests lock in the `f5-json-log` contract: alerts persist as single-line
//! JSON records with strict permissions, unsafe reopen targets buffer alerts
//! instead of following symlinks, and clean restarts append to the existing file
//! without truncating prior records.

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
};

use mini_edr_common::{Alert, FeatureVector};
use mini_edr_daemon::HotReloadDaemon;
use onnx_pb::ModelProto;
use prost::Message;
use serde_json::Value;
use tempfile::TempDir;

#[tokio::test]
async fn predict_writes_alert_and_inference_json_logs_with_expected_permissions() {
    let tempdir = TempDir::new().expect("tempdir");
    let config_path = write_logging_config(tempdir.path(), 0.0);
    let daemon = HotReloadDaemon::load_for_tests(&config_path).expect("daemon loads");

    for pid in 10_000..10_050 {
        let _ = daemon
            .predict(&sample_feature_vector(pid))
            .await
            .expect("prediction succeeds");
    }

    let alert_log_path = tempdir.path().join("logs/alerts.jsonl");
    let event_log_path = tempdir.path().join("logs/events.jsonl");
    let daemon_log_path = tempdir.path().join("logs/daemon.log");

    let alert_lines = read_non_empty_lines(&alert_log_path);
    assert_eq!(alert_lines.len(), 50, "expected one alert per prediction");
    let mut previous_timestamp = None;
    for line in &alert_lines {
        let alert = serde_json::from_str::<Alert>(line).expect("alert JSON parses");
        assert!(!alert.summary.contains('\n'));
        assert_eq!(alert.top_features.len(), 5);
        if let Some(previous_timestamp) = previous_timestamp {
            assert!(
                alert.timestamp >= previous_timestamp,
                "alerts.jsonl must serialize timestamps in non-decreasing order"
            );
        }
        previous_timestamp = Some(alert.timestamp);
    }

    let event_lines = read_non_empty_lines(&event_log_path);
    assert_eq!(
        event_lines.len(),
        50,
        "expected one inference log per prediction"
    );
    for line in &event_lines {
        let value = serde_json::from_str::<Value>(line).expect("event JSON parses");
        assert_eq!(value["event_type"], "inference_result");
        assert_eq!(
            value["top_features"].as_array().map(Vec::len),
            Some(5),
            "every inference log must keep the structured top-features array"
        );
    }

    assert_eq!(
        fs::metadata(&alert_log_path)
            .expect("alert log metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&daemon_log_path)
            .expect("daemon log metadata")
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
}

#[tokio::test]
async fn reopen_refuses_symlink_target_and_flushes_buffered_alerts_once_safe_path_returns() {
    let tempdir = TempDir::new().expect("tempdir");
    let config_path = write_logging_config(tempdir.path(), 0.0);
    let daemon = HotReloadDaemon::load_for_tests(&config_path).expect("daemon loads");

    let alert_log_path = tempdir.path().join("logs/alerts.jsonl");
    let daemon_log_path = tempdir.path().join("logs/daemon.log");

    let _ = daemon
        .predict(&sample_feature_vector(20_000))
        .await
        .expect("initial prediction succeeds");
    assert_eq!(read_non_empty_lines(&alert_log_path).len(), 1);

    fs::remove_file(&alert_log_path).expect("remove alert log for symlink swap");
    symlink("/dev/null", &alert_log_path).expect("replace alert log with symlink");
    daemon
        .reopen_logs_for_tests()
        .expect("unsafe reopen should not crash the daemon");

    let _ = daemon
        .predict(&sample_feature_vector(20_001))
        .await
        .expect("buffered prediction succeeds");
    let _ = daemon
        .predict(&sample_feature_vector(20_002))
        .await
        .expect("second buffered prediction succeeds");

    fs::remove_file(&alert_log_path).expect("remove unsafe symlink");
    daemon
        .reopen_logs_for_tests()
        .expect("safe reopen should flush buffered alerts");
    let _ = daemon
        .predict(&sample_feature_vector(20_003))
        .await
        .expect("post-reopen prediction succeeds");

    let alert_lines = read_non_empty_lines(&alert_log_path);
    assert_eq!(
        alert_lines.len(),
        3,
        "the two alerts written while the path was unsafe must be flushed once the path is safe again, alongside the first safe post-reopen alert"
    );

    let daemon_log = fs::read_to_string(&daemon_log_path).expect("daemon log");
    assert!(
        daemon_log.contains("log_target_unsafe"),
        "unsafe reopen attempts must be recorded in the daemon operational log"
    );
}

#[tokio::test]
async fn reopen_failure_closes_old_fd_logs_error_and_flushes_buffered_alerts_after_recovery() {
    let tempdir = TempDir::new().expect("tempdir");
    let config_path = write_logging_config(tempdir.path(), 0.0);
    let daemon = HotReloadDaemon::load_for_tests(&config_path).expect("daemon loads");

    let alert_log_path = tempdir.path().join("logs/alerts.jsonl");
    let rotated_log_path = tempdir.path().join("logs/alerts.jsonl.1");
    let daemon_log_path = tempdir.path().join("logs/daemon.log");
    let log_directory = tempdir.path().join("logs");

    let _ = daemon
        .predict(&sample_feature_vector(21_000))
        .await
        .expect("initial prediction succeeds");
    fs::rename(&alert_log_path, &rotated_log_path).expect("rename alert log for rotation");
    let rotated_size_before_failure = fs::metadata(&rotated_log_path)
        .expect("rotated log metadata")
        .len();

    let writable_permissions = fs::metadata(&log_directory)
        .expect("log directory metadata")
        .permissions();
    let mut read_only_permissions = writable_permissions.clone();
    read_only_permissions.set_mode(0o500);
    fs::set_permissions(&log_directory, read_only_permissions)
        .expect("make log directory read-only");

    daemon
        .reopen_logs_for_tests()
        .expect("rotation failure should be downgraded to an operational error");
    let _ = daemon
        .predict(&sample_feature_vector(21_001))
        .await
        .expect("prediction should stay alive while alerts are buffered");

    assert_eq!(
        fs::metadata(&rotated_log_path)
            .expect("rotated log metadata after failed reopen")
            .len(),
        rotated_size_before_failure,
        "failed rotation must close the old descriptor so the renamed file stops growing"
    );
    assert!(
        !alert_log_path.exists(),
        "the daemon must not recreate the alert path while the directory is read-only"
    );

    fs::set_permissions(&log_directory, writable_permissions)
        .expect("restore log directory permissions");
    daemon
        .reopen_logs_for_tests()
        .expect("recovered reopen flushes buffered alerts");
    let _ = daemon
        .predict(&sample_feature_vector(21_002))
        .await
        .expect("post-recovery prediction succeeds");

    let alert_lines = read_non_empty_lines(&alert_log_path);
    assert_eq!(
        alert_lines.len(),
        2,
        "the buffered alert plus the first post-recovery alert should land in the recovered file"
    );

    let daemon_log = fs::read_to_string(&daemon_log_path).expect("daemon log");
    assert!(
        daemon_log.contains("log_rotate_failed"),
        "rotation failures must be recorded in the daemon operational log"
    );
}

#[tokio::test]
async fn append_only_alert_log_survives_restart_without_truncating_prior_records() {
    let tempdir = TempDir::new().expect("tempdir");
    let config_path = write_logging_config(tempdir.path(), 0.0);
    let alert_log_path = tempdir.path().join("logs/alerts.jsonl");

    let daemon = HotReloadDaemon::load_for_tests(&config_path).expect("daemon loads");
    for pid in 30_000..30_100 {
        let _ = daemon
            .predict(&sample_feature_vector(pid))
            .await
            .expect("first-run prediction succeeds");
    }

    let first_snapshot = fs::read(&alert_log_path).expect("first alert snapshot");
    let first_metadata = fs::metadata(&alert_log_path).expect("first metadata");
    let first_inode = first_metadata.ino();
    let first_mtime = (first_metadata.mtime(), first_metadata.mtime_nsec());

    let restarted = HotReloadDaemon::load_for_tests(&config_path).expect("daemon reloads");
    for pid in 40_000..40_100 {
        let _ = restarted
            .predict(&sample_feature_vector(pid))
            .await
            .expect("second-run prediction succeeds");
    }

    let combined_lines = read_non_empty_lines(&alert_log_path);
    assert_eq!(
        combined_lines.len(),
        200,
        "restart must append, not truncate"
    );
    assert_eq!(
        &fs::read(&alert_log_path).expect("combined alert snapshot")[..first_snapshot.len()],
        first_snapshot.as_slice(),
        "the first 100 records must remain byte-identical after restart"
    );
    let second_metadata = fs::metadata(&alert_log_path).expect("second metadata");
    assert_eq!(second_metadata.ino(), first_inode);
    assert!(
        (second_metadata.mtime(), second_metadata.mtime_nsec()) >= first_mtime,
        "mtime should not move backwards across the append-only restart path"
    );

    let mut alert_ids = combined_lines
        .iter()
        .map(|line| {
            serde_json::from_str::<Alert>(line)
                .expect("alert parses")
                .alert_id
        })
        .collect::<Vec<_>>();
    alert_ids.sort_unstable();
    alert_ids.dedup();
    assert_eq!(
        alert_ids.len(),
        200,
        "alert IDs must stay unique across restart"
    );
}

fn write_logging_config(tempdir: &Path, threshold: f64) -> PathBuf {
    let config_path = tempdir.join("config.toml");
    let model_path = copy_model(trained_model_path(), tempdir.join("model.onnx"));
    fs::write(
        &config_path,
        format!(
            "alert_threshold = {threshold}\nweb_port = 0\nmodel_path = \"{}\"\nlog_file_path = \"alerts.jsonl\"\n",
            model_path.display()
        ),
    )
    .expect("write config");
    config_path
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

#[allow(dead_code)]
fn mutate_model_hash(source: &Path, destination: PathBuf) -> PathBuf {
    let mut model =
        ModelProto::decode(fs::read(source).expect("read model").as_slice()).expect("decode ONNX");
    "mini-edr-json-log-v2".clone_into(&mut model.producer_name);
    let mut encoded = Vec::with_capacity(model.encoded_len());
    model.encode(&mut encoded).expect("encode ONNX");
    fs::write(&destination, encoded).expect("write mutated ONNX");
    destination
}

fn read_non_empty_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .expect("read log file")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn sample_feature_vector(pid: u32) -> FeatureVector {
    let mut bigrams = BTreeMap::new();
    bigrams.insert("__process_positive_rate__".to_owned(), 0.65);
    bigrams.insert("__event_positive_rate__".to_owned(), 0.15);

    let mut trigrams = BTreeMap::new();
    trigrams.insert("__path_positive_rate__".to_owned(), 0.35);

    FeatureVector {
        pid,
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
