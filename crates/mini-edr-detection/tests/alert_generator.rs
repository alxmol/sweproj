//! Integration tests for alert generation semantics and payload shaping.
//!
//! These tests lock down the detection-milestone contract around threshold
//! comparisons, alert payload completeness, per-inference debug logging, alert
//! ID monotonicity, and output sanitization.

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use mini_edr_common::{
    EnrichedEvent, FeatureContribution, FeatureVector, ProcessInfo, SyscallEvent, SyscallType,
};
use mini_edr_detection::{
    AlertGenerationError, AlertGenerator, InferenceLogEntry, InferenceModel, InferenceResult,
    OnnxModel,
};
use proptest::prelude::*;
use rand::{Rng, SeedableRng, rngs::StdRng};
use regex::Regex;
use tempfile::TempDir;
use tokio::sync::broadcast::{self, error::TryRecvError};

#[test]
fn alert_generator_emits_exactly_one_alert_when_score_exceeds_threshold() {
    let tempdir = TempDir::new().expect("tempdir");
    let (alert_sender, mut receiver) = broadcast::channel(8);
    let (inference_log_sender, _inference_log_receiver) = broadcast::channel(8);
    let generator = AlertGenerator::new(
        0.7,
        alert_sender,
        inference_log_sender,
        tempdir.path().join("alert_id.seq"),
    )
    .expect("generator constructs");

    let alert = generator
        .publish(&sample_enriched_event(), &sample_result(0.85, 6))
        .expect("publish succeeds")
        .expect("score above threshold emits an alert");

    assert!((0.84..=0.86).contains(&alert.threat_score));
    assert_eq!(alert.top_features.len(), 5);
    assert!(!alert.ancestry_chain.is_empty());
    assert_eq!(alert.alert_id, 1);
    assert!(!alert.process_name.is_empty());
    assert!(alert.binary_path.starts_with('/'));
    assert!(!alert.summary.is_empty());
    assert_eq!(alert.model_hash, "sample-model-hash");
    let json = serde_json::to_value(&alert).expect("alert serializes to JSON value");
    for required_field in [
        "alert_id",
        "timestamp",
        "pid",
        "process_name",
        "binary_path",
        "ancestry_chain",
        "threat_score",
        "model_hash",
        "top_features",
        "summary",
    ] {
        assert!(
            json.get(required_field).is_some(),
            "FR-D04 requires `{required_field}` in the alert payload"
        );
    }

    let broadcast_alert = receiver.try_recv().expect("receiver gets one alert");
    assert_eq!(broadcast_alert, alert);
    assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn alert_generator_uses_greater_than_or_equal_threshold_boundary() {
    let tempdir = TempDir::new().expect("tempdir");
    let (alert_sender, mut receiver) = broadcast::channel(8);
    let (inference_log_sender, _inference_log_receiver) = broadcast::channel(8);
    let generator = AlertGenerator::new(
        0.7,
        alert_sender,
        inference_log_sender,
        tempdir.path().join("alert_id.seq"),
    )
    .expect("generator constructs");

    let boundary = generator
        .publish(&sample_enriched_event(), &sample_result(0.7, 5))
        .expect("boundary publish succeeds");
    assert!(
        approx_equal(
            boundary
                .expect("score equal to threshold must alert")
                .threat_score,
            0.7
        ),
        "scores exactly on the threshold must preserve the boundary value"
    );
    receiver.try_recv().expect("boundary alert is broadcast");

    let below = generator
        .publish(&sample_enriched_event(), &sample_result(0.6999, 5))
        .expect("below-threshold publish succeeds");
    assert!(below.is_none(), "scores below threshold must not alert");
    assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn alert_generator_emits_structured_inference_log_entry_for_every_inference() {
    let tempdir = TempDir::new().expect("tempdir");
    let (alert_sender, _alert_receiver) = broadcast::channel(8);
    let (inference_log_sender, mut inference_log_receiver) = broadcast::channel(128);
    let generator = AlertGenerator::new(
        0.7,
        alert_sender,
        inference_log_sender,
        tempdir.path().join("alert_id.seq"),
    )
    .expect("generator constructs");

    for index in 0..100 {
        let score = if index % 2 == 0 { 0.85 } else { 0.6999 };
        let _ = generator.publish(&sample_enriched_event(), &sample_result(score, 5));
    }

    let records = collect_inference_logs(&mut inference_log_receiver);
    assert_eq!(
        records.len(),
        100,
        "every inference must emit one log entry"
    );
    for record in records {
        let serialized = serde_json::to_string(&record).expect("log entry serializes");
        let parsed = serde_json::from_str::<serde_json::Value>(&serialized)
            .expect("serialized inference log entry parses as JSON");
        assert_eq!(parsed["event_type"], "inference_result");
        assert!(
            parsed["pid"].as_u64().is_some_and(|pid| pid > 0),
            "each structured record must contain a non-zero pid"
        );
        assert!(
            parsed["score"]
                .as_f64()
                .is_some_and(|score| (0.0..=1.0).contains(&score)),
            "each structured record must clamp score into [0, 1]"
        );
        let top_features = parsed["top_features"]
            .as_array()
            .expect("top_features must serialize as a JSON array");
        assert_eq!(top_features.len(), 5);
    }
}

#[test]
fn alert_generator_persists_monotonic_ids_across_restart() {
    let tempdir = TempDir::new().expect("tempdir");
    let state_path = tempdir.path().join("alert_id.seq");
    let (alert_sender, _alert_receiver) = broadcast::channel(8);
    let (inference_log_sender, _inference_log_receiver) = broadcast::channel(8);

    let generator = AlertGenerator::new(
        0.7,
        alert_sender.clone(),
        inference_log_sender.clone(),
        state_path.clone(),
    )
    .expect("first generator constructs");
    let mut last_id = 0;
    for _ in 0..100 {
        last_id = generator
            .publish(&sample_enriched_event(), &sample_result(0.85, 5))
            .expect("publish succeeds")
            .expect("high score alerts")
            .alert_id;
    }
    assert_eq!(last_id, 100);
    assert_eq!(
        fs::read_to_string(&state_path)
            .expect("state file exists")
            .trim(),
        "100"
    );

    let restarted = AlertGenerator::new(0.7, alert_sender, inference_log_sender, state_path)
        .expect("restart constructs");
    let first_after_restart = restarted
        .publish(&sample_enriched_event(), &sample_result(0.85, 5))
        .expect("publish succeeds")
        .expect("high score alerts")
        .alert_id;
    assert!(
        first_after_restart > last_id,
        "restarted alert IDs must continue above the previous run"
    );
}

#[test]
fn alert_generator_returns_a_structured_error_and_preserves_the_last_persisted_id_on_write_failure()
{
    let tempdir = TempDir::new().expect("tempdir");
    let state_path = tempdir.path().join("alert_id.seq");
    fs::write(&state_path, "42\n").expect("seed last issued alert id");
    let (alert_sender, _alert_receiver) = broadcast::channel(8);
    let mut alert_receiver = alert_sender.subscribe();
    let (inference_log_sender, _inference_log_receiver) = broadcast::channel(8);
    let generator =
        AlertGenerator::new(0.7, alert_sender, inference_log_sender, state_path.clone())
            .expect("generator constructs");

    let writable_permissions = fs::metadata(tempdir.path())
        .expect("state directory metadata")
        .permissions();
    let mut read_only_permissions = writable_permissions.clone();
    read_only_permissions.set_mode(0o500);
    fs::set_permissions(tempdir.path(), read_only_permissions)
        .expect("make state directory read-only");

    let error = generator
        .publish(&sample_enriched_event(), &sample_result(0.85, 5))
        .expect_err("persist failures must fail the publish call loudly");
    assert!(
        matches!(error, AlertGenerationError::AlertIdStateWriteFailed { .. }),
        "the caller must receive a structured persistence error, got {error:?}"
    );
    assert!(
        matches!(alert_receiver.try_recv(), Err(TryRecvError::Empty)),
        "no alert should be emitted when the next alert id cannot be durably persisted"
    );

    fs::set_permissions(tempdir.path(), writable_permissions)
        .expect("restore state directory permissions");

    let recovered_id = generator
        .publish(&sample_enriched_event(), &sample_result(0.85, 5))
        .expect("publish succeeds after persistence recovers")
        .expect("high score alerts")
        .alert_id;
    assert_eq!(
        recovered_id, 43,
        "the in-memory counter must not advance past the last persisted id when a write fails"
    );
    assert_eq!(
        fs::read_to_string(&state_path)
            .expect("state file catches back up after recovery")
            .trim(),
        "43"
    );
}

#[test]
fn alert_generator_restart_reuses_only_the_last_persisted_id_after_repeated_write_failures() {
    let tempdir = TempDir::new().expect("tempdir");
    let state_path = tempdir.path().join("alert_id.seq");
    fs::write(&state_path, "42\n").expect("seed last issued alert id");
    let (alert_sender, _alert_receiver) = broadcast::channel(128);
    let mut alert_receiver = alert_sender.subscribe();
    let (inference_log_sender, _inference_log_receiver) = broadcast::channel(128);
    let generator =
        AlertGenerator::new(0.7, alert_sender, inference_log_sender, state_path.clone())
            .expect("generator constructs");

    let writable_permissions = fs::metadata(tempdir.path())
        .expect("state directory metadata")
        .permissions();
    let mut read_only_permissions = writable_permissions.clone();
    read_only_permissions.set_mode(0o500);
    fs::set_permissions(tempdir.path(), read_only_permissions)
        .expect("make state directory read-only");

    // This loop models the scrutiny failure mode directly: a long run keeps
    // trying to alert while `alert_id.seq` is stale on disk. The fixed policy
    // must refuse every alert so a restart can safely resume from the last
    // durable high-water mark instead of reissuing duplicate IDs.
    for _ in 0..100 {
        let error = generator
            .publish(&sample_enriched_event(), &sample_result(0.85, 5))
            .expect_err("every persistence failure must block alert emission");
        assert!(
            matches!(error, AlertGenerationError::AlertIdStateWriteFailed { .. }),
            "every failed publish must surface the same structured persistence error"
        );
    }
    assert!(
        matches!(alert_receiver.try_recv(), Err(TryRecvError::Empty)),
        "a failed persistence run must not leak any alert IDs before restart"
    );

    fs::set_permissions(tempdir.path(), writable_permissions)
        .expect("restore state directory permissions");
    assert_eq!(
        fs::read_to_string(&state_path)
            .expect("stale state file still exists on disk")
            .trim(),
        "42",
        "the on-disk high-water mark must remain at the last durable value"
    );

    let (restarted_alert_sender, _restarted_alert_receiver) = broadcast::channel(8);
    let (restarted_inference_log_sender, _restarted_inference_log_receiver) = broadcast::channel(8);
    let restarted = AlertGenerator::new(
        0.7,
        restarted_alert_sender,
        restarted_inference_log_sender,
        state_path,
    )
    .expect("restart constructs from the last durable high-water mark");

    let first_after_restart = restarted
        .publish(&sample_enriched_event(), &sample_result(0.85, 5))
        .expect("publish succeeds once persistence is restored")
        .expect("high score alerts")
        .alert_id;
    assert_eq!(
        first_after_restart, 43,
        "restart must resume from the last durable high-water mark instead of duplicating any lost in-memory range"
    );
}

#[test]
fn alert_generator_pads_top_features_to_exactly_five_entries_and_sanitizes_kernel_pointers() {
    let tempdir = TempDir::new().expect("tempdir");
    let (alert_sender, _alert_receiver) = broadcast::channel(8);
    let (inference_log_sender, _inference_log_receiver) = broadcast::channel(8);
    let generator = AlertGenerator::new(
        0.7,
        alert_sender,
        inference_log_sender,
        tempdir.path().join("alert_id.seq"),
    )
    .expect("generator constructs");

    let mut event = sample_enriched_event();
    event.process_name = Some("evil 0xffff123456789abc process".to_owned());
    event.binary_path = Some("/opt/0xffff123456789abc/bin".to_owned());
    event.ancestry_chain = vec![
        ProcessInfo {
            pid: 1,
            process_name: "systemd".to_owned(),
            binary_path: "/usr/lib/systemd/systemd".to_owned(),
        },
        ProcessInfo {
            pid: 4_242,
            process_name: "child 0xffff123456789abc".to_owned(),
            binary_path: "/tmp/0xffff123456789abc".to_owned(),
        },
    ];

    let alert = generator
        .publish(&event, &sample_result(0.85, 2))
        .expect("publish succeeds")
        .expect("high score alerts");

    assert_eq!(alert.top_features.len(), 5);
    let json = serde_json::to_string(&alert).expect("alert serializes");
    let kernel_pointer_pattern =
        Regex::new(r"0xffff[0-9a-f]{12}").expect("kernel pointer regex compiles");
    assert!(
        !kernel_pointer_pattern.is_match(&json),
        "kernel pointer patterns must be redacted from serialized alert output"
    );
}

#[test]
fn alert_generator_corpus_threshold_boundaries_and_pointer_redaction() {
    let tempdir = TempDir::new().expect("tempdir");
    let model = OnnxModel::load(&trained_model_path()).expect("onnx model loads");
    let (alert_sender_zero, _alert_receiver_zero) = broadcast::channel(16);
    let (inference_log_sender_zero, _inference_log_receiver_zero) = broadcast::channel(16);
    let (alert_sender_one, _alert_receiver_one) = broadcast::channel(16);
    let (inference_log_sender_one, _inference_log_receiver_one) = broadcast::channel(16);
    let generator_zero = AlertGenerator::new(
        0.0,
        alert_sender_zero,
        inference_log_sender_zero,
        tempdir.path().join("zero.seq"),
    )
    .expect("0.0 accepted");
    let generator_one = AlertGenerator::new(
        1.0,
        alert_sender_one,
        inference_log_sender_one,
        tempdir.path().join("one.seq"),
    )
    .expect("1.0 accepted");
    let kernel_pointer_pattern =
        Regex::new(r"0xffff[0-9a-f]{12}").expect("kernel pointer regex compiles");
    let mut rng = StdRng::seed_from_u64(0xA11E_271D_u64);

    let mut threshold_zero_alerts = 0;
    let mut threshold_one_alerts = 0;
    let mut exact_one_scores = 0;

    for index in 0..10_000 {
        let vector = random_feature_vector(&mut rng);
        let result = model.predict(&vector).expect("model scores random vector");
        if (result.threat_score - 1.0).abs() <= f64::EPSILON {
            exact_one_scores += 1;
        }

        let zero_alert = generator_zero
            .publish(&sample_enriched_event_for_pid(index + 10_000), &result)
            .expect("threshold 0 publish succeeds");
        if let Some(alert) = zero_alert {
            threshold_zero_alerts += 1;
            let json = serde_json::to_string(&alert).expect("alert serializes");
            assert!(
                !kernel_pointer_pattern.is_match(&json),
                "corpus alert output must not leak kernel pointers"
            );
        }

        let one_alert = generator_one
            .publish(&sample_enriched_event_for_pid(index + 20_000), &result)
            .expect("threshold 1 publish succeeds");
        if one_alert.is_some() {
            threshold_one_alerts += 1;
        }
    }

    assert_eq!(threshold_zero_alerts, 10_000);
    assert_eq!(threshold_one_alerts, exact_one_scores);
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1_000,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn alert_generator_inference_log_entry_shape_invariants_hold_for_1000_random_inputs(
        pid in 1_u32..u32::MAX,
        raw_score_millis in -10_000_i32..1_000_i32,
        raw_features in proptest::collection::vec(
            (
                "[a-z_]{1,16}",
                -1_000_000_i32..1_000_000_i32,
            ),
            0..12
        ),
    ) {
        let tempdir = TempDir::new().expect("tempdir");
        let (alert_sender, _alert_receiver) = broadcast::channel(4);
        let (inference_log_sender, mut inference_log_receiver) = broadcast::channel(4);
        let generator = AlertGenerator::new(
            1.0,
            alert_sender,
            inference_log_sender,
            tempdir.path().join("alert_id.seq"),
        )
        .expect("generator constructs");

        let inference_result = InferenceResult {
            threat_score: f64::from(raw_score_millis) / 1_000.0,
            feature_importances: raw_features
                .into_iter()
                .map(|(feature_name, weight_millis)| FeatureContribution {
                    feature_name,
                    contribution_score: f64::from(weight_millis) / 1_000.0,
                })
                .collect(),
            model_hash: "property-test-model".to_owned(),
        };

        let _ = generator
            .publish(&sample_enriched_event_for_pid(pid), &inference_result)
            .expect("publish succeeds");

        let record = inference_log_receiver
            .try_recv()
            .expect("one structured inference log entry is emitted");
        let serialized = serde_json::to_string(&record).expect("entry serializes");
        let parsed = serde_json::from_str::<InferenceLogEntry>(&serialized)
            .expect("serialized structured log parses back into its schema");
        prop_assert_eq!(parsed.event_type, "inference_result");
        prop_assert_eq!(parsed.top_features.len(), 5);
        prop_assert!(parsed.top_features.iter().all(|feature| feature.weight.is_finite()));
        prop_assert!((0.0..=1.0).contains(&parsed.score));
    }
}

fn trained_model_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../training/output/model.onnx")
        .canonicalize()
        .expect("training output model exists")
}

fn sample_result(score: f64, contribution_count: usize) -> InferenceResult {
    let importances = (0..contribution_count)
        .map(|index| FeatureContribution {
            feature_name: format!("feature_{index}"),
            contribution_score: [1.0, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1]
                .get(index)
                .copied()
                .unwrap_or(0.0),
        })
        .collect();
    InferenceResult {
        threat_score: score,
        feature_importances: importances,
        model_hash: "sample-model-hash".to_owned(),
    }
}

fn collect_inference_logs(
    receiver: &mut broadcast::Receiver<InferenceLogEntry>,
) -> Vec<InferenceLogEntry> {
    let mut records = Vec::new();
    loop {
        match receiver.try_recv() {
            Ok(record) => records.push(record),
            Err(TryRecvError::Empty) => break,
            Err(error) => panic!("unexpected inference-log receive error: {error}"),
        }
    }
    records
}

fn approx_equal(left: f64, right: f64) -> bool {
    (left - right).abs() <= f64::EPSILON
}

fn sample_enriched_event() -> EnrichedEvent {
    sample_enriched_event_for_pid(4_242)
}

fn sample_enriched_event_for_pid(pid: u32) -> EnrichedEvent {
    EnrichedEvent {
        event: SyscallEvent {
            event_id: u64::from(pid),
            timestamp: 1_713_000_005_123_456_789,
            pid,
            ppid: 1_001,
            tid: pid,
            syscall_type: SyscallType::Connect,
            filename: None,
            ip_address: Some([127, 0, 0, 1]),
            port: Some(4_443),
            child_pid: None,
            open_flags: None,
            syscall_result: None,
        },
        process_name: Some("curl".to_owned()),
        binary_path: Some("/usr/bin/curl".to_owned()),
        cgroup: Some("0::/user.slice/user-1000.slice/session-2.scope".to_owned()),
        uid: Some(1_000),
        ancestry_chain: vec![
            ProcessInfo {
                pid: 1,
                process_name: "systemd".to_owned(),
                binary_path: "/usr/lib/systemd/systemd".to_owned(),
            },
            ProcessInfo {
                pid: 1_001,
                process_name: "bash".to_owned(),
                binary_path: "/usr/bin/bash".to_owned(),
            },
            ProcessInfo {
                pid,
                process_name: "curl".to_owned(),
                binary_path: "/usr/bin/curl".to_owned(),
            },
        ],
        ancestry_truncated: false,
        repeat_count: 1,
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "The corpus fixture intentionally exercises large integer counters and timestamps that the deployed model later narrows into floating-point tensors."
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
