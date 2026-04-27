//! Criterion benchmarks for the Mini-EDR detection and feature-extraction path.
//!
//! The system-integration performance contract needs two kinds of evidence:
//! 1. Criterion's ordinary regression tracking for stable microbenchmarks, and
//! 2. explicit p50/p99 / throughput summaries that shell harnesses can parse.
//!
//! We therefore keep Criterion as the measurement runner while also writing
//! one JSON summary per benchmark under `target/criterion/mini-edr-performance/`.
//! Each summary captures the methodology inline so later engineers can see the
//! exact sample counts, fixture sources, and assumptions without reverse-
//! engineering the harness from the code alone.
#![allow(missing_docs)]

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use mini_edr_common::{
    Alert, EnrichedEvent, FeatureContribution, FeatureVector, ProcessInfo, SyscallEvent,
    SyscallType,
};
use mini_edr_detection::{ModelBackend, ModelManager, ModelStatus};
use mini_edr_pipeline::WindowAggregator;
use serde::Serialize;
use std::{
    cmp, env, fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const INFERENCE_BENCH_NAME: &str = "inference_latency";
const FEATURE_BENCH_NAME: &str = "feature_extraction_throughput";
const SERIALIZATION_BENCH_NAME: &str = "json_serialization";

#[derive(Serialize)]
struct LatencySummary {
    benchmark: String,
    methodology: String,
    sample_count: usize,
    fixture_path: String,
    model_path: String,
    warmup_iterations: usize,
    p50_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    mean_ms: f64,
}

#[derive(Serialize)]
struct ThroughputSummary {
    benchmark: String,
    methodology: String,
    event_count: u64,
    simulated_duration_seconds: u64,
    observed_events_per_second: f64,
    emitted_feature_vectors: u64,
    alerts_above_threshold: u64,
}

#[derive(Serialize)]
struct SerializationSummary {
    benchmark: String,
    methodology: String,
    sample_count: usize,
    fixture_path: String,
    mean_microseconds: f64,
    p50_microseconds: f64,
    p99_microseconds: f64,
    max_microseconds: f64,
    encoded_bytes: usize,
}

fn performance_benches(c: &mut Criterion) {
    write_summaries().expect("benchmark summaries write successfully");

    let model_manager = load_model_manager();
    let feature_vector = sample_feature_vector();
    let enriched_events = synthetic_enriched_events(4_096, 4_096);
    let alert = sample_alert();

    c.bench_function(INFERENCE_BENCH_NAME, |bench| {
        bench.iter(|| {
            black_box(
                model_manager
                    .predict(black_box(&feature_vector))
                    .expect("trained ONNX model scores the representative feature vector"),
            );
        });
    });

    {
        let mut throughput_group = c.benchmark_group(FEATURE_BENCH_NAME);
        throughput_group.throughput(Throughput::Elements(
            u64::try_from(enriched_events.len()).expect("event corpus length fits in u64"),
        ));
        throughput_group.bench_function(FEATURE_BENCH_NAME, |bench| {
            bench.iter(|| {
                let mut aggregator = WindowAggregator::new(1);
                let mut emitted = 0_u64;
                for event in &enriched_events {
                    emitted = emitted.saturating_add(
                        u64::try_from(aggregator.push_event(black_box(event.clone())).len())
                            .expect("feature-vector count fits in u64"),
                    );
                }
                let final_flush_timestamp = synthetic_timestamp_ns(
                    u64::try_from(enriched_events.len())
                        .expect("corpus length fits in u64")
                        .saturating_add(4_096),
                    4_096,
                );
                emitted = emitted.saturating_add(
                    u64::try_from(aggregator.flush_expired(final_flush_timestamp).len())
                        .expect("feature-vector count fits in u64"),
                );
                black_box(emitted);
            });
        });
        throughput_group.finish();
    }

    c.bench_function(SERIALIZATION_BENCH_NAME, |bench| {
        bench.iter(|| {
            black_box(
                serde_json::to_string(black_box(&alert))
                    .expect("representative alert serializes as single-line JSON"),
            );
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(10))
        .sample_size(100);
    targets = performance_benches
}
criterion_main!(benches);

fn write_summaries() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(summary_directory())?;
    write_json_summary(
        INFERENCE_BENCH_NAME,
        &measure_inference_latency(inference_sample_count(), 1_000),
    )?;
    write_json_summary(
        FEATURE_BENCH_NAME,
        &measure_feature_extraction(feature_event_count(), 60_000),
    )?;
    write_json_summary(
        SERIALIZATION_BENCH_NAME,
        &measure_json_serialization(serialization_sample_count()),
    )?;
    Ok(())
}

fn write_json_summary(
    benchmark_name: &str,
    value: &impl Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = serde_json::to_vec_pretty(value)?;
    fs::write(
        summary_directory().join(format!("{benchmark_name}.json")),
        encoded,
    )?;
    Ok(())
}

fn summary_directory() -> PathBuf {
    repo_root()
        .join("target")
        .join("criterion")
        .join("mini-edr-performance")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn trained_model_path() -> PathBuf {
    repo_root()
        .join("training/output/model.onnx")
        .canonicalize()
        .expect("training output model exists")
}

fn fixture_path(name: &str) -> PathBuf {
    repo_root()
        .join("tests/fixtures/feature_vectors")
        .join(name)
        .canonicalize()
        .expect("fixture path resolves")
}

fn inference_sample_count() -> usize {
    env::var("MINI_EDR_INFERENCE_SAMPLES")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(100_000)
}

fn feature_event_count() -> u64 {
    env::var("MINI_EDR_FEATURE_EVENT_COUNT")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(3_600_000)
}

fn serialization_sample_count() -> usize {
    env::var("MINI_EDR_SERIALIZATION_SAMPLES")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(100_000)
}

fn load_model_manager() -> ModelManager {
    let manager = ModelManager::load_at_startup(&trained_model_path(), ModelBackend::OnnxRuntime);
    match manager.status() {
        ModelStatus::Running { .. } => manager,
        status @ ModelStatus::Degraded { .. } => {
            panic!("benchmarks require a live model, got {status:?}")
        }
    }
}

fn measure_inference_latency(sample_count: usize, warmup_iterations: usize) -> LatencySummary {
    let manager = load_model_manager();
    let vector = sample_feature_vector();
    for _ in 0..warmup_iterations {
        manager
            .predict(&vector)
            .expect("warmup prediction succeeds before latency sampling");
    }

    let mut latencies_ms = Vec::with_capacity(sample_count);
    for _ in 0..sample_count {
        let started_at = Instant::now();
        manager
            .predict(&vector)
            .expect("prediction succeeds during latency sampling");
        latencies_ms.push(started_at.elapsed().as_secs_f64() * 1_000.0);
    }
    latencies_ms.sort_by(f64::total_cmp);

    LatencySummary {
        benchmark: INFERENCE_BENCH_NAME.to_owned(),
        methodology: "Warm up the deployed ONNX model with 1,000 predictions, then time 100,000 single-vector inferences against the checked-in high_085 fixture vector. Statistics use nearest-rank p50/p99 over per-call wall-clock latency. Assumes the host is otherwise idle and reuses the already-loaded model artifact to isolate inference cost.".to_owned(),
        sample_count,
        fixture_path: fixture_path("high_085.json").display().to_string(),
        model_path: trained_model_path().display().to_string(),
        warmup_iterations,
        p50_ms: percentile(&latencies_ms, 50, 100),
        p99_ms: percentile(&latencies_ms, 99, 100),
        max_ms: *latencies_ms.last().unwrap_or(&0.0),
        mean_ms: average(&latencies_ms),
    }
}

fn measure_feature_extraction(event_count: u64, target_eps: u64) -> ThroughputSummary {
    let manager = load_model_manager();
    let mut aggregator = WindowAggregator::new(1);
    let started_at = Instant::now();
    let mut emitted_feature_vectors = 0_u64;
    let mut alerts_above_threshold = 0_u64;

    for index in 0..event_count {
        let event = synthetic_enriched_event(index, target_eps);
        emitted_feature_vectors = emitted_feature_vectors.saturating_add(process_ready_vectors(
            &manager,
            aggregator.push_event(event),
            &mut alerts_above_threshold,
        ));
    }

    let final_flush_timestamp = synthetic_timestamp_ns(
        event_count.saturating_add(target_eps).saturating_add(1),
        target_eps,
    );
    emitted_feature_vectors = emitted_feature_vectors.saturating_add(process_ready_vectors(
        &manager,
        aggregator.flush_expired(final_flush_timestamp),
        &mut alerts_above_threshold,
    ));

    let elapsed_seconds = started_at.elapsed().as_secs_f64().max(f64::EPSILON);
    ThroughputSummary {
        benchmark: FEATURE_BENCH_NAME.to_owned(),
        methodology: "Generate a synthetic 60,000-events/second enriched-event stream for 60 seconds of equivalent workload (3.6M events total), aggregate those events into 1-second process windows, and score every emitted feature vector through the deployed ONNX model. Throughput is total input events divided by wall-clock processing time; the harness has no bounded queues, so sustained drops are reported as zero by construction.".to_owned(),
        event_count,
        simulated_duration_seconds: event_count / target_eps,
        observed_events_per_second: f64::from(
            u32::try_from(event_count).expect("benchmark event count stays within u32")
        ) / elapsed_seconds,
        emitted_feature_vectors,
        alerts_above_threshold,
    }
}

fn measure_json_serialization(sample_count: usize) -> SerializationSummary {
    let alert = sample_alert();
    let mut durations_us = Vec::with_capacity(sample_count);
    let mut encoded_bytes = 0_usize;

    for _ in 0..sample_count {
        let started_at = Instant::now();
        let encoded =
            serde_json::to_string(&alert).expect("representative alert serializes to JSON");
        durations_us.push(started_at.elapsed().as_secs_f64() * 1_000_000.0);
        encoded_bytes = encoded.len();
    }
    durations_us.sort_by(f64::total_cmp);

    SerializationSummary {
        benchmark: SERIALIZATION_BENCH_NAME.to_owned(),
        methodology: "Serialize the representative alert payload from the shared common schema 100,000 times with serde_json::to_string, recording per-call wall-clock cost in microseconds. The fixture mirrors the append-only alert log schema and therefore reflects the JSON shape operators actually persist and stream.".to_owned(),
        sample_count,
        fixture_path: "synthetic::sample_alert".to_owned(),
        mean_microseconds: average(&durations_us),
        p50_microseconds: percentile(&durations_us, 50, 100),
        p99_microseconds: percentile(&durations_us, 99, 100),
        max_microseconds: *durations_us.last().unwrap_or(&0.0),
        encoded_bytes,
    }
}

fn process_ready_vectors(
    manager: &ModelManager,
    ready_vectors: Vec<FeatureVector>,
    alerts_above_threshold: &mut u64,
) -> u64 {
    let mut emitted = 0_u64;
    for vector in ready_vectors {
        emitted = emitted.saturating_add(1);
        let result = manager
            .predict(&vector)
            .expect("synthetic feature vector scores during throughput sampling");
        if result.threat_score >= 0.7 {
            *alerts_above_threshold = alerts_above_threshold.saturating_add(1);
        }
    }
    emitted
}

fn percentile(sorted_values: &[f64], numerator: usize, denominator: usize) -> f64 {
    if sorted_values.is_empty() {
        return 0.0;
    }
    let max_index = sorted_values.len().saturating_sub(1);
    let rounded = max_index
        .saturating_mul(numerator)
        .saturating_add(denominator / 2)
        / denominator.max(1);
    let index = cmp::min(max_index, rounded);
    sorted_values[index]
}

fn average(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>()
        / f64::from(u32::try_from(values.len()).expect("benchmark sample counts stay within u32"))
}

fn sample_feature_vector() -> FeatureVector {
    let contents = fs::read_to_string(fixture_path("high_085.json"))
        .expect("high_085 fixture loads for inference benchmarking");
    serde_json::from_str(&contents).expect("high_085 fixture parses into FeatureVector")
}

fn synthetic_enriched_events(event_count: u64, target_eps: u64) -> Vec<EnrichedEvent> {
    let mut events =
        Vec::with_capacity(usize::try_from(event_count).unwrap_or(usize::MAX.saturating_sub(1)));

    for index in 0..event_count {
        events.push(synthetic_enriched_event(index, target_eps));
    }

    events
}

fn synthetic_timestamp_ns(index: u64, target_eps: u64) -> u64 {
    let nanos_per_event = 1_000_000_000_u64 / target_eps.max(1);
    1_713_000_000_000_000_000_u64.saturating_add(index.saturating_mul(nanos_per_event))
}

fn synthetic_enriched_event(index: u64, target_eps: u64) -> EnrichedEvent {
    let pid = 4_000_u32 + u32::try_from(index % 256).expect("pid offset fits in u32");
    let syscall_type = match index % 4 {
        0 => SyscallType::Execve,
        1 => SyscallType::Openat,
        2 => SyscallType::Connect,
        _ => SyscallType::Clone,
    };
    let timestamp = synthetic_timestamp_ns(index, target_eps);

    EnrichedEvent {
        event: SyscallEvent {
            event_id: index,
            timestamp,
            pid,
            tid: pid,
            ppid: 1,
            syscall_type,
            filename: match syscall_type {
                SyscallType::Execve => Some("/usr/bin/python3".to_owned()),
                SyscallType::Openat => Some(format!("/tmp/mini-edr-bench-{}.tmp", index % 32)),
                _ => None,
            },
            ip_address: (syscall_type == SyscallType::Connect).then_some([127, 0, 0, 1]),
            port: (syscall_type == SyscallType::Connect)
                .then_some(4_000_u16 + u16::try_from(index % 128).expect("port offset fits")),
            child_pid: (syscall_type == SyscallType::Clone).then_some(pid.saturating_add(10_000)),
            open_flags: (syscall_type == SyscallType::Openat).then_some(0o100 | 0o1),
            syscall_result: Some(0),
        },
        process_name: Some(
            match syscall_type {
                SyscallType::Execve => "python3",
                SyscallType::Openat => "touch",
                SyscallType::Connect => "curl",
                SyscallType::Clone => "bash",
            }
            .to_owned(),
        ),
        binary_path: Some(
            match syscall_type {
                SyscallType::Execve => "/usr/bin/python3",
                SyscallType::Openat => "/usr/bin/touch",
                SyscallType::Connect => "/usr/bin/curl",
                SyscallType::Clone => "/usr/bin/bash",
            }
            .to_owned(),
        ),
        cgroup: Some("/user.slice/user-1000.slice/session-bench.scope".to_owned()),
        uid: Some(1_000),
        ancestry_chain: vec![
            ProcessInfo {
                pid: 1,
                process_name: "systemd".to_owned(),
                binary_path: "/usr/lib/systemd/systemd".to_owned(),
            },
            ProcessInfo {
                pid,
                process_name: "bench-worker".to_owned(),
                binary_path: "/home/alexm/mini-edr/target/release/examples/performance".to_owned(),
            },
        ],
        ancestry_truncated: false,
        repeat_count: 1,
    }
}

fn sample_alert() -> Alert {
    let timestamp = chrono::DateTime::parse_from_rfc3339("2026-04-27T12:00:00Z")
        .expect("sample alert timestamp parses")
        .with_timezone(&chrono::Utc);
    let feature_vector = sample_feature_vector();

    Alert {
        alert_id: 42,
        timestamp,
        pid: feature_vector.pid,
        process_name: "reverse_shell.sh".to_owned(),
        binary_path: "/home/alexm/mini-edr/tests/fixtures/malware/reverse_shell.sh".to_owned(),
        ancestry_chain: vec![
            ProcessInfo {
                pid: 1,
                process_name: "systemd".to_owned(),
                binary_path: "/usr/lib/systemd/systemd".to_owned(),
            },
            ProcessInfo {
                pid: feature_vector.pid,
                process_name: "reverse_shell.sh".to_owned(),
                binary_path: "/home/alexm/mini-edr/tests/fixtures/malware/reverse_shell.sh"
                    .to_owned(),
            },
        ],
        threat_score: 0.85,
        model_hash: "sample-model-hash".to_owned(),
        top_features: vec![
            FeatureContribution {
                feature_name: "__process_positive_rate__".to_owned(),
                contribution_score: 0.42,
            },
            FeatureContribution {
                feature_name: "__event_positive_rate__".to_owned(),
                contribution_score: 0.19,
            },
            FeatureContribution {
                feature_name: "__path_positive_rate__".to_owned(),
                contribution_score: 0.12,
            },
            FeatureContribution {
                feature_name: "outbound_connection_count".to_owned(),
                contribution_score: 0.07,
            },
            FeatureContribution {
                feature_name: "wrote_tmp".to_owned(),
                contribution_score: 0.05,
            },
        ],
        summary: "reverse_shell.sh exceeded the alert threshold during performance serialization benchmarking".to_owned(),
    }
}
