//! Userland performance harnesses for the system-integration milestone.
//!
//! The shell scripts under `tests/perf/` need a deterministic, non-interactive
//! driver that they can run on hosts with and without probe capabilities. This
//! example binary provides three such modes:
//!
//! - `throughput`: capacity-style event processing over a 60-second-equivalent
//!   synthetic workload.
//! - `steady-load`: real-time paced synthetic load suitable for `top` and RSS
//!   sampling.
//! - `latency`: repeated reverse-shell fixture-vector predictions through the
//!   daemon's alerting path.
//!
//! The harness intentionally stays inside the Rust deployment path (pipeline +
//! detection + daemon alerting) so performance evidence reflects the same code
//! that ships in the actual binary rather than a Python-only surrogate.

use mini_edr_common::{EnrichedEvent, FeatureVector, ProcessInfo, SyscallEvent, SyscallType};
use mini_edr_daemon::HotReloadDaemon;
use mini_edr_detection::{InferenceError, ModelBackend, ModelManager, ModelStatus};
use mini_edr_pipeline::WindowAggregator;
use serde::Serialize;
use std::{
    env,
    fs::{self},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const DEFAULT_THRESHOLD: f64 = 0.7;

#[derive(Clone, Copy, Debug)]
enum Mode {
    Throughput,
    SteadyLoad,
    Latency,
}

#[derive(Debug)]
struct Args {
    mode: Mode,
    duration_seconds: u64,
    target_eps: u64,
    trials: usize,
    fixture_path: PathBuf,
    report_path: Option<PathBuf>,
}

#[derive(Serialize)]
struct ThroughputReport {
    mode: String,
    methodology: String,
    requested_duration_seconds: u64,
    target_events_per_second: u64,
    total_events: u64,
    total_feature_vectors: u64,
    alerts_above_threshold: u64,
    dropped_events_total: u64,
    observed_events_per_second: f64,
    elapsed_seconds: f64,
}

#[derive(Serialize)]
struct LatencyReport {
    mode: String,
    methodology: String,
    trials: usize,
    fixture_path: String,
    alert_log_path: String,
    alert_count_total: u64,
    p50_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    mean_ms: f64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;
    match args.mode {
        Mode::Throughput => {
            let report = run_synthetic_pipeline(args.duration_seconds, args.target_eps, false)?;
            finish(args.report_path.as_ref(), &report)?;
        }
        Mode::SteadyLoad => {
            let report = run_synthetic_pipeline(args.duration_seconds, args.target_eps, true)?;
            finish(args.report_path.as_ref(), &report)?;
        }
        Mode::Latency => {
            let report = run_latency_trials(args.trials, &args.fixture_path).await?;
            finish(args.report_path.as_ref(), &report)?;
        }
    }
    Ok(())
}

fn parse_args() -> Result<Args, String> {
    let mut args = env::args().skip(1);
    let mode = match args.next().as_deref() {
        Some("throughput") => Mode::Throughput,
        Some("steady-load") => Mode::SteadyLoad,
        Some("latency") => Mode::Latency,
        _ => {
            return Err(
                "usage: perf_harness {throughput|steady-load|latency} [--duration-seconds N] [--target-eps N] [--trials N] [--fixture PATH] [--report-path PATH]".to_owned(),
            )
        }
    };

    let mut parsed = Args {
        mode,
        duration_seconds: 60,
        target_eps: 60_000,
        trials: 50,
        fixture_path: repo_root().join("tests/fixtures/feature_vectors/reverse_shell.json"),
        report_path: None,
    };

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--duration-seconds" => {
                parsed.duration_seconds = args
                    .next()
                    .ok_or_else(|| "--duration-seconds requires a value".to_owned())?
                    .parse()
                    .map_err(|error| format!("invalid --duration-seconds value: {error}"))?;
            }
            "--target-eps" => {
                parsed.target_eps = args
                    .next()
                    .ok_or_else(|| "--target-eps requires a value".to_owned())?
                    .parse()
                    .map_err(|error| format!("invalid --target-eps value: {error}"))?;
            }
            "--trials" => {
                parsed.trials = args
                    .next()
                    .ok_or_else(|| "--trials requires a value".to_owned())?
                    .parse()
                    .map_err(|error| format!("invalid --trials value: {error}"))?;
            }
            "--fixture" => {
                parsed.fixture_path = PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--fixture requires a value".to_owned())?,
                );
            }
            "--report-path" => {
                parsed.report_path =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "--report-path requires a value".to_owned()
                    })?));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(parsed)
}

fn finish(
    report_path: Option<&PathBuf>,
    report: &impl Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = serde_json::to_string_pretty(report)?;
    println!("{encoded}");
    if let Some(path) = report_path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, encoded.as_bytes())?;
        fs::write(path.with_extension("pretty.json"), format!("{encoded}\n"))?;
    }
    Ok(())
}

fn run_synthetic_pipeline(
    duration_seconds: u64,
    target_eps: u64,
    realtime: bool,
) -> Result<ThroughputReport, Box<dyn std::error::Error>> {
    let manager = load_model_manager()?;
    let mut aggregator = WindowAggregator::new(1);
    let total_events = duration_seconds.saturating_mul(target_eps);
    let started_at = Instant::now();
    let mut emitted_feature_vectors = 0_u64;
    let mut alerts_above_threshold = 0_u64;

    for second in 0..duration_seconds {
        let batch_started_at = Instant::now();
        for offset in 0..target_eps {
            let global_index = second.saturating_mul(target_eps).saturating_add(offset);
            let event = synthetic_enriched_event(global_index, target_eps);
            emitted_feature_vectors =
                emitted_feature_vectors.saturating_add(process_ready_vectors(
                    &manager,
                    aggregator.push_event(event),
                    &mut alerts_above_threshold,
                )?);
        }

        let flush_timestamp = synthetic_timestamp_ns(
            second
                .saturating_add(1)
                .saturating_mul(target_eps)
                .saturating_add(1),
            target_eps,
        );
        emitted_feature_vectors = emitted_feature_vectors.saturating_add(process_ready_vectors(
            &manager,
            aggregator.flush_expired(flush_timestamp),
            &mut alerts_above_threshold,
        )?);

        if realtime {
            let elapsed = batch_started_at.elapsed();
            if elapsed < Duration::from_secs(1) {
                thread::sleep(
                    Duration::from_secs(1)
                        .checked_sub(elapsed)
                        .expect("elapsed stays below one second in this branch"),
                );
            }
        }
    }

    let final_flush_timestamp = synthetic_timestamp_ns(
        total_events.saturating_add(target_eps).saturating_add(1),
        target_eps,
    );
    emitted_feature_vectors = emitted_feature_vectors.saturating_add(process_ready_vectors(
        &manager,
        aggregator.flush_expired(final_flush_timestamp),
        &mut alerts_above_threshold,
    )?);

    let elapsed_seconds = started_at.elapsed().as_secs_f64().max(f64::EPSILON);
    Ok(ThroughputReport {
        mode: if realtime {
            "steady-load"
        } else {
            "throughput"
        }
        .to_owned(),
        methodology: if realtime {
            "Pace a synthetic enriched-event stream at the requested wall-clock rate, aggregating one-second process windows and scoring every emitted feature vector through the deployed ONNX model. This mode is intended for shell-level CPU and RSS sampling because it keeps the process alive for the requested duration."
        } else {
            "Process a 60-second-equivalent synthetic enriched-event stream as quickly as possible, aggregating one-second process windows and scoring every emitted feature vector through the deployed ONNX model. Capacity is reported as total events divided by elapsed wall-clock time; no bounded queues are involved, so sustained drops remain zero by construction."
        }
        .to_owned(),
        requested_duration_seconds: duration_seconds,
        target_events_per_second: target_eps,
        total_events,
        total_feature_vectors: emitted_feature_vectors,
        alerts_above_threshold,
        dropped_events_total: 0,
        observed_events_per_second: f64::from(
            u32::try_from(total_events).expect("synthetic harness event counts stay within u32"),
        ) / elapsed_seconds,
        elapsed_seconds,
    })
}

async fn run_latency_trials(
    trials: usize,
    fixture_path: &Path,
) -> Result<LatencyReport, Box<dyn std::error::Error>> {
    let fixture_contents = fs::read_to_string(fixture_path)?;
    let feature_vector: FeatureVector = serde_json::from_str(&fixture_contents)?;
    let sandbox = create_latency_sandbox()?;
    let daemon = HotReloadDaemon::load_for_tests(&sandbox.config_path)?;

    let mut latencies_ms = Vec::with_capacity(trials);
    for _ in 0..trials {
        let started_at = Instant::now();
        let response = daemon.predict(&feature_vector).await?;
        if !response.would_alert {
            return Err(format!(
                "fixture {} no longer crosses the alert threshold; latency evidence would be invalid",
                fixture_path.display()
            )
            .into());
        }
        latencies_ms.push(started_at.elapsed().as_secs_f64() * 1_000.0);
    }
    latencies_ms.sort_by(f64::total_cmp);

    let telemetry = daemon.telemetry_snapshot();
    Ok(LatencyReport {
        mode: "latency".to_owned(),
        methodology: "Reuse the checked-in reverse_shell feature-vector fixture for 50 alerting trials through HotReloadDaemon::predict so the measurement covers the daemon's configured threshold check, alert generation, alert-ID persistence, and append-only alert-log write without requiring privileged probe attachment. Latency is measured from API ingress inside the harness to the completed predict call that already flushed the alert to disk.".to_owned(),
        trials,
        fixture_path: fixture_path.canonicalize()?.display().to_string(),
        alert_log_path: sandbox.alert_log_path.display().to_string(),
        alert_count_total: telemetry.alert_count_total,
        p50_ms: percentile(&latencies_ms, 50, 100),
        p99_ms: percentile(&latencies_ms, 99, 100),
        max_ms: *latencies_ms.last().unwrap_or(&0.0),
        mean_ms: average(&latencies_ms),
    })
}

fn process_ready_vectors(
    manager: &ModelManager,
    ready_vectors: Vec<FeatureVector>,
    alerts_above_threshold: &mut u64,
) -> Result<u64, InferenceError> {
    let mut emitted = 0_u64;
    for vector in ready_vectors {
        emitted = emitted.saturating_add(1);
        let result = manager.predict(&vector)?;
        if result.threat_score >= DEFAULT_THRESHOLD {
            *alerts_above_threshold = alerts_above_threshold.saturating_add(1);
        }
    }
    Ok(emitted)
}

fn load_model_manager() -> Result<ModelManager, Box<dyn std::error::Error>> {
    let manager = ModelManager::load_at_startup(&trained_model_path(), ModelBackend::OnnxRuntime);
    match manager.status() {
        ModelStatus::Running { .. } => Ok(manager),
        status @ ModelStatus::Degraded { .. } => {
            Err(format!("performance harness requires a live model, got {status:?}").into())
        }
    }
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

fn percentile(sorted_values: &[f64], numerator: usize, denominator: usize) -> f64 {
    if sorted_values.is_empty() {
        return 0.0;
    }
    let max_index = sorted_values.len().saturating_sub(1);
    let rounded = max_index
        .saturating_mul(numerator)
        .saturating_add(denominator / 2)
        / denominator.max(1);
    sorted_values[rounded.min(max_index)]
}

fn average(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>()
        / f64::from(u32::try_from(values.len()).expect("latency trial counts stay within u32"))
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

    EnrichedEvent {
        event: SyscallEvent {
            event_id: index,
            timestamp: synthetic_timestamp_ns(index, target_eps),
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
                binary_path: "/home/alexm/mini-edr/target/release/examples/perf_harness".to_owned(),
            },
        ],
        ancestry_truncated: false,
        repeat_count: 1,
    }
}

struct LatencySandbox {
    config_path: PathBuf,
    alert_log_path: PathBuf,
}

fn create_latency_sandbox() -> Result<LatencySandbox, Box<dyn std::error::Error>> {
    let unique_suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = env::temp_dir().join(format!("mini-edr-perf-latency-{unique_suffix}"));
    fs::create_dir_all(&root)?;
    let logs_dir = root.join("logs");
    let state_dir = root.join("state");
    fs::create_dir_all(&logs_dir)?;
    fs::create_dir_all(&state_dir)?;
    let alert_log_path = logs_dir.join("alerts.jsonl");
    let config_path = root.join("config.toml");

    let config = format!(
        "alert_threshold = {DEFAULT_THRESHOLD}\nweb_port = 0\nmodel_path = \"{}\"\nlog_file_path = \"{}\"\nstate_dir = \"{}\"\nenable_tui = false\nenable_web = false\n",
        trained_model_path().display(),
        alert_log_path.display(),
        state_dir.display(),
    );
    fs::write(&config_path, config)?;

    Ok(LatencySandbox {
        config_path,
        alert_log_path,
    })
}
