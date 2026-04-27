//! Integration tests for the daemon-owned localhost and Unix-socket API.
//!
//! These tests intentionally launch the real `mini-edr-daemon` binary because
//! the local API contract spans multiple concerns at once: HTTP routing,
//! Unix-socket lifecycle policy, alert streaming, and startup error handling.

mod support;

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use onnx_pb::ModelProto;
use prost::Message;
use serde_json::Value;
use tempfile::TempDir;

use crate::support::{
    assert_score_in_documented_band, threshold_fixture_contract, threshold_fixture_payload,
};

#[test]
fn unix_socket_streams_alerts_and_http_surfaces_health_and_telemetry() {
    let tempdir = TempDir::new().expect("tempdir");
    let socket_path = tempdir.path().join("api.sock");
    let config_path = write_logging_config(tempdir.path(), 0.7);
    let mut daemon = spawn_daemon(&config_path, &socket_path);
    let http_health = wait_for_unix_health(&mut daemon, &socket_path);
    let port: u16 = http_health["web_port"]
        .as_u64()
        .expect("web_port u64")
        .try_into()
        .expect("web_port fits in u16");

    let http_health_alias = curl_json(&["-fsS", &format!("http://127.0.0.1:{port}/health")]);
    assert_eq!(http_health_alias, http_health);

    let api_health = curl_json(&["-fsS", &format!("http://127.0.0.1:{port}/api/health")]);
    assert_eq!(api_health, http_health, "legacy /api/health alias diverged");

    let telemetry = curl_json(&["-fsS", &format!("http://127.0.0.1:{port}/telemetry")]);
    assert!(telemetry["events_per_second"].is_number());
    assert!(telemetry["ring_buffer_util"].is_number());
    assert!(telemetry["inference_latency_p99_ms"].is_number());
    assert!(telemetry["uptime_seconds"].is_number());
    assert!(telemetry["rss_bytes"].is_number());
    assert!(telemetry["alert_count_total"].is_number());

    let telemetry_summary = curl_json(&[
        "-fsS",
        &format!("http://127.0.0.1:{port}/telemetry/summary"),
    ]);
    assert_telemetry_alias_contract(&telemetry_summary, &telemetry);

    // The stream subscriber starts before the prediction so the test proves the
    // endpoint is truly live NDJSON, not a replay of already-written log lines.
    let mut stream = Command::new("curl")
        .args([
            "--unix-socket",
            socket_path.to_str().expect("UTF-8 socket path"),
            "-N",
            "http://localhost/alerts/stream",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alert-stream curl");

    let fixture_payload = threshold_fixture_payload("high_085");
    let predict_response = curl_json_with_stdin(
        &[
            "-fsS",
            "-H",
            "content-type: application/json",
            "-d",
            "@-",
            &format!("http://127.0.0.1:{port}/internal/predict"),
        ],
        &fixture_payload,
    );
    let predict_score = predict_response["threat_score"]
        .as_f64()
        .expect("threat_score number");
    assert_score_in_documented_band("high_085", predict_score);

    // Full-workspace nextest runs schedule many binaries in parallel, so give
    // the live alert-stream subscriber a little more headroom than the focused
    // local-api-only run before declaring the first alert missing.
    let first_alert_line = read_first_stream_line(&mut stream, Duration::from_secs(5))
        .expect("high_085 fixture should emit an alert");
    terminate_process(&mut stream);

    let first_alert: Value = serde_json::from_str(&first_alert_line).expect("alert JSON parses");
    assert_eq!(
        first_alert["binary_path"].as_str(),
        Some("/home/alexm/mini-edr/tests/fixtures/feature_vectors/high_085.json"),
        "alert stream must preserve the fixture identity the harness correlates on"
    );
    assert_score_in_documented_band(
        "high_085",
        first_alert["threat_score"]
            .as_f64()
            .expect("alert stream threat_score number"),
    );

    terminate_process(&mut daemon);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "This end-to-end contract test keeps the threshold and reload scenario in one linear narrative so each alert-stream assertion reads in execution order."
)]
fn threshold_boundary_and_reload_fixtures_follow_the_alert_stream_contract() {
    let exact_contract = threshold_fixture_contract("exact_threshold");
    let below_contract = threshold_fixture_contract("below_threshold");
    let threshold_065_contract = threshold_fixture_contract("threshold_065");
    let tempdir = TempDir::new().expect("tempdir");
    let socket_path = tempdir.path().join("api.sock");
    let config_path = write_logging_config(tempdir.path(), exact_contract.natural_score);
    let mut daemon = spawn_daemon(&config_path, &socket_path);
    let health = wait_for_unix_health(&mut daemon, &socket_path);
    let port: u16 = health["web_port"]
        .as_u64()
        .expect("web_port u64")
        .try_into()
        .expect("web_port fits in u16");

    let mut exact_stream = spawn_alert_stream(&socket_path);
    let exact_response = curl_json_with_stdin(
        &[
            "-fsS",
            "-H",
            "content-type: application/json",
            "-d",
            "@-",
            &format!("http://127.0.0.1:{port}/internal/predict"),
        ],
        &threshold_fixture_payload("exact_threshold"),
    );
    let exact_score = exact_response["threat_score"]
        .as_f64()
        .expect("exact threshold score number");
    assert_score_in_documented_band("exact_threshold", exact_score);
    assert!(
        approx_equal(exact_score, exact_contract.natural_score),
        "the exact-threshold fixture must preserve its documented natural score"
    );
    assert_eq!(
        exact_response["threshold"].as_f64(),
        Some(exact_contract.natural_score)
    );
    assert_eq!(exact_response["would_alert"].as_bool(), Some(true));
    let exact_alert = read_first_stream_line(&mut exact_stream, Duration::from_secs(2))
        .expect("exact-threshold fixture should alert");
    terminate_process(&mut exact_stream);
    let exact_alert: Value = serde_json::from_str(&exact_alert).expect("alert JSON parses");
    assert!(
        approx_equal(
            exact_alert["threat_score"]
                .as_f64()
                .expect("exact alert threat_score number"),
            exact_contract.natural_score
        ),
        "alert stream must preserve the documented exact-threshold score"
    );

    let alerts_before_reload = count_non_empty_lines(tempdir.path().join("logs/alerts.jsonl"));
    let mut below_stream = spawn_alert_stream(&socket_path);
    let below_response = curl_json_with_stdin(
        &[
            "-fsS",
            "-H",
            "content-type: application/json",
            "-d",
            "@-",
            &format!("http://127.0.0.1:{port}/internal/predict"),
        ],
        &threshold_fixture_payload("below_threshold"),
    );
    let below_score = below_response["threat_score"]
        .as_f64()
        .expect("below-threshold score number");
    assert_score_in_documented_band("below_threshold", below_score);
    assert!(
        below_score < exact_contract.natural_score,
        "the below-threshold fixture must stay below the documented exact threshold score"
    );
    assert!(
        approx_equal(below_score, below_contract.natural_score),
        "the below-threshold fixture must preserve its documented natural score"
    );
    assert!(
        read_first_stream_line(&mut below_stream, Duration::from_secs(1)).is_none(),
        "the below-threshold fixture must not emit an alert"
    );
    terminate_process(&mut below_stream);

    let event_log = fs::read_to_string(tempdir.path().join("logs/events.jsonl"))
        .expect("read inference event log");
    let event_log_contains_below_score = event_log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .any(|record| {
            approx_equal(
                record["score"].as_f64().unwrap_or_default(),
                below_contract.natural_score,
            )
        });
    assert!(
        event_log_contains_below_score,
        "suppressed inferences must still land in events.jsonl with the documented natural score"
    );

    let mut pre_reload_stream = spawn_alert_stream(&socket_path);
    let mid_response = curl_json_with_stdin(
        &[
            "-fsS",
            "-H",
            "content-type: application/json",
            "-d",
            "@-",
            &format!("http://127.0.0.1:{port}/internal/predict"),
        ],
        &threshold_fixture_payload("threshold_065"),
    );
    let mid_score = mid_response["threat_score"]
        .as_f64()
        .expect("mid fixture score number");
    assert_score_in_documented_band("threshold_065", mid_score);
    assert!(
        read_first_stream_line(&mut pre_reload_stream, Duration::from_secs(1)).is_none(),
        "the documented threshold_065 fixture must stay suppressed before the threshold change"
    );
    terminate_process(&mut pre_reload_stream);
    assert_eq!(
        count_non_empty_lines(tempdir.path().join("logs/alerts.jsonl")),
        alerts_before_reload,
        "pre-change suppressed fixtures must not append to alerts.jsonl"
    );

    rewrite_threshold_only_config(
        &config_path,
        tempdir.path().join("model.onnx").as_path(),
        0.6,
    );
    send_sighup(&daemon);
    wait_for_threshold(&socket_path, 0.6);

    let mut post_reload_stream = spawn_alert_stream(&socket_path);
    let post_reload_response = curl_json_with_stdin(
        &[
            "-fsS",
            "-H",
            "content-type: application/json",
            "-d",
            "@-",
            &format!("http://127.0.0.1:{port}/internal/predict"),
        ],
        &threshold_fixture_payload("threshold_065"),
    );
    assert!(
        post_reload_response["would_alert"]
            .as_bool()
            .unwrap_or(false),
        "lowering the threshold to 0.6 should make the documented threshold_065 fixture alert"
    );
    assert!(
        approx_equal(
            post_reload_response["threat_score"]
                .as_f64()
                .expect("post-reload threat_score number"),
            threshold_065_contract.natural_score
        ),
        "reloading the threshold must not change the natural model score"
    );
    let post_reload_alert = read_first_stream_line(&mut post_reload_stream, Duration::from_secs(2))
        .expect("post-reload threshold_065 fixture should alert");
    terminate_process(&mut post_reload_stream);
    let post_reload_alert: Value =
        serde_json::from_str(&post_reload_alert).expect("post-reload alert JSON parses");
    assert_eq!(
        post_reload_alert["binary_path"].as_str(),
        Some("/home/alexm/mini-edr/tests/fixtures/feature_vectors/threshold_065.json"),
    );
    assert_eq!(
        count_non_empty_lines(tempdir.path().join("logs/alerts.jsonl")),
        alerts_before_reload + 1,
        "the same fixture should append exactly one new alert after the threshold change"
    );

    terminate_process(&mut daemon);
}

#[test]
fn stale_socket_is_replaced_before_the_daemon_binds() {
    let tempdir = TempDir::new().expect("tempdir");
    let socket_path = tempdir.path().join("api.sock");
    let stale_listener = std::os::unix::net::UnixListener::bind(&socket_path)
        .expect("create stale socket placeholder");
    drop(stale_listener);

    let config_path = write_logging_config(tempdir.path(), 0.7);
    let mut daemon = spawn_daemon(&config_path, &socket_path);
    let _health = wait_for_unix_health(&mut daemon, &socket_path);

    let fresh_metadata = fs::metadata(&socket_path).expect("fresh socket metadata");
    assert!(
        fresh_metadata.file_type().is_socket(),
        "daemon should leave a live Unix socket at the configured path"
    );

    terminate_process(&mut daemon);
}

#[test]
fn live_socket_holder_returns_socket_in_use_error() {
    let tempdir = TempDir::new().expect("tempdir");
    let socket_path = tempdir.path().join("api.sock");
    let _live_listener =
        std::os::unix::net::UnixListener::bind(&socket_path).expect("bind live socket holder");
    let config_path = write_logging_config(tempdir.path(), 0.7);

    let mut child = Command::new(env!("CARGO_BIN_EXE_mini-edr-daemon"))
        .args(["--config", config_path.to_str().expect("UTF-8 config path")])
        .env("MINI_EDR_API_SOCKET", &socket_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon");

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll daemon exit") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "daemon never exited while a live process held the Unix socket"
        );
        thread::sleep(Duration::from_millis(50));
    };
    assert!(!status.success());

    let mut stderr = String::new();
    BufReader::new(child.stderr.take().expect("captured stderr"))
        .read_to_string(&mut stderr)
        .expect("read stderr bytes");
    assert!(
        stderr.contains("socket_in_use"),
        "expected socket_in_use policy in stderr, got: {stderr}"
    );
}

#[test]
fn sighup_swap_load_probe_enforces_throughput_and_cutover_at_smaller_scale() {
    let tempdir = TempDir::new().expect("tempdir");
    let model_v1 = copy_model(trained_model_path(), tempdir.path().join("model-v1.onnx"));
    let model_v2 = mutate_model_hash(&model_v1, tempdir.path().join("model-v2.onnx"));
    let socket_path = tempdir.path().join("api.sock");
    let config_path = tempdir.path().join("config.toml");
    write_reload_config(&config_path, &model_v1, 1.0);

    let mut daemon = spawn_daemon(&config_path, &socket_path);
    let health = wait_for_unix_health(&mut daemon, &socket_path);
    let port: u16 = health["web_port"]
        .as_u64()
        .expect("web_port u64")
        .try_into()
        .expect("web_port fits in u16");

    let summary =
        run_sighup_swap_load_probe(port, daemon.id(), &model_v2, &model_v1, 8, 2_048, 1_000.0);

    assert_eq!(summary["total_requests"].as_u64(), Some(2_048));
    assert_eq!(summary["thread_count"].as_u64(), Some(8));
    assert!(
        summary["achieved_rps"].as_f64().expect("achieved_rps f64") >= 1_000.0,
        "smaller-scale regression run must sustain at least 1k req/s"
    );
    assert_eq!(summary["late_v1_after_swap"].as_u64(), Some(0));
    assert_eq!(summary["health"]["state"].as_str(), Some("Running"));
    assert_eq!(summary["observed_hashes"].as_array().map(Vec::len), Some(2));

    terminate_process(&mut daemon);
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

fn write_reload_config(config_path: &Path, model_path: &Path, threshold: f64) {
    fs::write(
        config_path,
        format!(
            "alert_threshold = {threshold}\nweb_port = 0\nmodel_path = \"{}\"\nlog_file_path = \"alerts.jsonl\"\n",
            model_path.display()
        ),
    )
    .expect("write reload config");
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
    "mini-edr-local-api-load-probe-v2".clone_into(&mut model.producer_name);
    let mut encoded = Vec::with_capacity(model.encoded_len());
    model.encode(&mut encoded).expect("encode ONNX");
    fs::write(&destination, encoded).expect("write mutated model");
    destination
}

fn spawn_daemon(config_path: &Path, socket_path: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_mini-edr-daemon"))
        .args(["--config", config_path.to_str().expect("UTF-8 config path")])
        .env("MINI_EDR_API_SOCKET", socket_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon")
}

fn run_sighup_swap_load_probe(
    port: u16,
    daemon_pid: u32,
    swap_source: &Path,
    swap_destination: &Path,
    thread_count: usize,
    max_requests: usize,
    target_rps: f64,
) -> Value {
    let script_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/run_sighup_swap_load.py");
    let payload_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/feature_vectors/mixed_10k.jsonl");
    let output = Command::new(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../mini-edr-detection/training/.venv/bin/python"),
    )
    .arg(script_path)
    .args([
        "--port",
        &port.to_string(),
        "--payload-path",
        payload_path.to_str().expect("UTF-8 payload path"),
        "--swap-copy-from",
        swap_source.to_str().expect("UTF-8 model v2 path"),
        "--swap-copy-to",
        swap_destination.to_str().expect("UTF-8 model v1 path"),
        "--sighup-pid",
        &daemon_pid.to_string(),
        "--thread-count",
        &thread_count.to_string(),
        "--max-requests",
        &max_requests.to_string(),
        "--target-rps",
        &target_rps.to_string(),
        "--swap-delay-ms",
        "50",
    ])
    .output()
    .expect("run sighup swap load probe");
    assert!(
        output.status.success(),
        "sighup swap load probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("probe summary JSON parses")
}

fn spawn_alert_stream(socket_path: &Path) -> Child {
    let child = Command::new("curl")
        .args([
            "--unix-socket",
            socket_path.to_str().expect("UTF-8 socket path"),
            "-N",
            "http://localhost/alerts/stream",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alert-stream curl");
    // The integration tests subscribe first and then trigger a prediction. A
    // short delay keeps that ordering deterministic despite `curl` starting in
    // a separate child process.
    thread::sleep(Duration::from_millis(50));
    child
}

fn wait_for_unix_health(daemon: &mut Child, socket_path: &Path) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = daemon.try_wait().expect("poll daemon status");
        assert!(
            status.is_none(),
            "daemon exited early while waiting for /health"
        );

        if let Ok(output) = Command::new("curl")
            .args([
                "--unix-socket",
                socket_path.to_str().expect("UTF-8 socket path"),
                "-fsS",
                "http://localhost/health",
            ])
            .output()
            && output.status.success()
        {
            return serde_json::from_slice(&output.stdout).expect("Unix health JSON parses");
        }

        assert!(
            Instant::now() < deadline,
            "daemon Unix-socket health endpoint never became ready"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn curl_json(args: &[&str]) -> Value {
    let output = Command::new("curl").args(args).output().expect("run curl");
    assert!(
        output.status.success(),
        "curl {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("response JSON parses")
}

fn curl_json_with_stdin(args: &[&str], stdin: &str) -> Value {
    let mut child = Command::new("curl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn curl");
    {
        let mut handle = child.stdin.take().expect("curl stdin");
        handle
            .write_all(stdin.as_bytes())
            .expect("write curl stdin payload");
    }
    let output = child.wait_with_output().expect("collect curl output");
    assert!(
        output.status.success(),
        "curl {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("response JSON parses")
}

fn assert_telemetry_alias_contract(alias: &Value, canonical: &Value) {
    // `/telemetry` and `/telemetry/summary` are fetched sequentially, so the
    // daemon's live RSS sample can drift slightly between requests. The alias
    // contract is therefore "same stable fields, near-equal rss_bytes"
    // instead of byte-for-byte object equality.
    for field in [
        "alert_count_total",
        "events_per_second",
        "inference_latency_p99_ms",
        "ring_buffer_util",
        "uptime_seconds",
    ] {
        assert_eq!(
            alias[field], canonical[field],
            "legacy /telemetry/summary alias diverged for stable field {field}"
        );
    }

    let alias_rss = alias["rss_bytes"].as_u64().expect("alias rss_bytes u64");
    let canonical_rss = canonical["rss_bytes"]
        .as_u64()
        .expect("canonical rss_bytes u64");
    assert!(
        alias_rss.abs_diff(canonical_rss) < 1_000_000,
        "legacy /telemetry/summary alias diverged too far in rss_bytes: alias={alias_rss} canonical={canonical_rss}"
    );
}

fn read_first_stream_line(stream: &mut Child, timeout: Duration) -> Option<String> {
    let stdout = stream.stdout.take().expect("stream stdout");
    let reader = thread::spawn(move || {
        let mut line = String::new();
        let mut reader = BufReader::new(stdout);
        reader.read_line(&mut line).expect("read alert line");
        line
    });
    let deadline = Instant::now() + timeout;
    loop {
        if reader.is_finished() {
            return Some(reader.join().expect("stream reader thread"));
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn terminate_process(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn count_non_empty_lines(path: PathBuf) -> usize {
    fs::read_to_string(path)
        .expect("read JSONL file")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

fn rewrite_threshold_only_config(config_path: &Path, model_path: &Path, threshold: f64) {
    fs::write(
        config_path,
        format!(
            "alert_threshold = {threshold}\nweb_port = 0\nmodel_path = \"{}\"\nlog_file_path = \"alerts.jsonl\"\n",
            model_path.display()
        ),
    )
    .expect("rewrite config with new threshold");
}

fn send_sighup(child: &Child) {
    let status = Command::new("kill")
        .args(["-HUP", &child.id().to_string()])
        .status()
        .expect("send SIGHUP");
    assert!(status.success(), "sending SIGHUP failed");
}

fn approx_equal(left: f64, right: f64) -> bool {
    (left - right).abs() <= 1.0e-6
}

fn wait_for_threshold(socket_path: &Path, expected: f64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(output) = Command::new("curl")
            .args([
                "--unix-socket",
                socket_path.to_str().expect("UTF-8 socket path"),
                "-fsS",
                "http://localhost/health",
            ])
            .output()
            && output.status.success()
        {
            let health: Value = serde_json::from_slice(&output.stdout).expect("health JSON parses");
            if health["alert_threshold"].as_f64() == Some(expected) {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "daemon never reported alert_threshold={expected}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}
