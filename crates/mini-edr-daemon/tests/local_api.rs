//! Integration tests for the daemon-owned localhost and Unix-socket API.
//!
//! These tests intentionally launch the real `mini-edr-daemon` binary because
//! the local API contract spans multiple concerns at once: HTTP routing,
//! Unix-socket lifecycle policy, alert streaming, and startup error handling.

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use tempfile::TempDir;

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
    assert_eq!(
        telemetry_summary, telemetry,
        "legacy /telemetry/summary alias diverged"
    );

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

    let fixture_payload = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/feature_vectors/high_085.json"),
    )
    .expect("read high_085 fixture");
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
    assert!(
        (0.84..=0.86).contains(
            &predict_response["threat_score"]
                .as_f64()
                .expect("threat_score number")
        ),
        "the calibrated daemon score should honor the high_085 fixture contract"
    );

    let first_alert_line = read_first_stream_line(&mut stream, Duration::from_secs(2))
        .expect("high_085 fixture should emit an alert");
    terminate_process(&mut stream);

    let first_alert: Value = serde_json::from_str(&first_alert_line).expect("alert JSON parses");
    assert_eq!(
        first_alert["binary_path"].as_str(),
        Some("/home/alexm/mini-edr/tests/fixtures/feature_vectors/high_085.json"),
        "alert stream must preserve the fixture identity the harness correlates on"
    );
    assert!(
        (0.84..=0.86).contains(
            &first_alert["threat_score"]
                .as_f64()
                .expect("alert stream threat_score number")
        ),
        "alert stream must publish the same calibrated threat score"
    );

    terminate_process(&mut daemon);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "This end-to-end contract test keeps the threshold and reload scenario in one linear narrative so each alert-stream assertion reads in execution order."
)]
fn threshold_boundary_and_reload_fixtures_follow_the_alert_stream_contract() {
    let tempdir = TempDir::new().expect("tempdir");
    let socket_path = tempdir.path().join("api.sock");
    let config_path = write_logging_config(tempdir.path(), 0.7);
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
        &fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/feature_vectors/exact_threshold.json"),
        )
        .expect("read exact-threshold fixture"),
    );
    assert_eq!(exact_response["threat_score"].as_f64(), Some(0.7));
    let exact_alert = read_first_stream_line(&mut exact_stream, Duration::from_secs(2))
        .expect("exact-threshold fixture should alert");
    terminate_process(&mut exact_stream);
    let exact_alert: Value = serde_json::from_str(&exact_alert).expect("alert JSON parses");
    assert_eq!(exact_alert["threat_score"].as_f64(), Some(0.7));

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
        &fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/feature_vectors/below_threshold.json"),
        )
        .expect("read below-threshold fixture"),
    );
    assert_eq!(below_response["threat_score"].as_f64(), Some(0.6999));
    assert!(
        read_first_stream_line(&mut below_stream, Duration::from_secs(1)).is_none(),
        "the below-threshold fixture must not emit an alert"
    );
    terminate_process(&mut below_stream);

    let event_log = fs::read_to_string(tempdir.path().join("logs/events.jsonl"))
        .expect("read inference event log");
    assert!(
        event_log.contains("\"score\":0.6999"),
        "suppressed inferences must still land in events.jsonl with the calibrated score"
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
        &fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/feature_vectors/threshold_065.json"),
        )
        .expect("read threshold_065 fixture"),
    );
    let mid_score = mid_response["threat_score"]
        .as_f64()
        .expect("mid fixture score number");
    assert!(
        (0.6..0.7).contains(&mid_score),
        "the calibrated threshold_065 fixture must stay inside the requested [0.6, 0.7) band"
    );
    assert!(
        read_first_stream_line(&mut pre_reload_stream, Duration::from_secs(1)).is_none(),
        "the 0.65 fixture must stay suppressed before the threshold change"
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
        &fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/feature_vectors/threshold_065.json"),
        )
        .expect("read threshold_065 fixture"),
    );
    assert!(
        post_reload_response["would_alert"]
            .as_bool()
            .unwrap_or(false),
        "lowering the threshold to 0.6 should make the same fixture alert"
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

fn spawn_daemon(config_path: &Path, socket_path: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_mini-edr-daemon"))
        .args(["--config", config_path.to_str().expect("UTF-8 config path")])
        .env("MINI_EDR_API_SOCKET", socket_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon")
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
