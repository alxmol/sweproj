//! Integration tests for the daemon-owned localhost and Unix-socket API.
//!
//! These tests intentionally launch the real `mini-edr-daemon` binary because
//! the local API contract spans multiple concerns at once: HTTP routing,
//! Unix-socket lifecycle policy, alert streaming, and startup error handling.

mod support;

use std::{
    fs,
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    os::unix::{fs::FileTypeExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use onnx_pb::ModelProto;
use prost::Message;
use serde_json::{Value, json};
use tempfile::{NamedTempFile, TempDir};

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
    let mut stream = connect_alert_stream(&socket_path);

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
fn dashboard_root_serves_html_on_the_configured_localhost_port() {
    let tempdir = TempDir::new().expect("tempdir");
    let socket_path = tempdir.path().join("api.sock");
    let configured_port = 9_191;
    let config_path = write_logging_config_with_port(tempdir.path(), 0.7, configured_port);
    let mut daemon = spawn_daemon(&config_path, &socket_path);
    let health = wait_for_unix_health(&mut daemon, &socket_path);

    assert_eq!(
        health["web_port"].as_u64(),
        Some(u64::from(configured_port))
    );

    let html = curl_text(&["-fsS", &format!("http://127.0.0.1:{configured_port}/")]);
    assert!(html.contains("<title>Mini-EDR</title>"));
    assert!(html.contains("Mini-EDR"));
    assert!(html.contains("aria-label=\"Settings\""));
    assert!(html.contains("id=\"process-tree\""));

    let listeners = Command::new("ss").args(["-tln"]).output().expect("run ss");
    assert!(listeners.status.success(), "ss -tln should succeed");
    let listeners = String::from_utf8(listeners.stdout).expect("utf8 ss output");
    assert!(
        listeners.contains(&format!("127.0.0.1:{configured_port}")),
        "expected localhost listener on configured port, got:\n{listeners}"
    );
    assert!(
        !listeners.contains(&format!("0.0.0.0:{configured_port}")),
        "dashboard must not bind wildcard addresses:\n{listeners}"
    );
    assert!(
        !listeners.contains(&format!("*:{configured_port}")),
        "dashboard must not bind wildcard addresses:\n{listeners}"
    );

    terminate_process(&mut daemon);
}

#[test]
fn dashboard_process_routes_surface_injected_tree_and_detail_payloads() {
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
    let csrf_token = fetch_csrf_token(port);

    let injected_snapshot = json!({
        "processes": [
            {
                "pid": 9001,
                "process_name": "мойбин-🔥",
                "binary_path": "/opt/demo/мойбин-🔥",
                "threat_score": 0.9,
                "depth": 4,
                "detail": {
                    "ancestry_chain": [
                        {
                            "pid": 1,
                            "process_name": "systemd",
                            "binary_path": "/usr/lib/systemd/systemd"
                        },
                        {
                            "pid": 9001,
                            "process_name": "мойбин-🔥",
                            "binary_path": "/opt/demo/мойбин-🔥"
                        }
                    ],
                    "feature_vector": [
                        {"label": "entropy", "value": "0.900"}
                    ],
                    "recent_syscalls": ["execve ×1", "openat ×2"],
                    "threat_score": 0.9,
                    "top_features": [
                        {"feature_name": "entropy", "contribution_score": 0.42}
                    ]
                },
                "exited": false
            }
        ]
    });
    let injected_response = dashboard_post_json(
        port,
        "/internal/dashboard/process-tree",
        &injected_snapshot,
        &csrf_token,
    );
    assert_eq!(injected_response, injected_snapshot);

    for path in ["/processes", "/api/processes"] {
        let payload = curl_json(&["-fsS", &format!("http://127.0.0.1:{port}{path}")]);
        assert_eq!(
            payload, injected_snapshot,
            "{path} should mirror the injected snapshot"
        );
    }

    let html = curl_text(&["-fsS", &format!("http://127.0.0.1:{port}/")]);
    assert!(html.contains("id=\"process-detail\""));
    assert!(html.contains("Top Features"));

    terminate_process(&mut daemon);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "The CSRF regression exercises all three mutable dashboard routes plus the unchanged-state checks in one end-to-end sequence."
)]
fn dashboard_mutation_routes_require_origin_and_csrf_before_they_change_state() {
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

    let initial_processes = curl_json(&["-fsS", &format!("http://127.0.0.1:{port}/api/processes")]);
    let initial_alerts = curl_json(&[
        "-fsS",
        &format!("http://127.0.0.1:{port}/api/dashboard/alerts"),
    ]);

    let injected_process_tree = json!({
        "processes": [
            {
                "pid": 7_001,
                "process_name": "csrf-process",
                "binary_path": "/tmp/csrf-process",
                "threat_score": 0.91,
                "depth": 1,
                "detail": {
                    "ancestry_chain": [
                        {
                            "pid": 1,
                            "process_name": "systemd",
                            "binary_path": "/usr/lib/systemd/systemd"
                        },
                        {
                            "pid": 7_001,
                            "process_name": "csrf-process",
                            "binary_path": "/tmp/csrf-process"
                        }
                    ],
                    "feature_vector": [
                        {"label": "entropy", "value": "0.910"}
                    ],
                    "recent_syscalls": ["openat ×1"],
                    "threat_score": 0.91,
                    "top_features": [
                        {"feature_name": "entropy", "contribution_score": 0.91}
                    ]
                },
                "exited": false
            }
        ]
    });
    let replaced_alerts = json!({
        "alerts": [
            sample_dashboard_alert(8_001, "csrf-replaced", 0.83)
        ]
    });
    let emitted_alerts = json!({
        "alerts": [
            sample_dashboard_alert(8_002, "csrf-emitted", 0.94)
        ]
    });

    let (process_status, process_error) = dashboard_post_status_json(
        port,
        "/internal/dashboard/process-tree",
        &injected_process_tree,
        "http://evil.example",
        None,
    );
    assert_eq!(process_status, 403);
    assert_eq!(
        process_error["error"].as_str(),
        Some("cross-origin requests are forbidden")
    );
    assert_eq!(
        curl_json(&["-fsS", &format!("http://127.0.0.1:{port}/api/processes")]),
        initial_processes,
        "cross-origin process-tree posts must not mutate the dashboard snapshot"
    );

    let (replace_status, replace_error) = dashboard_post_status_json(
        port,
        "/internal/dashboard/alerts",
        &replaced_alerts,
        "http://evil.example",
        None,
    );
    assert_eq!(replace_status, 403);
    assert_eq!(
        replace_error["error"].as_str(),
        Some("cross-origin requests are forbidden")
    );
    assert_eq!(
        curl_json(&[
            "-fsS",
            &format!("http://127.0.0.1:{port}/api/dashboard/alerts"),
        ]),
        initial_alerts,
        "cross-origin alert replacement must leave the dashboard timeline untouched"
    );

    let (emit_status, emit_error) = dashboard_post_status_json(
        port,
        "/internal/dashboard/alerts/emit",
        &emitted_alerts,
        "http://evil.example",
        None,
    );
    assert_eq!(emit_status, 403);
    assert_eq!(
        emit_error["error"].as_str(),
        Some("cross-origin requests are forbidden")
    );
    assert_eq!(
        curl_json(&[
            "-fsS",
            &format!("http://127.0.0.1:{port}/api/dashboard/alerts"),
        ]),
        initial_alerts,
        "forged alert emission must not append dashboard rows before CSRF passes"
    );

    let csrf_token = fetch_csrf_token(port);
    let injected_process_response = dashboard_post_json(
        port,
        "/internal/dashboard/process-tree",
        &injected_process_tree,
        &csrf_token,
    );
    assert_eq!(injected_process_response, injected_process_tree);
    assert_eq!(
        curl_json(&["-fsS", &format!("http://127.0.0.1:{port}/api/processes")]),
        injected_process_tree
    );

    let replaced_alert_response = dashboard_post_json(
        port,
        "/internal/dashboard/alerts",
        &replaced_alerts,
        &csrf_token,
    );
    assert_eq!(replaced_alert_response, replaced_alerts);
    assert_eq!(
        curl_json(&[
            "-fsS",
            &format!("http://127.0.0.1:{port}/api/dashboard/alerts"),
        ]),
        replaced_alerts
    );

    let emitted_alert_response = dashboard_post_json(
        port,
        "/internal/dashboard/alerts/emit",
        &emitted_alerts,
        &csrf_token,
    );
    assert_eq!(emitted_alert_response, emitted_alerts);
    let updated_alerts = curl_json(&[
        "-fsS",
        &format!("http://127.0.0.1:{port}/api/dashboard/alerts"),
    ]);
    assert_eq!(updated_alerts["alerts"].as_array().map(Vec::len), Some(2));
    assert!(
        updated_alerts["alerts"]
            .as_array()
            .expect("alerts array")
            .iter()
            .any(|alert| alert["process_name"].as_str() == Some("csrf-emitted")),
        "same-origin + CSRF alert emission should append the emitted alert"
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

    let mut exact_stream = connect_alert_stream(&socket_path);
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
    let mut below_stream = connect_alert_stream(&socket_path);
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

    let mut pre_reload_stream = connect_alert_stream(&socket_path);
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

    let mut post_reload_stream = connect_alert_stream(&socket_path);
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
    let daemon_output = read_captured_output(&mut daemon);
    let rendered_socket_path = socket_path.display().to_string();
    assert!(
        daemon_output.contains("stale_socket_removed"),
        "daemon output should prove the stale-socket cleanup path ran, got: {daemon_output}"
    );
    assert!(
        daemon_output.contains(&rendered_socket_path),
        "daemon output should mention the removed stale socket path `{rendered_socket_path}`, got: {daemon_output}"
    );
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
    write_logging_config_with_port(tempdir, threshold, 0)
}

fn write_logging_config_with_port(tempdir: &Path, threshold: f64, web_port: u16) -> PathBuf {
    let config_path = tempdir.join("config.toml");
    let model_path = copy_model(trained_model_path(), tempdir.join("model.onnx"));
    let state_dir = tempdir.join("state");
    fs::create_dir_all(&state_dir).expect("create writable state directory");
    fs::write(
        &config_path,
        format!(
            "alert_threshold = {threshold}\nweb_port = {web_port}\nmodel_path = \"{}\"\nlog_file_path = \"alerts.jsonl\"\nstate_dir = \"{}\"\n",
            model_path.display(),
            state_dir.display()
        ),
    )
    .expect("write config");
    config_path
}

fn write_reload_config(config_path: &Path, model_path: &Path, threshold: f64) {
    let state_dir = config_path
        .parent()
        .expect("config path has parent")
        .join("state");
    fs::create_dir_all(&state_dir).expect("create writable state directory");
    fs::write(
        config_path,
        format!(
            "alert_threshold = {threshold}\nweb_port = 0\nmodel_path = \"{}\"\nlog_file_path = \"alerts.jsonl\"\nstate_dir = \"{}\"\n",
            model_path.display(),
            state_dir.display()
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
        .stdout(Stdio::piped())
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

fn connect_alert_stream(socket_path: &Path) -> AlertStream {
    let mut stream = UnixStream::connect(socket_path).expect("connect alert stream socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("configure alert stream read timeout");
    stream
        .write_all(
            b"GET /alerts/stream HTTP/1.0\r\nHost: localhost\r\nAccept: application/x-ndjson\r\n\r\n",
        )
        .expect("send alert stream request");

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .expect("read alert stream status line");
    assert!(
        status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200"),
        "alert stream should return HTTP 200, got `{status_line}`"
    );

    loop {
        let mut header_line = String::new();
        reader
            .read_line(&mut header_line)
            .expect("read alert stream header line");
        if header_line == "\r\n" {
            break;
        }
        assert!(
            !header_line.is_empty(),
            "alert stream closed before finishing HTTP headers"
        );
    }

    AlertStream { reader }
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

fn curl_text(args: &[&str]) -> String {
    let output = Command::new("curl").args(args).output().expect("run curl");
    assert!(
        output.status.success(),
        "curl {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("response body utf8")
}

fn dashboard_origin(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

fn fetch_csrf_token(port: u16) -> String {
    curl_json(&[
        "-fsS",
        &format!("http://127.0.0.1:{port}/api/settings/csrf"),
    ])["token"]
        .as_str()
        .expect("csrf token string")
        .to_owned()
}

fn dashboard_post_json(port: u16, path: &str, payload: &Value, csrf_token: &str) -> Value {
    let origin = dashboard_origin(port);
    curl_json_with_stdin(
        &[
            "-fsS",
            "-H",
            "content-type: application/json",
            "-H",
            &format!("Origin: {origin}"),
            "-H",
            &format!("x-csrf-token: {csrf_token}"),
            "-d",
            "@-",
            &format!("http://127.0.0.1:{port}{path}"),
        ],
        &payload.to_string(),
    )
}

fn dashboard_post_status_json(
    port: u16,
    path: &str,
    payload: &Value,
    origin: &str,
    csrf_token: Option<&str>,
) -> (u16, Value) {
    let response_file = NamedTempFile::new().expect("response temp file");
    let mut command = Command::new("curl");
    command
        .args([
            "-sS",
            "-o",
            response_file
                .path()
                .to_str()
                .expect("UTF-8 response file path"),
            "-w",
            "%{http_code}",
            "-H",
            "content-type: application/json",
            "-H",
            &format!("Origin: {origin}"),
        ])
        .args(csrf_token.map_or_else(Vec::new, |token| {
            vec!["-H".to_owned(), format!("x-csrf-token: {token}")]
        }))
        .args(["-d", "@-", &format!("http://127.0.0.1:{port}{path}")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn curl");
    {
        let mut handle = child.stdin.take().expect("curl stdin");
        handle
            .write_all(payload.to_string().as_bytes())
            .expect("write curl stdin payload");
    }
    let output = child.wait_with_output().expect("collect curl output");
    assert!(
        output.status.success(),
        "curl {path} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status = String::from_utf8(output.stdout)
        .expect("utf8 curl status")
        .parse::<u16>()
        .expect("curl status code");
    let body = fs::read_to_string(response_file.path()).expect("read response body");
    (
        status,
        serde_json::from_str(&body).expect("error response JSON parses"),
    )
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

fn sample_dashboard_alert(alert_id: u64, process_name: &str, threat_score: f64) -> Value {
    json!({
        "alert_id": alert_id,
        "timestamp": "2026-04-27T10:00:00Z",
        "pid": alert_id,
        "process_name": process_name,
        "binary_path": format!("/tmp/{process_name}"),
        "ancestry_chain": [
            {
                "pid": 1,
                "process_name": "systemd",
                "binary_path": "/usr/lib/systemd/systemd"
            }
        ],
        "threat_score": threat_score,
        "top_features": [
            {"feature_name": "entropy", "contribution_score": threat_score}
        ],
        "summary": format!("{process_name} summary")
    })
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

fn read_first_stream_line(stream: &mut AlertStream, timeout: Duration) -> Option<String> {
    stream
        .reader
        .get_mut()
        .set_read_timeout(Some(timeout))
        .expect("configure alert stream body timeout");
    let mut line = String::new();
    match stream.reader.read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => Some(line),
        Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => None,
        Err(error) => panic!("read alert line: {error}"),
    }
}

struct AlertStream {
    reader: BufReader<UnixStream>,
}

fn terminate_process(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn read_captured_output(child: &mut Child) -> String {
    let mut output = String::new();
    if let Some(mut stdout_handle) = child.stdout.take() {
        stdout_handle
            .read_to_string(&mut output)
            .expect("read captured daemon stdout");
    }
    if let Some(mut stderr_handle) = child.stderr.take() {
        stderr_handle
            .read_to_string(&mut output)
            .expect("read captured daemon stderr");
    }
    output
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
