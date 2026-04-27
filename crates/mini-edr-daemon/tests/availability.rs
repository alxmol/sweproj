//! Integration tests for availability-specific daemon behavior.
//!
//! These tests intentionally reuse the real daemon binary in deterministic
//! test-mode sensor mode so the system-test shell harnesses have a fast,
//! capability-free contract check in CI and local nextest runs.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use tempfile::TempDir;

#[test]
fn synthetic_probe_reload_restores_connect_events_within_one_second() {
    let tempdir = TempDir::new().expect("tempdir");
    let socket_path = tempdir.path().join("api.sock");
    let config_path = write_logging_config(tempdir.path(), 0.7);
    let mut daemon = spawn_availability_daemon(
        &config_path,
        &socket_path,
        &[
            ("MINI_EDR_TEST_SENSOR_RATE", "20"),
            ("MINI_EDR_TEST_SENSOR_PID_COUNT", "32"),
            ("MINI_EDR_TEST_SENSOR_RECONNECT_DELAY_MS", "200"),
        ],
    );
    let health = wait_for_unix_health(&mut daemon, &socket_path);
    let port: u16 = health["web_port"]
        .as_u64()
        .expect("web_port u64")
        .try_into()
        .expect("web_port fits in u16");

    let baseline_connect_id = wait_for_connect_event_id(port, Duration::from_secs(2));
    curl_json(&[
        "-fsS",
        "-X",
        "POST",
        &format!("http://127.0.0.1:{port}/api/probes/connect/detach"),
    ]);
    let detached = curl_json(&["-fsS", &format!("http://127.0.0.1:{port}/api/health")]);
    assert!(
        !detached["active_probes"]
            .as_array()
            .expect("active_probes array")
            .iter()
            .any(|probe| probe.as_str() == Some("connect"))
    );

    curl_json(&[
        "-fsS",
        "-X",
        "POST",
        &format!("http://127.0.0.1:{port}/api/probes/connect/attach"),
    ]);
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let next_connect_id = wait_for_connect_event_id(port, Duration::from_millis(250));
        if next_connect_id > baseline_connect_id {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for a fresh synthetic connect event after reattach"
        );
        thread::sleep(Duration::from_millis(50));
    }

    let daemon_log =
        fs::read_to_string(tempdir.path().join("logs/daemon.log")).expect("read daemon log");
    assert!(daemon_log.contains("ringbuf_reconnected"));
    terminate_process(&mut daemon);
}

#[test]
fn synthetic_memory_pressure_surfaces_backpressure_and_window_evictions() {
    let tempdir = TempDir::new().expect("tempdir");
    let socket_path = tempdir.path().join("api.sock");
    let config_path = write_logging_config(tempdir.path(), 0.7);
    let mut daemon = spawn_availability_daemon(
        &config_path,
        &socket_path,
        &[
            ("MINI_EDR_TEST_SENSOR_RATE", "100000"),
            ("MINI_EDR_TEST_SENSOR_PID_COUNT", "10000"),
            ("MINI_EDR_TEST_MAX_ACTIVE_WINDOWS", "64"),
        ],
    );
    let health = wait_for_unix_health(&mut daemon, &socket_path);
    let port: u16 = health["web_port"]
        .as_u64()
        .expect("web_port u64")
        .try_into()
        .expect("web_port fits in u16");

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let pressure = curl_json(&["-fsS", &format!("http://127.0.0.1:{port}/api/health")]);
        if pressure["state"].as_str() == Some("BackPressure")
            && pressure["ring_events_dropped_total"]
                .as_u64()
                .unwrap_or_default()
                > 0
            && pressure["windows_evicted_total"]
                .as_u64()
                .unwrap_or_default()
                > 0
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "synthetic pressure never surfaced BackPressure with both drop counters"
        );
        thread::sleep(Duration::from_millis(100));
    }

    terminate_process(&mut daemon);
}

fn trained_model_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../training/output/model.onnx")
        .canonicalize()
        .expect("training output model exists")
}

fn write_logging_config(tempdir: &Path, threshold: f64) -> PathBuf {
    let config_path = tempdir.join("config.toml");
    let model_path = tempdir.join("model.onnx");
    fs::copy(trained_model_path(), &model_path).expect("copy model");
    let state_dir = tempdir.join("state");
    fs::create_dir_all(&state_dir).expect("create state dir");
    fs::write(
        &config_path,
        format!(
            "alert_threshold = {threshold}\nweb_port = 0\nmodel_path = \"{}\"\nlog_file_path = \"alerts.jsonl\"\nstate_dir = \"{}\"\nenable_tui = false\nenable_web = false\n",
            model_path.display(),
            state_dir.display()
        ),
    )
    .expect("write daemon config");
    config_path
}

fn spawn_availability_daemon(
    config_path: &Path,
    socket_path: &Path,
    extra_env: &[(&str, &str)],
) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-edr-daemon"));
    command
        .args(["--config", config_path.to_str().expect("UTF-8 config path")])
        .env("MINI_EDR_API_SOCKET", socket_path)
        .env("MINI_EDR_TEST_MODE", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in extra_env {
        command.env(name, value);
    }
    command.spawn().expect("spawn daemon")
}

fn wait_for_unix_health(daemon: &mut Child, socket_path: &Path) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            daemon.try_wait().expect("poll daemon status").is_none(),
            "daemon exited early while waiting for /health"
        );
        let output = Command::new("curl")
            .args([
                "--unix-socket",
                socket_path.to_str().expect("UTF-8 socket path"),
                "-fsS",
                "http://localhost/health",
            ])
            .output()
            .expect("run curl");
        if output.status.success() {
            return serde_json::from_slice(&output.stdout).expect("health JSON parses");
        }
        assert!(
            Instant::now() < deadline,
            "daemon Unix-socket health never became ready"
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

fn wait_for_connect_event_id(port: u16, timeout: Duration) -> u64 {
    let deadline = Instant::now() + timeout;
    loop {
        let events = curl_json(&[
            "-fsS",
            &format!("http://127.0.0.1:{port}/api/events?limit=200"),
        ]);
        if let Some(event_id) = events
            .as_array()
            .expect("events array")
            .iter()
            .filter(|event| event["syscall_type"].as_str() == Some("Connect"))
            .filter_map(|event| event["event_id"].as_u64())
            .max()
        {
            return event_id;
        }
        assert!(
            Instant::now() < deadline,
            "at least one synthetic connect event should arrive before the deadline"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn terminate_process(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
