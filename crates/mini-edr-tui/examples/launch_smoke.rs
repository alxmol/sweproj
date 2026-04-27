//! PTY-driven smoke harness for the Mini-EDR TUI.
//!
//! The example feeds deterministic broadcast snapshots into `TuiApp` so
//! tuistory can verify cold-start loading, empty-timeline text, and degraded
//! warnings without needing the full daemon wiring yet.

use mini_edr_tui::{DaemonMode, ProcessTreeNode, TuiApp, TuiTelemetry};
use std::{env, time::Duration};
use tokio::{sync::broadcast, time::sleep};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = env::var("MINI_EDR_TUI_SCENARIO").unwrap_or_else(|_| "normal".to_owned());
    let auto_quit_after = env::var("MINI_EDR_TUI_AUTOQUIT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .or(Some(Duration::from_millis(3_000)));

    let (alert_sender, alert_receiver) = broadcast::channel(8);
    let (telemetry_sender, telemetry_receiver) = broadcast::channel(8);

    let feed_scenario = scenario;
    tokio::spawn(async move {
        // Delay the first snapshot so the loading placeholder remains visible
        // long enough for VAL-TUI-001 / TC-60 PTY captures at t=+150 ms.
        sleep(Duration::from_millis(500)).await;

        let daemon_mode = if feed_scenario.eq_ignore_ascii_case("degraded") {
            DaemonMode::Degraded
        } else {
            DaemonMode::Running
        };
        let _ = telemetry_sender.send(TuiTelemetry {
            daemon_mode,
            processes: vec![
                ProcessTreeNode::new(1, "systemd", Some(0.02), 0),
                ProcessTreeNode::new(2457, "mini-edr-daemon", Some(0.08), 1),
                ProcessTreeNode::new(8120, "sleep 30", None, 2),
            ],
            events_per_second: 1_000.0,
            ring_buffer_utilization: 0.18,
            average_inference_latency_ms: 4.3,
            uptime: Duration::from_secs(42),
        });

        // Keep the alert sender alive for the life of the app so the empty
        // timeline remains a true "no alerts yet" state instead of looking
        // empty because the channel closed.
        sleep(Duration::from_secs(10)).await;
        drop(alert_sender);
    });

    TuiApp::new(alert_receiver, telemetry_receiver).run(auto_quit_after)?;
    Ok(())
}
