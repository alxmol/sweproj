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

        let _ = telemetry_sender.send(telemetry_for_scenario(&feed_scenario));

        // Keep the alert sender alive for the life of the app so the empty
        // timeline remains a true "no alerts yet" state instead of looking
        // empty because the channel closed.
        sleep(Duration::from_secs(10)).await;
        drop(alert_sender);
    });

    TuiApp::new(alert_receiver, telemetry_receiver).run(auto_quit_after)?;
    Ok(())
}

fn telemetry_for_scenario(scenario: &str) -> TuiTelemetry {
    // The smoke harness intentionally synthesizes deterministic process trees so
    // tuistory can validate rendering invariants without depending on the full
    // daemon broadcast wiring.
    match scenario {
        "color_partition" => TuiTelemetry {
            daemon_mode: DaemonMode::Running,
            processes: vec![
                ProcessTreeNode::new(1001, "green-low", Some(0.10), 0),
                ProcessTreeNode::new(1002, "yellow-mid", Some(0.50), 1),
                ProcessTreeNode::new(1003, "red-high", Some(0.90), 1),
                ProcessTreeNode::new(1004, "green-boundary", Some(0.299), 2),
                ProcessTreeNode::new(1005, "yellow-boundary", Some(0.300), 2),
                ProcessTreeNode::new(1006, "yellow-upper", Some(0.699), 2),
                ProcessTreeNode::new(1007, "red-boundary", Some(0.700), 2),
            ],
            events_per_second: 512.0,
            ring_buffer_utilization: 0.14,
            average_inference_latency_ms: 3.6,
            uptime: Duration::from_secs(15),
        },
        "deep_tree" => TuiTelemetry {
            daemon_mode: DaemonMode::Running,
            processes: (0_u32..1_200)
                .map(|depth| {
                    ProcessTreeNode::new(
                        4_000 + depth,
                        format!("node-{depth:04}"),
                        Some(f64::from(depth % 10) / 10.0),
                        u16::try_from(depth).expect("deep-tree smoke depth fits in u16"),
                    )
                })
                .collect(),
            events_per_second: 4_096.0,
            ring_buffer_utilization: 0.33,
            average_inference_latency_ms: 7.5,
            uptime: Duration::from_secs(120),
        },
        "control_chars" => TuiTelemetry {
            daemon_mode: DaemonMode::Running,
            processes: vec![
                ProcessTreeNode::new(2001, "benign-before", Some(0.11), 0),
                ProcessTreeNode::new(2002, "\u{0007}\u{001b}[2J\u{001b}[Hpwn", Some(0.82), 1),
                ProcessTreeNode::new(2003, "benign-after", Some(0.05), 1),
            ],
            events_per_second: 256.0,
            ring_buffer_utilization: 0.09,
            average_inference_latency_ms: 2.1,
            uptime: Duration::from_secs(9),
        },
        "degraded" => TuiTelemetry {
            daemon_mode: DaemonMode::Degraded,
            ..normal_telemetry()
        },
        _ => normal_telemetry(),
    }
}

fn normal_telemetry() -> TuiTelemetry {
    TuiTelemetry {
        daemon_mode: DaemonMode::Running,
        processes: vec![
            ProcessTreeNode::new(1, "systemd", Some(0.02), 0),
            ProcessTreeNode::new(2457, "mini-edr-daemon", Some(0.08), 1),
            ProcessTreeNode::new(8120, "sleep 30", None, 2),
        ],
        events_per_second: 1_000.0,
        ring_buffer_utilization: 0.18,
        average_inference_latency_ms: 4.3,
        uptime: Duration::from_secs(42),
    }
}
