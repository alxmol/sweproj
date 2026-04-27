//! PTY-driven smoke harness for the Mini-EDR TUI.
//!
//! The example feeds deterministic broadcast snapshots into `TuiApp` so
//! tuistory can verify cold-start loading, empty-timeline text, and degraded
//! warnings without needing the full daemon wiring yet.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use mini_edr_common::{Alert, FeatureContribution, ProcessInfo};
use mini_edr_tui::{
    DaemonMode, ProcessDetail, ProcessDetailField, ProcessTreeNode, TuiApp, TuiTelemetry,
};
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

    let (alert_sender, alert_receiver) = broadcast::channel(64);
    let (telemetry_sender, telemetry_receiver) = broadcast::channel(8);

    let feed_scenario = scenario;
    tokio::spawn(async move {
        // Delay the first snapshot so the loading placeholder remains visible
        // long enough for VAL-TUI-001 / TC-60 PTY captures at t=+150 ms.
        sleep(Duration::from_millis(500)).await;
        for alert in alerts_for_scenario(&feed_scenario) {
            let _ = alert_sender.send(alert);
        }
        for telemetry in telemetry_updates_for_scenario(&feed_scenario) {
            let _ = telemetry_sender.send(telemetry);
            sleep(Duration::from_secs(1)).await;
        }

        // Keep the alert sender alive for the life of the app so the empty
        // timeline remains a true "no alerts yet" state instead of looking
        // empty because the channel closed.
        sleep(Duration::from_secs(10)).await;
        drop(alert_sender);
    });

    TuiApp::new(alert_receiver, telemetry_receiver).run(auto_quit_after)?;
    Ok(())
}

fn telemetry_updates_for_scenario(scenario: &str) -> Vec<TuiTelemetry> {
    // The smoke harness intentionally synthesizes deterministic process trees so
    // tuistory can validate rendering invariants without depending on the full
    // daemon broadcast wiring.
    match scenario {
        "color_partition" => vec![TuiTelemetry {
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
        }],
        "deep_tree" => vec![TuiTelemetry {
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
        }],
        "control_chars" => vec![TuiTelemetry {
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
        }],
        "detail_view" => vec![detail_view_telemetry()],
        "exited_process" => vec![
            exited_process_initial_telemetry(),
            exited_process_follow_up_telemetry(),
        ],
        "degraded" => {
            let mut telemetry = normal_telemetry();
            telemetry.daemon_mode = DaemonMode::Degraded;
            vec![telemetry]
        }
        "status_updates" => vec![
            TuiTelemetry {
                events_per_second: 980.0,
                ring_buffer_utilization: 0.18,
                average_inference_latency_ms: 4.3,
                uptime: Duration::from_secs(42),
                ..normal_telemetry()
            },
            TuiTelemetry {
                events_per_second: 1_004.0,
                ring_buffer_utilization: 0.24,
                average_inference_latency_ms: 5.1,
                uptime: Duration::from_secs(43),
                ..normal_telemetry()
            },
            TuiTelemetry {
                events_per_second: 1_020.0,
                ring_buffer_utilization: 0.31,
                average_inference_latency_ms: 6.4,
                uptime: Duration::from_secs(44),
                ..normal_telemetry()
            },
        ],
        _ => vec![normal_telemetry()],
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

fn detail_view_telemetry() -> TuiTelemetry {
    TuiTelemetry {
        daemon_mode: DaemonMode::Running,
        processes: vec![
            ProcessTreeNode::new(1, "systemd", Some(0.02), 0),
            ProcessTreeNode::new(2_101, "bash", Some(0.07), 1),
            ProcessTreeNode::new(4_242, "python3-worker", Some(0.91), 2).with_detail(
                ProcessDetail {
                    ancestry_chain: vec![
                        ProcessInfo {
                            pid: 1,
                            process_name: "systemd".to_owned(),
                            binary_path: "/sbin/init".to_owned(),
                        },
                        ProcessInfo {
                            pid: 2_101,
                            process_name: "bash".to_owned(),
                            binary_path: "/usr/bin/bash".to_owned(),
                        },
                        ProcessInfo {
                            pid: 4_242,
                            process_name: "python3-worker".to_owned(),
                            binary_path: "/usr/bin/python3".to_owned(),
                        },
                    ],
                    feature_vector: vec![
                        ProcessDetailField::new("entropy", "7.30"),
                        ProcessDetailField::new("unique_files", "12"),
                        ProcessDetailField::new("network_fanout", "4"),
                    ],
                    recent_syscalls: vec![
                        "execve /tmp/payload".to_owned(),
                        "openat /etc/ld.so.cache".to_owned(),
                        "connect 10.0.0.8:4444".to_owned(),
                    ],
                    threat_score: Some(0.91),
                    top_features: vec![
                        FeatureContribution {
                            feature_name: "entropy".to_owned(),
                            contribution_score: 0.61,
                        },
                        FeatureContribution {
                            feature_name: "rare_connect".to_owned(),
                            contribution_score: 0.19,
                        },
                        FeatureContribution {
                            feature_name: "child_spawn_count".to_owned(),
                            contribution_score: 0.11,
                        },
                        FeatureContribution {
                            feature_name: "loopback_connection_count".to_owned(),
                            contribution_score: 0.07,
                        },
                        FeatureContribution {
                            feature_name: "wrote_tmp".to_owned(),
                            contribution_score: 0.04,
                        },
                    ],
                },
            ),
            ProcessTreeNode::new(4_500, "curl", Some(0.32), 2),
            ProcessTreeNode::new(4_800, "redis-server", Some(0.12), 1),
            ProcessTreeNode::new(4_801, "cron", Some(0.04), 1),
        ],
        events_per_second: 1_024.0,
        ring_buffer_utilization: 0.12,
        average_inference_latency_ms: 4.8,
        uptime: Duration::from_secs(91),
    }
}

fn exited_process_initial_telemetry() -> TuiTelemetry {
    TuiTelemetry {
        daemon_mode: DaemonMode::Running,
        processes: vec![
            ProcessTreeNode::new(1, "systemd", Some(0.02), 0),
            ProcessTreeNode::new(2_101, "bash", Some(0.07), 1),
            ProcessTreeNode::new(9_001, "short-lived-agent", Some(0.78), 2).with_detail(
                ProcessDetail {
                    ancestry_chain: vec![
                        ProcessInfo {
                            pid: 1,
                            process_name: "systemd".to_owned(),
                            binary_path: "/sbin/init".to_owned(),
                        },
                        ProcessInfo {
                            pid: 2_101,
                            process_name: "bash".to_owned(),
                            binary_path: "/usr/bin/bash".to_owned(),
                        },
                        ProcessInfo {
                            pid: 9_001,
                            process_name: "short-lived-agent".to_owned(),
                            binary_path: "/tmp/agent".to_owned(),
                        },
                    ],
                    feature_vector: vec![
                        ProcessDetailField::new("entropy", "6.40"),
                        ProcessDetailField::new("unique_files", "4"),
                    ],
                    recent_syscalls: vec![
                        "execve /tmp/agent".to_owned(),
                        "openat /tmp/agent.conf".to_owned(),
                    ],
                    threat_score: Some(0.78),
                    top_features: vec![
                        FeatureContribution {
                            feature_name: "entropy".to_owned(),
                            contribution_score: 0.48,
                        },
                        FeatureContribution {
                            feature_name: "wrote_tmp".to_owned(),
                            contribution_score: 0.20,
                        },
                        FeatureContribution {
                            feature_name: "child_spawn_count".to_owned(),
                            contribution_score: 0.05,
                        },
                        FeatureContribution {
                            feature_name: "unique_files".to_owned(),
                            contribution_score: 0.04,
                        },
                        FeatureContribution {
                            feature_name: "execve_count".to_owned(),
                            contribution_score: 0.03,
                        },
                    ],
                },
            ),
        ],
        events_per_second: 750.0,
        ring_buffer_utilization: 0.08,
        average_inference_latency_ms: 3.3,
        uptime: Duration::from_secs(19),
    }
}

fn exited_process_follow_up_telemetry() -> TuiTelemetry {
    TuiTelemetry {
        processes: vec![
            ProcessTreeNode::new(1, "systemd", Some(0.02), 0),
            ProcessTreeNode::new(2_101, "bash", Some(0.07), 1),
        ],
        ..exited_process_initial_telemetry()
    }
}

fn alerts_for_scenario(scenario: &str) -> Vec<Alert> {
    match scenario {
        "timeline_scroll" => {
            let base_timestamp = DateTime::parse_from_rfc3339("2026-04-27T00:00:00Z")
                .expect("fixture timestamp parses")
                .with_timezone(&Utc);
            (1_u64..=20)
                .map(|alert_id| {
                    let minutes = i64::try_from(alert_id).expect("alert id fits into i64") * 5;
                    sample_alert(alert_id, base_timestamp + ChronoDuration::minutes(minutes))
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

fn sample_alert(alert_id: u64, timestamp: DateTime<Utc>) -> Alert {
    Alert {
        alert_id,
        timestamp,
        pid: 6_000 + u32::try_from(alert_id).expect("alert id fits into u32"),
        process_name: format!("timeline-{alert_id:02}"),
        binary_path: format!("/tmp/timeline-{alert_id:02}"),
        ancestry_chain: vec![ProcessInfo {
            pid: 1,
            process_name: "systemd".to_owned(),
            binary_path: "/sbin/init".to_owned(),
        }],
        threat_score: 0.9,
        top_features: vec![FeatureContribution {
            feature_name: "entropy".to_owned(),
            contribution_score: 0.7,
        }],
        summary: format!("summary-{alert_id:02}"),
    }
}
