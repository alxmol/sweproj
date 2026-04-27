//! ratatui terminal interface for Mini-EDR.
//!
//! Per SDD §6.1.1 and §8.2, this crate owns the terminal presentation layer
//! only. It renders process, alert, and daemon-status data that a higher-level
//! coordinator such as the daemon fan-outs over broadcast channels; it does not
//! depend directly on sensor, pipeline, or detection crates so the workspace
//! graph stays acyclic.

pub mod app;
pub mod model;
pub mod view;

/// Re-export the common crate under a stable module name so TUI code and its
/// callers can share alert/domain schemas without ad-hoc dependency aliases.
pub use mini_edr_common as common;

pub use app::TuiApp;
pub use model::{DaemonMode, ProcessTreeNode, TuiTelemetry};
pub use view::{AlertTimelineView, ProcessTreeView, StatusBarView};

#[cfg(test)]
mod tests {
    use super::{DaemonMode, ProcessTreeNode, TuiApp, TuiTelemetry};
    use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};
    use std::time::Duration;
    use tokio::sync::broadcast;

    #[test]
    fn process_tree_shows_loading_indicator_before_first_telemetry() {
        let (_alert_sender, alert_receiver) = broadcast::channel(8);
        let (_telemetry_sender, telemetry_receiver) = broadcast::channel(8);
        let mut app = TuiApp::new(alert_receiver, telemetry_receiver);

        let snapshot = render_snapshot(&mut app);
        assert!(
            snapshot.contains("Loading process tree…"),
            "expected the cold-start placeholder before telemetry arrives, got:\n{snapshot}"
        );
    }

    #[test]
    fn empty_timeline_renders_expected_text() {
        let (_alert_sender, alert_receiver) = broadcast::channel(8);
        let (_telemetry_sender, telemetry_receiver) = broadcast::channel(8);
        let mut app = TuiApp::new(alert_receiver, telemetry_receiver);

        let snapshot = render_snapshot(&mut app);
        assert!(
            snapshot.contains("No threats detected"),
            "empty alert timeline text missing from snapshot:\n{snapshot}"
        );
    }

    #[test]
    fn telemetry_replaces_loading_indicator_with_process_rows() {
        let (_alert_sender, alert_receiver) = broadcast::channel(8);
        let (telemetry_sender, telemetry_receiver) = broadcast::channel(8);
        let mut app = TuiApp::new(alert_receiver, telemetry_receiver);

        telemetry_sender
            .send(sample_running_telemetry())
            .expect("telemetry receiver is subscribed");
        app.drain_broadcasts();

        let snapshot = render_snapshot(&mut app);
        assert!(
            !snapshot.contains("Loading process tree…"),
            "loading text should disappear after telemetry arrives:\n{snapshot}"
        );
        assert!(
            snapshot.contains("mini-edr-daemon"),
            "process tree did not render the broadcast process rows:\n{snapshot}"
        );
    }

    #[test]
    fn degraded_mode_renders_warning_banner_in_status_panel() {
        let (_alert_sender, alert_receiver) = broadcast::channel(8);
        let (telemetry_sender, telemetry_receiver) = broadcast::channel(8);
        let mut app = TuiApp::new(alert_receiver, telemetry_receiver);

        let mut degraded = sample_running_telemetry();
        degraded.daemon_mode = DaemonMode::Degraded;
        telemetry_sender
            .send(degraded)
            .expect("telemetry receiver is subscribed");
        app.drain_broadcasts();

        let snapshot = render_snapshot(&mut app);
        assert!(
            snapshot.to_ascii_lowercase().contains("degraded"),
            "status bar warning banner missing degraded text:\n{snapshot}"
        );
    }

    #[test]
    fn frame_interval_meets_one_hz_contract() {
        let (_alert_sender, alert_receiver) = broadcast::channel(8);
        let (_telemetry_sender, telemetry_receiver) = broadcast::channel(8);
        let app = TuiApp::new(alert_receiver, telemetry_receiver);

        assert!(
            app.frame_interval() <= Duration::from_secs(1),
            "frame cadence must be at least 1 Hz"
        );
    }

    fn sample_running_telemetry() -> TuiTelemetry {
        TuiTelemetry {
            daemon_mode: DaemonMode::Running,
            processes: vec![
                ProcessTreeNode::new(1, "systemd", Some(0.02), 0),
                ProcessTreeNode::new(2457, "mini-edr-daemon", Some(0.11), 1),
                ProcessTreeNode::new(8120, "sleep 30", None, 2),
            ],
            events_per_second: 1_024.0,
            ring_buffer_utilization: 0.12,
            average_inference_latency_ms: 4.8,
            uptime: Duration::from_secs(91),
        }
    }

    fn render_snapshot(app: &mut TuiApp) -> String {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test terminal builds");
        terminal
            .draw(|frame| app.render(frame))
            .expect("render succeeds");
        buffer_to_string(terminal.backend().buffer())
    }

    fn buffer_to_string(buffer: &Buffer) -> String {
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
