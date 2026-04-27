//! Reusable ratatui panel renderers for the Mini-EDR terminal layout.
//!
//! These helpers keep the three SDD §6.1.1 panels small and focused so the
//! `TuiApp` orchestration code can concentrate on event-loop timing and channel
//! fan-in rather than widget assembly.

use crate::model::{DaemonMode, ProcessTreeNode, TuiTelemetry};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
};

/// Left-hand process-tree renderer from SDD §6.1.1.
pub struct ProcessTreeView;

impl ProcessTreeView {
    /// Render the 60%-width process tree panel.
    ///
    /// When no telemetry has arrived yet, the panel shows the exact
    /// `Loading process tree…` placeholder required by VAL-TUI-001. Once the
    /// first telemetry snapshot lands, the placeholder is replaced by the most
    /// recent process rows.
    pub fn render(
        frame: &mut Frame<'_>,
        area: Rect,
        processes: &[ProcessTreeNode],
        has_received_telemetry: bool,
    ) {
        let lines = if !has_received_telemetry {
            vec![Line::from("Loading process tree…")]
        } else if processes.is_empty() {
            vec![Line::from("Waiting for process telemetry")]
        } else {
            processes
                .iter()
                .map(|process| {
                    // Per SDD §6.1.1, the tree is hierarchical and indented, so
                    // every child row prefixes two spaces per depth level before
                    // the PID / process-name tuple.
                    let indent = "  ".repeat(usize::from(process.depth));
                    let score = process
                        .threat_score
                        .map_or_else(|| "unscored".to_owned(), |value| format!("{value:.2}"));
                    Line::from(format!(
                        "{indent}pid {:>5}  {:<24}  score {score}",
                        process.pid, process.process_name
                    ))
                })
                .collect()
        };

        let paragraph = Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(" Process Tree ")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }
}

/// Right-top alert timeline renderer from SDD §6.1.1.
pub struct AlertTimelineView;

impl AlertTimelineView {
    /// Render the alert timeline panel.
    ///
    /// The panel is intentionally empty-state-aware so a clean host renders the
    /// exact `No threats detected` text required by VAL-TUI-010 instead of an
    /// ambiguous blank region.
    pub fn render(frame: &mut Frame<'_>, area: Rect, alerts: &[mini_edr_common::Alert]) {
        let lines = if alerts.is_empty() {
            vec![Line::from("No threats detected")]
        } else {
            alerts
                .iter()
                .map(|alert| {
                    let timestamp = alert.timestamp.format("%H:%M:%S");
                    Line::from(format!(
                        "{timestamp}  pid {:>5}  {:<18}  {:.2}  {}",
                        alert.pid, alert.process_name, alert.threat_score, alert.summary
                    ))
                })
                .collect()
        };

        let paragraph = Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(" Alert Timeline ")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }
}

/// Right-bottom status renderer from SDD §6.1.1.
pub struct StatusBarView;

impl StatusBarView {
    /// Render the status-bar panel with degraded-mode warning support.
    ///
    /// The degraded banner is rendered in-band in the right-bottom panel so the
    /// operator can still see live metrics even when the model is unavailable.
    pub fn render(frame: &mut Frame<'_>, area: Rect, telemetry: &TuiTelemetry) {
        let mut lines = Vec::new();

        if telemetry.daemon_mode == DaemonMode::Degraded {
            lines.push(Line::from(
                "WARNING: degraded mode — alerts may be unscored",
            ));
        }

        lines.push(Line::from(format!(
            "Events/s: {:.0}",
            telemetry.events_per_second
        )));
        lines.push(Line::from(format!(
            "Ring Buffer: {:.1}%",
            telemetry.ring_buffer_utilization * 100.0
        )));
        lines.push(Line::from(format!(
            "Avg Inference: {:.1} ms",
            telemetry.average_inference_latency_ms
        )));
        lines.push(Line::from(format!(
            "Uptime: {}",
            format_duration(telemetry.uptime)
        )));

        let paragraph = Paragraph::new(Text::from(lines))
            .block(Block::default().title(" Status ").borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }
}

fn format_duration(duration: std::time::Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let seconds = total_seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}
