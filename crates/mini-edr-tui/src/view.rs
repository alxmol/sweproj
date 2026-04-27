//! Reusable ratatui panel renderers for the Mini-EDR terminal layout.
//!
//! These helpers keep the three SDD §6.1.1 panels small and focused so the
//! `TuiApp` orchestration code can concentrate on event-loop timing and channel
//! fan-in rather than widget assembly.

use crate::model::{DaemonMode, ProcessTreeNode, TuiTelemetry};
use mini_edr_common::Alert;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
};

// FR-T02 defines the green bucket as scores strictly below 0.3, so 0.299
// stays green while 0.300 moves into the yellow partition.
const THREAT_SCORE_GREEN_MAX: f64 = 0.3;
// FR-T02 defines the red bucket as scores at or above 0.7, so 0.699 remains
// yellow while 0.700 must render red.
const THREAT_SCORE_YELLOW_MAX: f64 = 0.7;

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
        scroll_offset: usize,
    ) {
        let lines = if !has_received_telemetry {
            vec![Line::from("Loading process tree…")]
        } else if processes.is_empty() {
            vec![Line::from("Waiting for process telemetry")]
        } else {
            process_tree_lines(
                processes,
                scroll_offset,
                area.height.saturating_sub(2).into(),
                area.width.into(),
            )
        };

        let paragraph = Paragraph::new(Text::from(lines)).block(
            Block::default()
                .title(" Process Tree ")
                .borders(Borders::ALL),
        );
        frame.render_widget(paragraph, area);
    }
}

fn process_tree_lines(
    processes: &[ProcessTreeNode],
    scroll_offset: usize,
    viewport_rows: usize,
    viewport_width: usize,
) -> Vec<Line<'static>> {
    let max_scroll_offset = max_scroll_offset(processes.len(), viewport_rows);
    let clamped_scroll_offset = scroll_offset.min(max_scroll_offset);
    let max_indent_levels = max_visible_indent_levels(viewport_width);

    processes
        .iter()
        .skip(clamped_scroll_offset)
        .take(viewport_rows.max(1))
        .map(|process| {
            let indent = render_indent(process.depth, max_indent_levels);
            let process_name = sanitize_process_name(&process.process_name);
            let score = process
                .threat_score
                .map_or_else(|| "unscored".to_owned(), |value| format!("{value:.3}"));
            let row_text = format!(
                "{indent}pid {:>5}  {process_name}  score {score}",
                process.pid
            );
            Line::from(vec![Span::styled(
                row_text,
                style_for_threat_score(process.threat_score),
            )])
        })
        .collect()
}

fn render_indent(depth: u16, max_indent_levels: usize) -> String {
    let depth = usize::from(depth);

    if depth <= max_indent_levels {
        return "  ".repeat(depth);
    }

    // Deep trees can easily exceed the panel width (for example 1,200 nested
    // nodes in VAL-TUI-016). Capping the visual indent and prefixing an
    // ellipsis preserves hierarchy without letting indentation push the PID and
    // process name entirely off-screen.
    if max_indent_levels == 0 {
        "… ".to_owned()
    } else {
        format!("…{}", "  ".repeat(max_indent_levels.saturating_sub(1)))
    }
}

const fn max_visible_indent_levels(viewport_width: usize) -> usize {
    const MIN_PROCESS_TEXT_WIDTH: usize = 28;

    viewport_width.saturating_sub(MIN_PROCESS_TEXT_WIDTH) / 2
}

fn max_scroll_offset(process_count: usize, viewport_rows: usize) -> usize {
    process_count.saturating_sub(viewport_rows.max(1))
}

fn sanitize_process_name(process_name: &str) -> String {
    process_name
        .chars()
        .map(|character| {
            if character.is_control() {
                // Control bytes must never be rendered verbatim inside the TUI
                // because escape sequences could clear the screen or move the
                // cursor. Replacing them with a visible glyph keeps the row
                // stable while still showing that unusual bytes were present.
                '�'
            } else {
                character
            }
        })
        .collect()
}

fn style_for_threat_score(threat_score: Option<f64>) -> Style {
    match threat_score {
        // FR-T02: scores strictly below 0.3 stay green, so 0.299 is green.
        Some(score) if score < THREAT_SCORE_GREEN_MAX => Style::default().fg(Color::Green),
        // FR-T02: scores from 0.3 up to but excluding 0.7 are yellow, so
        // 0.300 and 0.699 both remain in the middle partition.
        Some(score) if score < THREAT_SCORE_YELLOW_MAX => Style::default().fg(Color::Yellow),
        // FR-T02: scores at or above 0.7 are red, so 0.700 flips here.
        Some(_) => Style::default().fg(Color::Red),
        None => Style::default(),
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
    pub fn render(frame: &mut Frame<'_>, area: Rect, alerts: &[Alert], scroll_offset: usize) {
        let lines = if alerts.is_empty() {
            vec![Line::from("No threats detected")]
        } else {
            timeline_lines(alerts, scroll_offset, area.height.saturating_sub(2).into())
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

fn timeline_lines(
    alerts: &[Alert],
    scroll_offset: usize,
    viewport_rows: usize,
) -> Vec<Line<'static>> {
    alerts
        .iter()
        .skip(scroll_offset)
        .take(viewport_rows.max(1))
        .map(|alert| {
            let timestamp = alert.timestamp.format("%m-%d %H:%M");
            Line::from(format!(
                "#{:04}  {timestamp}  pid {:>5}  {:.2}",
                alert.alert_id, alert.pid, alert.threat_score
            ))
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::{
        Alert, Color, ProcessTreeNode, max_scroll_offset, process_tree_lines,
        sanitize_process_name, style_for_threat_score, timeline_lines,
    };
    use chrono::{DateTime, Duration as ChronoDuration, Utc};
    use mini_edr_common::{FeatureContribution, ProcessInfo};

    #[test]
    fn threat_score_partitions_follow_fr_t02_boundaries() {
        assert_eq!(
            style_for_threat_score(Some(0.10)),
            ratatui::style::Style::default().fg(Color::Green)
        );
        assert_eq!(
            style_for_threat_score(Some(0.299)),
            ratatui::style::Style::default().fg(Color::Green)
        );
        assert_eq!(
            style_for_threat_score(Some(0.300)),
            ratatui::style::Style::default().fg(Color::Yellow)
        );
        assert_eq!(
            style_for_threat_score(Some(0.699)),
            ratatui::style::Style::default().fg(Color::Yellow)
        );
        assert_eq!(
            style_for_threat_score(Some(0.700)),
            ratatui::style::Style::default().fg(Color::Red)
        );
    }

    #[test]
    fn sanitize_process_name_replaces_control_chars_without_dropping_utf8() {
        let sanitized = sanitize_process_name("мойбин-🔥\u{0007}\u{001b}[2J\u{001b}[Hpwn");
        assert!(
            sanitized.contains("мойбин-🔥"),
            "expected UTF-8 glyphs to remain intact, got: {sanitized}"
        );
        assert!(
            sanitized.contains("pwn"),
            "expected printable tail to remain visible, got: {sanitized}"
        );
        assert!(
            !sanitized.contains('\u{001b}'),
            "escape bytes must be removed from rendered names, got: {sanitized:?}"
        );
    }

    #[test]
    fn process_tree_lines_apply_scroll_offset_without_wrapping_previous_rows() {
        let processes = (0_u32..20)
            .map(|index| {
                ProcessTreeNode::new(
                    5_000 + index,
                    format!("node-{index:04}"),
                    Some(0.10),
                    u16::try_from(index).expect("test depth fits into u16"),
                )
            })
            .collect::<Vec<_>>();

        let lines = process_tree_lines(&processes, 10, 4, 80);
        let rendered = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            rendered.contains("node-0010"),
            "expected the scrolled viewport to start at node-0010, got:\n{rendered}"
        );
        assert!(
            !rendered.contains("node-0000"),
            "expected rows above the scroll window to be omitted, got:\n{rendered}"
        );
        assert_eq!(max_scroll_offset(processes.len(), 4), 16);
    }

    #[test]
    fn timeline_lines_keep_newest_alert_at_top_and_scroll_to_all_entries() {
        let base = DateTime::parse_from_rfc3339("2026-04-27T00:00:00Z")
            .expect("timestamp parses")
            .with_timezone(&Utc);
        let alerts = (1_u64..=20)
            .map(|alert_id| {
                sample_alert(
                    alert_id,
                    base + ChronoDuration::minutes(
                        i64::try_from(alert_id).expect("alert id fits into i64"),
                    ),
                )
            })
            .rev()
            .collect::<Vec<_>>();

        let first_page = timeline_lines(&alerts, 0, 5)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>();
        assert!(
            first_page[0].contains("#0020"),
            "expected newest alert first, got page:\n{}",
            first_page.join("\n")
        );
        assert!(
            first_page[4].contains("#0016"),
            "expected fifth visible row to be alert sixteen, got page:\n{}",
            first_page.join("\n")
        );

        let last_page = timeline_lines(&alerts, 15, 5)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>();
        assert!(
            last_page[0].contains("#0005") && last_page[4].contains("#0001"),
            "expected scrolled page to reach the oldest alerts, got page:\n{}",
            last_page.join("\n")
        );
    }

    fn sample_alert(alert_id: u64, timestamp: DateTime<Utc>) -> Alert {
        Alert {
            alert_id,
            timestamp,
            pid: 7_000 + u32::try_from(alert_id).expect("alert id fits into u32"),
            process_name: format!("alert-{alert_id:02}"),
            binary_path: format!("/tmp/alert-{alert_id:02}"),
            ancestry_chain: vec![ProcessInfo {
                pid: 1,
                process_name: "systemd".to_owned(),
                binary_path: "/sbin/init".to_owned(),
            }],
            threat_score: 0.85,
            top_features: vec![FeatureContribution {
                feature_name: "entropy".to_owned(),
                contribution_score: 0.42,
            }],
            summary: format!("summary-{alert_id:02}"),
        }
    }
}
