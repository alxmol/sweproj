//! Application state and crossterm event loop for the Mini-EDR TUI.
//!
//! The rendering pipeline is intentionally split into three phases:
//! 1. non-blocking drain of alert + telemetry broadcast channels;
//! 2. layout/render pass that maps state into the SDD §6.1.1 three-panel UI;
//! 3. bounded crossterm input wait that guarantees another frame no later than
//!    the configured cadence, satisfying the `>= 1 Hz` refresh contract.

use crate::{
    model::{DaemonMode, ProcessTreeNode, TuiTelemetry},
    view::{AlertTimelineView, ProcessDetailView, ProcessTreeView, StatusBarView},
};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
};
use std::{
    cmp::Reverse,
    io,
    time::{Duration, Instant},
};
use tokio::sync::broadcast::{self, error::TryRecvError};

const DEFAULT_FRAME_INTERVAL: Duration = Duration::from_millis(100);
const MAX_TIMELINE_ALERTS: usize = 64;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum FocusedPanel {
    #[default]
    ProcessTree,
    RightColumn,
}

/// ratatui application shell that renders Mini-EDR telemetry.
pub struct TuiApp {
    alert_receiver: broadcast::Receiver<mini_edr_common::Alert>,
    telemetry_receiver: broadcast::Receiver<TuiTelemetry>,
    alerts: Vec<mini_edr_common::Alert>,
    telemetry: TuiTelemetry,
    has_received_telemetry: bool,
    // The interaction state machine has three orthogonal pieces of state:
    // 1. `focused_panel` tracks whether `Tab` currently targets the tree or the
    //    right column, which keeps `Tab` visibly responsive for the latency
    //    contract.
    // 2. `selected_process_pid` tracks the logical tree selection independent
    //    of scrolling so `j/k` and arrow keys can move the cursor without
    //    coupling selection to viewport math.
    // 3. `detail_panel_open` + `retained_selected_process` preserve the last
    //    known process snapshot after exit so an analyst can still press
    //    `Enter` and inspect the final state required by TC-62.
    focused_panel: FocusedPanel,
    selected_process_pid: Option<u32>,
    retained_selected_process: Option<ProcessTreeNode>,
    detail_panel_open: bool,
    process_tree_scroll_offset: usize,
    process_tree_viewport_rows: usize,
    timeline_scroll_offset: usize,
    timeline_viewport_rows: usize,
    frame_interval: Duration,
}

impl TuiApp {
    /// Create a TUI application subscribed to alert and telemetry fan-out.
    #[must_use]
    pub fn new(
        alert_receiver: broadcast::Receiver<mini_edr_common::Alert>,
        telemetry_receiver: broadcast::Receiver<TuiTelemetry>,
    ) -> Self {
        Self {
            alert_receiver,
            telemetry_receiver,
            alerts: Vec::new(),
            telemetry: TuiTelemetry::default(),
            has_received_telemetry: false,
            focused_panel: FocusedPanel::ProcessTree,
            selected_process_pid: None,
            retained_selected_process: None,
            detail_panel_open: false,
            process_tree_scroll_offset: 0,
            process_tree_viewport_rows: 1,
            timeline_scroll_offset: 0,
            timeline_viewport_rows: 1,
            frame_interval: DEFAULT_FRAME_INTERVAL,
        }
    }

    /// Return the render cadence used by the crossterm event loop.
    #[must_use]
    pub const fn frame_interval(&self) -> Duration {
        self.frame_interval
    }

    /// Drain any pending alert and telemetry broadcasts without blocking.
    pub fn drain_broadcasts(&mut self) {
        self.drain_alerts();
        self.drain_telemetry();
    }

    /// Render one frame of the three-panel layout described by SDD §6.1.1.
    pub fn render(&mut self, frame: &mut Frame<'_>) {
        // Per SDD §6.1.1, the process tree owns 60% of the horizontal space and
        // the right column owns the remaining 40%. The right column normally
        // hosts the alert timeline + status bar, but `Enter` swaps that column
        // into a five-section detail drill-down without disturbing the tree.
        let [process_tree_area, right_column] = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .areas(frame.area());

        self.process_tree_viewport_rows =
            usize::from(process_tree_area.height.saturating_sub(2)).max(1);

        let visible_processes = self.visible_processes();
        self.ensure_selected_process(&visible_processes);
        self.clamp_process_tree_scroll_offset(visible_processes.len());
        self.sync_scroll_to_selection(&visible_processes);

        ProcessTreeView::render(
            frame,
            process_tree_area,
            &visible_processes,
            self.has_received_telemetry,
            self.process_tree_scroll_offset,
            self.selected_process_pid,
            self.focused_panel == FocusedPanel::ProcessTree,
        );

        if self.detail_panel_open
            && let Some(selected_process) = self.selected_process_from(&visible_processes)
            && let Some(detail) = selected_process.detail.as_ref()
        {
            ProcessDetailView::render(
                frame,
                right_column,
                &selected_process,
                detail,
                self.focused_panel == FocusedPanel::RightColumn,
            );
            return;
        }

        let [timeline_area, status_area] = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .areas(right_column);
        self.timeline_viewport_rows = usize::from(timeline_area.height.saturating_sub(2)).max(1);
        self.clamp_timeline_scroll_offset();

        AlertTimelineView::render(
            frame,
            timeline_area,
            &self.alerts,
            self.timeline_scroll_offset,
            self.focused_panel == FocusedPanel::RightColumn,
        );
        StatusBarView::render(frame, status_area, &self.telemetry);
    }

    /// Run the TUI with a crossterm-backed terminal.
    ///
    /// The optional `auto_quit_after` hook exists for PTY-driven smoke tests so
    /// the test harness can prove cold-start rendering without leaving an
    /// orphaned fullscreen session behind.
    ///
    /// # Errors
    ///
    /// Returns any terminal setup, input, or draw failure from crossterm or
    /// ratatui.
    pub fn run(mut self, auto_quit_after: Option<Duration>) -> io::Result<()> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;

        let backend = CrosstermBackend::new(io::stdout());
        let mut terminal = Terminal::new(backend)?;
        let result = self.run_event_loop(&mut terminal, auto_quit_after);

        disable_raw_mode()?;
        execute!(io::stdout(), LeaveAlternateScreen, cursor::Show)?;
        terminal.show_cursor()?;

        result
    }

    fn run_event_loop<B: Backend>(
        &mut self,
        terminal: &mut Terminal<B>,
        auto_quit_after: Option<Duration>,
    ) -> io::Result<()> {
        let launched_at = Instant::now();

        loop {
            self.drain_broadcasts();
            terminal.draw(|frame| self.render(frame))?;

            if auto_quit_after.is_some_and(|timeout| launched_at.elapsed() >= timeout) {
                return Ok(());
            }

            // A 100 ms poll budget satisfies the p99 keyboard requirement
            // while still guaranteeing a fresh render at least every second
            // even when the operator is idle and no telemetry changes arrive.
            if event::poll(self.frame_interval)? {
                let event = event::read()?;
                if self.handle_event(&event) {
                    return Ok(());
                }
            }
        }
    }

    fn handle_event(&mut self, event: &Event) -> bool {
        match event {
            Event::Key(key_event) => self.handle_key_event(*key_event),
            _ => false,
        }
    }

    fn handle_key_event(&mut self, key_event: KeyEvent) -> bool {
        if key_event.kind != KeyEventKind::Press {
            return false;
        }

        match key_event.code {
            KeyCode::Tab => {
                self.toggle_focus();
                false
            }
            KeyCode::Enter => {
                self.toggle_detail_panel();
                false
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.scroll_focused_panel_down();
                false
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.scroll_focused_panel_up();
                false
            }
            KeyCode::Char('q') | KeyCode::Esc => true,
            _ => false,
        }
    }

    fn drain_alerts(&mut self) {
        loop {
            match self.alert_receiver.try_recv() {
                Ok(alert) => self.alerts.push(alert),
                Err(TryRecvError::Lagged(_)) => {}
                Err(TryRecvError::Empty | TryRecvError::Closed) => break,
            }
        }

        self.alerts.sort_by_key(|alert| Reverse(alert.timestamp));
        self.alerts.truncate(MAX_TIMELINE_ALERTS);
        self.clamp_timeline_scroll_offset();
    }

    fn drain_telemetry(&mut self) {
        let previous_selected_process = self.selected_process_snapshot();
        let mut latest = None;
        loop {
            match self.telemetry_receiver.try_recv() {
                Ok(telemetry) => latest = Some(telemetry),
                Err(TryRecvError::Lagged(_)) => {}
                Err(TryRecvError::Empty | TryRecvError::Closed) => break,
            }
        }

        if let Some(telemetry) = latest {
            self.has_received_telemetry = true;
            self.telemetry = telemetry;

            if let Some(selected_process) = previous_selected_process {
                let process_is_still_live = self
                    .telemetry
                    .processes
                    .iter()
                    .any(|process| process.pid == selected_process.pid);
                if !process_is_still_live && self.selected_process_pid == Some(selected_process.pid)
                {
                    self.retained_selected_process = Some(selected_process.mark_exited());
                } else if process_is_still_live {
                    self.retained_selected_process = None;
                }
            }
        }
    }

    const fn toggle_focus(&mut self) {
        self.focused_panel = match self.focused_panel {
            FocusedPanel::ProcessTree => FocusedPanel::RightColumn,
            FocusedPanel::RightColumn => FocusedPanel::ProcessTree,
        };
    }

    fn toggle_detail_panel(&mut self) {
        if self.detail_panel_open {
            self.detail_panel_open = false;
            self.focused_panel = FocusedPanel::ProcessTree;
            return;
        }

        let visible_processes = self.visible_processes();
        self.ensure_selected_process(&visible_processes);
        if self
            .selected_process_from(&visible_processes)
            .and_then(|process| process.detail)
            .is_some()
        {
            self.detail_panel_open = true;
            self.focused_panel = FocusedPanel::RightColumn;
        }
    }

    fn scroll_focused_panel_down(&mut self) {
        match self.focused_panel {
            FocusedPanel::ProcessTree => self.move_selection_down(),
            FocusedPanel::RightColumn if !self.detail_panel_open => self.scroll_timeline_down(),
            FocusedPanel::RightColumn => {}
        }
    }

    fn scroll_focused_panel_up(&mut self) {
        match self.focused_panel {
            FocusedPanel::ProcessTree => self.move_selection_up(),
            FocusedPanel::RightColumn if !self.detail_panel_open => self.scroll_timeline_up(),
            FocusedPanel::RightColumn => {}
        }
    }

    fn move_selection_down(&mut self) {
        let visible_processes = self.visible_processes();
        self.ensure_selected_process(&visible_processes);
        if let Some(index) = self.current_selection_index(&visible_processes)
            && let Some(next_process) = visible_processes.get(index + 1)
        {
            self.selected_process_pid = Some(next_process.pid);
            self.sync_scroll_to_selection(&visible_processes);
        }
    }

    fn move_selection_up(&mut self) {
        let visible_processes = self.visible_processes();
        self.ensure_selected_process(&visible_processes);
        if let Some(index) = self.current_selection_index(&visible_processes)
            && index > 0
        {
            self.selected_process_pid = Some(visible_processes[index - 1].pid);
            self.sync_scroll_to_selection(&visible_processes);
        }
    }

    fn visible_processes(&self) -> Vec<ProcessTreeNode> {
        let mut processes = self.telemetry.processes.clone();
        if let Some(retained) = self.retained_selected_process.clone()
            && !processes.iter().any(|process| process.pid == retained.pid)
        {
            processes.push(retained);
        }
        processes
    }

    fn selected_process_snapshot(&self) -> Option<ProcessTreeNode> {
        let visible_processes = self.visible_processes();
        self.selected_process_from(&visible_processes)
    }

    fn selected_process_from(&self, processes: &[ProcessTreeNode]) -> Option<ProcessTreeNode> {
        self.selected_process_pid.and_then(|selected_pid| {
            processes
                .iter()
                .find(|process| process.pid == selected_pid)
                .cloned()
        })
    }

    fn ensure_selected_process(&mut self, processes: &[ProcessTreeNode]) {
        if processes.is_empty() {
            self.selected_process_pid = None;
            self.detail_panel_open = false;
            return;
        }

        if self
            .selected_process_pid
            .is_none_or(|selected_pid| !processes.iter().any(|process| process.pid == selected_pid))
        {
            self.selected_process_pid = processes.first().map(|process| process.pid);
        }
    }

    fn current_selection_index(&self, processes: &[ProcessTreeNode]) -> Option<usize> {
        self.selected_process_pid.and_then(|selected_pid| {
            processes
                .iter()
                .position(|process| process.pid == selected_pid)
        })
    }

    fn sync_scroll_to_selection(&mut self, processes: &[ProcessTreeNode]) {
        let Some(selection_index) = self.current_selection_index(processes) else {
            self.process_tree_scroll_offset = 0;
            return;
        };

        if selection_index < self.process_tree_scroll_offset {
            self.process_tree_scroll_offset = selection_index;
            return;
        }

        let viewport_rows = self.process_tree_viewport_rows.max(1);
        let bottom_visible_row = self.process_tree_scroll_offset + viewport_rows.saturating_sub(1);
        if selection_index > bottom_visible_row {
            self.process_tree_scroll_offset =
                selection_index.saturating_sub(viewport_rows.saturating_sub(1));
        }
    }

    fn scroll_timeline_down(&mut self) {
        let max_scroll_offset = self.max_timeline_scroll_offset();
        if self.timeline_scroll_offset < max_scroll_offset {
            self.timeline_scroll_offset += 1;
        }
    }

    const fn scroll_timeline_up(&mut self) {
        self.timeline_scroll_offset = self.timeline_scroll_offset.saturating_sub(1);
    }

    fn clamp_process_tree_scroll_offset(&mut self, visible_process_count: usize) {
        self.process_tree_scroll_offset = self
            .process_tree_scroll_offset
            .min(self.max_process_tree_scroll_offset(visible_process_count));
    }

    fn clamp_timeline_scroll_offset(&mut self) {
        self.timeline_scroll_offset = self
            .timeline_scroll_offset
            .min(self.max_timeline_scroll_offset());
    }

    fn max_process_tree_scroll_offset(&self, visible_process_count: usize) -> usize {
        visible_process_count.saturating_sub(self.process_tree_viewport_rows.max(1))
    }

    fn max_timeline_scroll_offset(&self) -> usize {
        self.alerts
            .len()
            .saturating_sub(self.timeline_viewport_rows.max(1))
    }
}

impl Default for TuiApp {
    fn default() -> Self {
        let (_alert_sender, alert_receiver) = broadcast::channel(8);
        let (_telemetry_sender, telemetry_receiver) = broadcast::channel(8);
        Self::new(alert_receiver, telemetry_receiver)
    }
}

impl From<DaemonMode> for String {
    fn from(mode: DaemonMode) -> Self {
        match mode {
            DaemonMode::Initializing => "initializing".to_owned(),
            DaemonMode::Running => "running".to_owned(),
            DaemonMode::Degraded => "degraded".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FocusedPanel, TuiApp};
    use crate::model::{
        DaemonMode, ProcessDetail, ProcessDetailField, ProcessTreeNode, TuiTelemetry,
    };
    use chrono::{Duration as ChronoDuration, Utc};
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    use mini_edr_common::{Alert, FeatureContribution, ProcessInfo};
    use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};
    use std::time::Duration;
    use tokio::sync::broadcast;

    #[test]
    fn tab_moves_shared_jk_scrolling_from_tree_to_timeline() {
        let (alert_sender, alert_receiver) = broadcast::channel(32);
        let (_telemetry_sender, telemetry_receiver) = broadcast::channel(8);
        let mut app = TuiApp::new(alert_receiver, telemetry_receiver);

        for alert in sample_alerts() {
            alert_sender
                .send(alert)
                .expect("test receiver stays subscribed");
        }
        app.timeline_viewport_rows = 5;
        app.drain_broadcasts();

        app.handle_event(&Event::Key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));
        app.handle_event(&Event::Key(KeyEvent::new(
            KeyCode::Char('j'),
            KeyModifiers::NONE,
        )));
        app.handle_event(&Event::Key(KeyEvent::new(
            KeyCode::Char('j'),
            KeyModifiers::NONE,
        )));

        assert_eq!(app.focused_panel, FocusedPanel::RightColumn);
        assert_eq!(app.timeline_scroll_offset, 2);

        app.handle_event(&Event::Key(KeyEvent::new(
            KeyCode::Char('k'),
            KeyModifiers::NONE,
        )));
        assert_eq!(app.timeline_scroll_offset, 1);
    }

    #[test]
    fn enter_opens_detail_view_for_selected_process() {
        let (_alert_sender, alert_receiver) = broadcast::channel(8);
        let (telemetry_sender, telemetry_receiver) = broadcast::channel(8);
        let mut app = TuiApp::new(alert_receiver, telemetry_receiver);

        telemetry_sender
            .send(detail_telemetry())
            .expect("telemetry receiver is subscribed");
        app.drain_broadcasts();

        app.handle_event(&Event::Key(KeyEvent::new(
            KeyCode::Down,
            KeyModifiers::NONE,
        )));
        app.handle_event(&Event::Key(KeyEvent::new(
            KeyCode::Down,
            KeyModifiers::NONE,
        )));
        app.handle_event(&Event::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));

        assert!(app.detail_panel_open, "expected detail panel to open");
        assert_eq!(app.focused_panel, FocusedPanel::RightColumn);

        let snapshot = render_snapshot(&mut app, 120, 30);
        assert!(
            snapshot.contains("Ancestry Chain"),
            "missing detail section:\n{snapshot}"
        );
        assert!(
            snapshot.contains("Feature Vector"),
            "missing detail section:\n{snapshot}"
        );
        assert!(
            snapshot.contains("Recent Syscalls"),
            "missing detail section:\n{snapshot}"
        );
        assert!(
            snapshot.contains("Threat Score"),
            "missing detail section:\n{snapshot}"
        );
        assert!(
            snapshot.contains("Top Features"),
            "missing detail section:\n{snapshot}"
        );
        assert!(
            snapshot.contains("python3-worker"),
            "missing selected process detail:\n{snapshot}"
        );
    }

    #[test]
    fn exited_selected_process_is_retained_with_last_known_detail() {
        let (_alert_sender, alert_receiver) = broadcast::channel(8);
        let (telemetry_sender, telemetry_receiver) = broadcast::channel(8);
        let mut app = TuiApp::new(alert_receiver, telemetry_receiver);

        telemetry_sender
            .send(exited_process_initial_telemetry())
            .expect("telemetry receiver is subscribed");
        app.drain_broadcasts();

        app.handle_event(&Event::Key(KeyEvent::new(
            KeyCode::Down,
            KeyModifiers::NONE,
        )));
        app.handle_event(&Event::Key(KeyEvent::new(
            KeyCode::Down,
            KeyModifiers::NONE,
        )));

        telemetry_sender
            .send(exited_process_follow_up_telemetry())
            .expect("telemetry receiver is subscribed");
        app.drain_broadcasts();

        let retained = app
            .retained_selected_process
            .clone()
            .expect("selected exited process should be retained");
        assert_eq!(retained.process_name, "short-lived-agent");
        assert!(retained.exited, "retained process should be marked exited");

        app.handle_event(&Event::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));
        let snapshot = render_snapshot(&mut app, 120, 30);
        assert!(
            snapshot.contains("process has exited"),
            "expected exited marker in detail view:\n{snapshot}"
        );
        assert!(
            snapshot.contains("short-lived-agent"),
            "expected last known process state to remain visible:\n{snapshot}"
        );
    }

    fn detail_telemetry() -> TuiTelemetry {
        TuiTelemetry {
            daemon_mode: DaemonMode::Running,
            processes: vec![
                ProcessTreeNode::new(1, "systemd", Some(0.01), 0),
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
                ProcessTreeNode::new(1, "systemd", Some(0.01), 0),
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
                ProcessTreeNode::new(1, "systemd", Some(0.01), 0),
                ProcessTreeNode::new(2_101, "bash", Some(0.07), 1),
            ],
            ..exited_process_initial_telemetry()
        }
    }

    fn sample_alerts() -> Vec<Alert> {
        let base_timestamp = Utc::now();
        (1_u64..=20)
            .map(|alert_id| Alert {
                alert_id,
                timestamp: base_timestamp
                    + ChronoDuration::minutes(
                        i64::try_from(alert_id).expect("alert id fits into i64"),
                    ),
                pid: 4_000 + u32::try_from(alert_id).expect("alert id fits into u32"),
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
                    contribution_score: 0.5,
                }],
                summary: format!("alert-{alert_id:02}"),
            })
            .collect()
    }

    fn render_snapshot(app: &mut TuiApp, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
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
