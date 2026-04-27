//! Application state and crossterm event loop for the Mini-EDR TUI.
//!
//! The rendering pipeline is intentionally split into three phases:
//! 1. non-blocking drain of alert + telemetry broadcast channels;
//! 2. layout/render pass that maps state into the SDD §6.1.1 three-panel UI;
//! 3. bounded crossterm input wait that guarantees another frame no later than
//!    the configured cadence, satisfying the `>= 1 Hz` refresh contract.

use crate::{
    model::{DaemonMode, TuiTelemetry},
    view::{AlertTimelineView, ProcessTreeView, StatusBarView},
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
    AlertTimeline,
}

/// ratatui application shell that renders Mini-EDR telemetry.
pub struct TuiApp {
    alert_receiver: broadcast::Receiver<mini_edr_common::Alert>,
    telemetry_receiver: broadcast::Receiver<TuiTelemetry>,
    alerts: Vec<mini_edr_common::Alert>,
    telemetry: TuiTelemetry,
    has_received_telemetry: bool,
    // The interaction model is deliberately tiny for the timeline/status
    // milestone: `Tab` toggles between the left process tree and the right-top
    // timeline, and the active panel consumes shared `j`/`k` + arrow scroll
    // inputs. This keeps later detail-view work additive instead of forcing a
    // rewrite of today's navigation state.
    focused_panel: FocusedPanel,
    // The process-tree interaction state is intentionally minimal for this
    // milestone: we track the top-most visible row and let `j`/`k` and the
    // arrow keys move that scroll cursor through arbitrarily deep trees. Later
    // milestones can layer selection and detail-view focus on top of the same
    // bounded scroll window without rewriting the render path.
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
        // the right column owns the remaining 40%. The right column is then
        // split vertically so the alert timeline receives 60% of that height
        // and the status bar receives the bottom 40%.
        let [process_tree_area, right_column] = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .areas(frame.area());
        let [timeline_area, status_area] = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .areas(right_column);

        self.process_tree_viewport_rows =
            usize::from(process_tree_area.height.saturating_sub(2)).max(1);
        self.timeline_viewport_rows = usize::from(timeline_area.height.saturating_sub(2)).max(1);
        self.clamp_process_tree_scroll_offset();
        self.clamp_timeline_scroll_offset();

        ProcessTreeView::render(
            frame,
            process_tree_area,
            &self.telemetry.processes,
            self.has_received_telemetry,
            self.process_tree_scroll_offset,
        );
        AlertTimelineView::render(
            frame,
            timeline_area,
            &self.alerts,
            self.timeline_scroll_offset,
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
            KeyCode::Char('j') | KeyCode::Down => {
                self.scroll_focused_panel_down();
                false
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.scroll_focused_panel_up();
                false
            }
            // `q` is the only navigation requirement for this feature. Later
            // milestones layer richer tree/timeline focus management on top of
            // this same crossterm loop.
            KeyCode::Char('q') | KeyCode::Esc => true,
            _ => false,
        }
    }

    fn drain_alerts(&mut self) {
        loop {
            match self.alert_receiver.try_recv() {
                Ok(alert) => {
                    self.alerts.push(alert);
                }
                Err(TryRecvError::Lagged(_)) => {}
                Err(TryRecvError::Empty | TryRecvError::Closed) => break,
            }
        }

        self.alerts.sort_by_key(|alert| Reverse(alert.timestamp));
        self.alerts.truncate(MAX_TIMELINE_ALERTS);
        self.clamp_timeline_scroll_offset();
    }

    fn drain_telemetry(&mut self) {
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
            // The daemon republishes this snapshot at a one-second cadence so
            // the status bar's events/s, ring utilization, latency, and uptime
            // lines keep ticking even when the process list itself is steady.
            self.telemetry = telemetry;
            self.clamp_process_tree_scroll_offset();
        }
    }

    const fn toggle_focus(&mut self) {
        self.focused_panel = match self.focused_panel {
            FocusedPanel::ProcessTree => FocusedPanel::AlertTimeline,
            FocusedPanel::AlertTimeline => FocusedPanel::ProcessTree,
        };
    }

    fn scroll_focused_panel_down(&mut self) {
        match self.focused_panel {
            FocusedPanel::ProcessTree => self.scroll_process_tree_down(),
            FocusedPanel::AlertTimeline => self.scroll_timeline_down(),
        }
    }

    const fn scroll_focused_panel_up(&mut self) {
        match self.focused_panel {
            FocusedPanel::ProcessTree => self.scroll_process_tree_up(),
            FocusedPanel::AlertTimeline => self.scroll_timeline_up(),
        }
    }

    fn scroll_process_tree_down(&mut self) {
        let max_scroll_offset = self.max_process_tree_scroll_offset();
        if self.process_tree_scroll_offset < max_scroll_offset {
            self.process_tree_scroll_offset += 1;
        }
    }

    const fn scroll_process_tree_up(&mut self) {
        self.process_tree_scroll_offset = self.process_tree_scroll_offset.saturating_sub(1);
    }

    fn clamp_process_tree_scroll_offset(&mut self) {
        self.process_tree_scroll_offset = self
            .process_tree_scroll_offset
            .min(self.max_process_tree_scroll_offset());
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

    fn clamp_timeline_scroll_offset(&mut self) {
        self.timeline_scroll_offset = self
            .timeline_scroll_offset
            .min(self.max_timeline_scroll_offset());
    }

    fn max_process_tree_scroll_offset(&self) -> usize {
        self.telemetry
            .processes
            .len()
            .saturating_sub(self.process_tree_viewport_rows.max(1))
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
    use chrono::{Duration as ChronoDuration, Utc};
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    use mini_edr_common::{Alert, FeatureContribution, ProcessInfo};
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

        assert_eq!(app.focused_panel, FocusedPanel::AlertTimeline);
        assert_eq!(app.process_tree_scroll_offset, 0);
        assert_eq!(app.timeline_scroll_offset, 2);

        app.handle_event(&Event::Key(KeyEvent::new(
            KeyCode::Char('k'),
            KeyModifiers::NONE,
        )));
        assert_eq!(app.timeline_scroll_offset, 1);
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
}
