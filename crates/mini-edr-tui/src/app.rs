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

/// ratatui application shell that renders Mini-EDR telemetry.
pub struct TuiApp {
    alert_receiver: broadcast::Receiver<mini_edr_common::Alert>,
    telemetry_receiver: broadcast::Receiver<TuiTelemetry>,
    alerts: Vec<mini_edr_common::Alert>,
    telemetry: TuiTelemetry,
    has_received_telemetry: bool,
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
    pub fn render(&self, frame: &mut Frame<'_>) {
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

        ProcessTreeView::render(
            frame,
            process_tree_area,
            &self.telemetry.processes,
            self.has_received_telemetry,
        );
        AlertTimelineView::render(frame, timeline_area, &self.alerts);
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
                if Self::handle_event(&event) {
                    return Ok(());
                }
            }
        }
    }

    fn handle_event(event: &Event) -> bool {
        match event {
            Event::Key(key_event) => Self::handle_key_event(*key_event),
            _ => false,
        }
    }

    fn handle_key_event(key_event: KeyEvent) -> bool {
        if key_event.kind != KeyEventKind::Press {
            return false;
        }

        match key_event.code {
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
            self.telemetry = telemetry;
        }
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
