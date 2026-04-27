//! TUI-owned view models and daemon-state snapshots.
//!
//! The daemon fans these values out over broadcast channels so the TUI can
//! render a coherent screen without reaching into subsystem internals. The
//! process tree travels inside the telemetry snapshot because SDD §6.1.1 treats
//! the tree and right-bottom status panel as one operator-facing live view.

use std::time::Duration;

/// High-level daemon mode surfaced to the terminal status bar.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DaemonMode {
    /// Startup is still in progress, so the TUI should show loading affordances.
    #[default]
    Initializing,
    /// Full scoring is active and the daemon is operating normally.
    Running,
    /// Capture continues, but scoring is degraded or unavailable.
    Degraded,
}

/// One row in the hierarchical process-tree panel.
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessTreeNode {
    /// Process identifier displayed in the tree.
    pub pid: u32,
    /// Human-readable process name rendered alongside the PID.
    pub process_name: String,
    /// Optional threat score shown inline when scoring data is available.
    pub threat_score: Option<f64>,
    /// Nesting depth used to indent child rows under their parents.
    pub depth: u16,
}

impl ProcessTreeNode {
    /// Construct a tree row from the fields the TUI renders directly.
    pub fn new(
        pid: u32,
        process_name: impl Into<String>,
        threat_score: Option<f64>,
        depth: u16,
    ) -> Self {
        Self {
            pid,
            process_name: process_name.into(),
            threat_score,
            depth,
        }
    }
}

/// Broadcast snapshot that drives both the process tree and the status bar.
#[derive(Clone, Debug, PartialEq)]
pub struct TuiTelemetry {
    /// Daemon lifecycle mode that controls degraded-mode warnings.
    pub daemon_mode: DaemonMode,
    /// Latest hierarchical process snapshot for the left-hand panel.
    pub processes: Vec<ProcessTreeNode>,
    /// Approximate live event rate over the trailing one-second window.
    pub events_per_second: f64,
    /// Ring buffer utilization in the inclusive `[0.0, 1.0]` range.
    pub ring_buffer_utilization: f64,
    /// Average inference latency rendered in milliseconds.
    pub average_inference_latency_ms: f64,
    /// Elapsed daemon uptime rendered in `hh:mm:ss`.
    pub uptime: Duration,
}

impl Default for TuiTelemetry {
    fn default() -> Self {
        Self {
            daemon_mode: DaemonMode::Initializing,
            processes: Vec::new(),
            events_per_second: 0.0,
            ring_buffer_utilization: 0.0,
            average_inference_latency_ms: 0.0,
            uptime: Duration::ZERO,
        }
    }
}
