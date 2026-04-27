//! TUI-owned view models and daemon-state snapshots.
//!
//! The daemon fans these values out over broadcast channels so the TUI can
//! render a coherent screen without reaching into subsystem internals. The
//! process tree travels inside the telemetry snapshot because SDD §6.1.1 treats
//! the tree and right-bottom status panel as one operator-facing live view.

use mini_edr_common::{FeatureContribution, ProcessInfo};
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
    /// Optional drill-down payload rendered when the analyst presses `Enter`.
    pub detail: Option<ProcessDetail>,
    /// Whether this row reflects a retained last-known snapshot of an exited process.
    pub exited: bool,
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
            detail: None,
            exited: false,
        }
    }

    /// Attach drill-down content to a process-tree row.
    #[must_use]
    pub fn with_detail(mut self, detail: ProcessDetail) -> Self {
        self.detail = Some(detail);
        self
    }

    /// Mark the row as an exited-process snapshot while retaining its last data.
    #[must_use]
    pub const fn mark_exited(mut self) -> Self {
        self.exited = true;
        self
    }
}

/// One labeled field rendered inside the feature-vector detail section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessDetailField {
    /// Human-readable field name such as `entropy` or `unique_files`.
    pub label: String,
    /// Preformatted field value shown alongside the label.
    pub value: String,
}

impl ProcessDetailField {
    /// Construct a labeled detail field from display-ready text.
    #[must_use]
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
        }
    }
}

/// Drill-down payload rendered for the currently selected process.
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessDetail {
    /// Parent-first ancestry chain for the selected process.
    pub ancestry_chain: Vec<ProcessInfo>,
    /// Preformatted feature-vector entries that fit the TUI layout.
    pub feature_vector: Vec<ProcessDetailField>,
    /// Human-readable recent syscall lines in newest-first order.
    pub recent_syscalls: Vec<String>,
    /// Threat score associated with the last known process state.
    pub threat_score: Option<f64>,
    /// Top contributing model features shown to the analyst.
    pub top_features: Vec<FeatureContribution>,
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
