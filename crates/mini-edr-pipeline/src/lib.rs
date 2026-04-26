//! Telemetry enrichment, ancestry, windowing, and feature-vector pipeline.
//!
//! The pipeline enriches raw syscall telemetry with `/proc` metadata before
//! later milestone features reconstruct ancestry, aggregate process windows,
//! and compute feature vectors. This crate intentionally depends only on
//! `mini-edr-common` so the SDD §8.2 workspace graph stays acyclic: runtime
//! data flows through the daemon, not through reverse compile-time edges.

pub mod proc_reader;

/// Re-export the common crate under a stable module name so future code in this
/// subsystem can share domain types without adding ad-hoc dependency aliases.
pub use mini_edr_common as common;

pub use proc_reader::{ProcHidePidSetting, ProcReadError, ProcReader, ProcStat, ProcStatus};
