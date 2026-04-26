//! ratatui terminal interface skeleton.
//!
//! This crate currently contains only the public skeleton required by SDD §8.2.
//! It depends on `mini-edr-common` and on no other Mini-EDR subsystem so the
//! initial workspace graph stays acyclic: data flows through the daemon at
//! runtime, not through reverse compile-time dependencies.

/// Re-export the common crate under a stable module name so future code in this
/// subsystem can share domain types without adding ad-hoc dependency aliases.
pub use mini_edr_common as common;
