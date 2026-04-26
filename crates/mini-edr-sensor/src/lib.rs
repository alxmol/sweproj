//! eBPF sensor and userspace ring-buffer integration for syscall capture.
//!
//! Per SDD §4.1.1 and §8.2 this crate owns the kernel probe object and the
//! userspace boundary types for the sensor layer. Higher-level lifecycle and
//! deserialization workers build on these modules without introducing reverse
//! dependencies on pipeline, detection, UI, or daemon crates.

pub mod bpf;
pub mod raw_event;
pub mod ringbuffer_consumer;

/// Re-export the common crate under a stable module name so future code in this
/// subsystem can share domain types without adding ad-hoc dependency aliases.
pub use mini_edr_common as common;

#[cfg(test)]
mod tests {
    use super::common::WORKSPACE_TOPOLOGY_VERSION;

    #[test]
    fn links_against_common_topology_contract() {
        // This smoke test deliberately exercises the current public skeleton so
        // the sensor crate participates in per-crate coverage gates before the
        // privileged Aya/eBPF implementation lands in the sensor milestone.
        assert_eq!(WORKSPACE_TOPOLOGY_VERSION, "mini-edr-workspace-v1");
    }
}
