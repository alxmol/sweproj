//! Shared kernel-counter names and aggregation logic for the sensor layer.
//!
//! The eBPF probes update per-CPU counters directly inside the kernel so they
//! can record ring-buffer overflow drops and explicit helper-fault injections
//! without taking locks in a tracepoint context. This userspace module keeps
//! the map names, index layout, and error-classification rules in one place so
//! privileged harnesses and the future daemon health surface read the exact same
//! semantics.

use mini_edr_common::SyscallType;
use std::collections::HashMap;

/// Name of the per-CPU drop counter map in the eBPF object.
pub const RINGBUF_DROP_COUNTER_MAP: &str = "RINGBUF_DROP_COUNTS";
/// Name of the per-CPU runtime-error counter map in the eBPF object.
pub const PROBE_RUNTIME_ERRORS_MAP: &str = "PROBE_RUNTIME_ERRORS";
/// Name of the fault-injection configuration map in the eBPF object.
pub const PROBE_FAULT_MODES_MAP: &str = "PROBE_FAULT_MODES";
/// Single global slot used by the drop counter map.
pub const RINGBUF_DROP_COUNTER_INDEX: u32 = 0;
/// Helper return code used by the connect-fault fixture (`-EINVAL`).
pub const BPF_EINVAL: i64 = -22;
/// Helper return code used when the ring buffer has no space left.
pub const BPF_ENOSPC: i64 = -28;
/// Deliberately invalid ring-buffer flag bit used to trigger `-EINVAL`.
pub const INVALID_RINGBUF_OUTPUT_FLAGS: u64 = 1 << 2;

/// Test-only fault modes that can be toggled per syscall probe.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeFaultMode {
    /// Normal probe behavior: valid ring-buffer submission flags.
    Normal = 0,
    /// Use unsupported ring-buffer flags so the helper returns `-EINVAL`.
    InvalidRingbufFlags = 1,
}

impl ProbeFaultMode {
    /// Decode the raw `u32` stored in the BPF control map.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        match raw {
            1 => Self::InvalidRingbufFlags,
            _ => Self::Normal,
        }
    }

    /// Return the raw representation stored in the BPF control map.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self as u32
    }
}

/// Meaning of one `bpf_ringbuf_output` return code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventSubmitOutcome {
    /// The event reached the ring buffer successfully.
    Delivered,
    /// The event was dropped because the ring buffer had no capacity left.
    DroppedOverflow,
    /// The helper failed for a non-capacity reason and the probe kept running.
    RuntimeFault,
}

/// Classify one `bpf_ringbuf_output` result using the active fault mode.
///
/// The kernel only enables explicit runtime-fault accounting when a harness
/// asks a probe to use intentionally invalid flags. In ordinary operation the
/// only expected helper failure is lack of space, which the SRS defines as a
/// graceful drop rather than a probe fault.
#[must_use]
pub const fn classify_ringbuf_submit_result(
    return_code: i64,
    fault_mode: ProbeFaultMode,
) -> EventSubmitOutcome {
    if return_code >= 0 {
        EventSubmitOutcome::Delivered
    } else if return_code == BPF_EINVAL && matches!(fault_mode, ProbeFaultMode::InvalidRingbufFlags)
    {
        EventSubmitOutcome::RuntimeFault
    } else {
        EventSubmitOutcome::DroppedOverflow
    }
}

/// Aggregated view of kernel-side sensor counters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelCounterSnapshot {
    /// Total number of events the kernel probes dropped at submit time.
    pub ring_events_dropped_total: u64,
    /// Per-syscall runtime helper errors that did not crash the probe.
    pub probe_runtime_errors_total: HashMap<SyscallType, u64>,
}

impl KernelCounterSnapshot {
    /// Build a snapshot by summing per-CPU values for each counter family.
    #[must_use]
    pub fn from_per_cpu_values(
        drop_counts: &[u64],
        runtime_errors: &[(SyscallType, &[u64])],
    ) -> Self {
        let mut probe_runtime_errors_total = HashMap::new();
        for (syscall_type, values) in runtime_errors {
            probe_runtime_errors_total.insert(*syscall_type, sum_per_cpu_values(values));
        }

        Self {
            ring_events_dropped_total: sum_per_cpu_values(drop_counts),
            probe_runtime_errors_total,
        }
    }

    /// Return the runtime-error total for one syscall, defaulting to zero.
    #[must_use]
    pub fn runtime_errors_for(&self, syscall_type: SyscallType) -> u64 {
        self.probe_runtime_errors_total
            .get(&syscall_type)
            .copied()
            .unwrap_or(0)
    }
}

/// Convert a shared `SyscallType` into its fixed BPF array index.
#[must_use]
pub const fn syscall_array_index(syscall_type: SyscallType) -> u32 {
    match syscall_type {
        SyscallType::Execve => 0,
        SyscallType::Openat => 1,
        SyscallType::Connect => 2,
        SyscallType::Clone => 3,
    }
}

/// Convert a BPF array index back into a syscall enum.
#[must_use]
pub const fn syscall_from_array_index(index: u32) -> Option<SyscallType> {
    match index {
        0 => Some(SyscallType::Execve),
        1 => Some(SyscallType::Openat),
        2 => Some(SyscallType::Connect),
        3 => Some(SyscallType::Clone),
        _ => None,
    }
}

fn sum_per_cpu_values(values: &[u64]) -> u64 {
    values.iter().copied().fold(0_u64, u64::saturating_add)
}
