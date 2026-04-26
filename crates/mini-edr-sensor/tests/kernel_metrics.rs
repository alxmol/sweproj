//! Tests for kernel-side overflow and runtime-fault counter aggregation.
//!
//! These tests stay non-privileged by exercising the pure userspace helpers
//! that later read Aya maps. The privileged harnesses cover live tracepoints;
//! this file locks the arithmetic and error-classification invariants in a fast
//! unit-test loop.

use mini_edr_common::SyscallType;
use mini_edr_sensor::kernel_metrics::{
    EventSubmitOutcome, KernelCounterSnapshot, ProbeFaultMode, classify_ringbuf_submit_result,
};

#[test]
fn classify_ringbuf_submit_result_treats_capacity_backpressure_as_drop() {
    assert_eq!(
        classify_ringbuf_submit_result(-28, ProbeFaultMode::Normal),
        EventSubmitOutcome::DroppedOverflow,
        "FR-S06 counts full-ring-buffer helper failures as graceful drops"
    );
}

#[test]
fn classify_ringbuf_submit_result_routes_invalid_flag_faults_to_runtime_error_counter() {
    assert_eq!(
        classify_ringbuf_submit_result(-22, ProbeFaultMode::InvalidRingbufFlags),
        EventSubmitOutcome::RuntimeFault,
        "fault-injection mode should turn -EINVAL helper failures into probe runtime errors"
    );
}

#[test]
fn kernel_counter_snapshot_sums_per_cpu_drop_and_per_probe_runtime_errors() {
    let snapshot = KernelCounterSnapshot::from_per_cpu_values(
        &[100, 7, 0, 5],
        &[
            (SyscallType::Execve, &[0, 0, 0, 0]),
            (SyscallType::Openat, &[0, 0, 0, 0]),
            (SyscallType::Connect, &[9, 3, 1, 0]),
            (SyscallType::Clone, &[0, 0, 0, 0]),
        ],
    );

    assert_eq!(snapshot.ring_events_dropped_total, 112);
    assert_eq!(snapshot.runtime_errors_for(SyscallType::Execve), 0);
    assert_eq!(snapshot.runtime_errors_for(SyscallType::Openat), 0);
    assert_eq!(snapshot.runtime_errors_for(SyscallType::Connect), 13);
    assert_eq!(snapshot.runtime_errors_for(SyscallType::Clone), 0);
}
