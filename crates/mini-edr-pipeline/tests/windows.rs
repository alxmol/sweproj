//! Integration tests for `WindowAggregator` boundary and exit semantics.

use mini_edr_common::{EnrichedEvent, ProcessInfo, SyscallEvent, SyscallType};
use mini_edr_pipeline::WindowAggregator;

#[test]
fn windows_emit_exactly_one_feature_vector_at_boundary_and_carry_boundary_event_forward() {
    let mut aggregator = WindowAggregator::new(5);

    assert!(
        aggregator
            .push_event(sample_event(7, 0, SyscallType::Execve))
            .is_empty()
    );
    assert!(
        aggregator
            .push_event(sample_event(7, 4_000_000_000, SyscallType::Openat))
            .is_empty()
    );

    let emitted = aggregator.push_event(sample_event(7, 5_000_000_000, SyscallType::Connect));
    assert_eq!(
        emitted.len(),
        1,
        "FR-P04 emits exactly one vector when the first 5 s window closes"
    );

    let first_window = &emitted[0];
    assert_eq!(first_window.window_start_ns, 0);
    assert_eq!(first_window.window_end_ns, 5_000_000_000);
    assert_eq!(first_window.total_syscalls, 2);
    assert_eq!(first_window.execve_count, 1);
    assert_eq!(first_window.openat_count, 1);
    assert_eq!(first_window.connect_count, 0);

    let partial = aggregator
        .close_process(7, 5_100_000_000)
        .expect("boundary event should have started the next partial window");
    assert!(partial.short_lived);
    assert_eq!(partial.window_start_ns, 5_000_000_000);
    assert_eq!(partial.window_end_ns, 5_100_000_000);
    assert_eq!(partial.total_syscalls, 1);
    assert_eq!(partial.connect_count, 1);
}

#[test]
fn windows_apply_duration_reconfiguration_to_the_next_window_only() {
    let mut aggregator = WindowAggregator::new(5);

    assert!(
        aggregator
            .push_event(sample_event(11, 0, SyscallType::Execve))
            .is_empty()
    );
    aggregator.set_window_duration_secs(1);

    let emitted = aggregator.push_event(sample_event(11, 5_000_000_000, SyscallType::Openat));
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0].window_duration_ns, 5_000_000_000);

    assert!(
        aggregator
            .push_event(sample_event(11, 5_250_000_000, SyscallType::Connect))
            .is_empty()
    );

    let next = aggregator.flush_expired(6_100_000_000);
    assert_eq!(
        next.len(),
        1,
        "the reconfigured 1 s duration should close the next window"
    );
    assert_eq!(next[0].window_start_ns, 5_000_000_000);
    assert_eq!(next[0].window_end_ns, 6_000_000_000);
    assert_eq!(next[0].window_duration_ns, 1_000_000_000);
    assert_eq!(next[0].total_syscalls, 2);
}

#[test]
fn windows_emit_short_lived_process_partial_window_once_at_exit_timestamp() {
    let mut aggregator = WindowAggregator::new(30);

    assert!(
        aggregator
            .push_event(sample_event(29, 2_000_000_000, SyscallType::Execve))
            .is_empty()
    );
    assert!(
        aggregator
            .push_event(sample_event(29, 3_500_000_000, SyscallType::Clone))
            .is_empty()
    );

    let partial = aggregator
        .close_process(29, 4_000_000_000)
        .expect("FR-P06 requires a partial feature vector when the process exits");
    assert!(partial.short_lived);
    assert_eq!(partial.window_start_ns, 2_000_000_000);
    assert_eq!(partial.window_end_ns, 4_000_000_000);
    assert_eq!(partial.window_duration_ns, 2_000_000_000);
    assert_eq!(partial.total_syscalls, 2);
    assert_eq!(partial.clone_count, 1);

    assert!(
        aggregator.close_process(29, 4_000_000_000).is_none(),
        "a process exit must emit at most one partial vector"
    );
    assert!(aggregator.flush_expired(40_000_000_000).is_empty());
}

fn sample_event(pid: u32, timestamp: u64, syscall_type: SyscallType) -> EnrichedEvent {
    EnrichedEvent {
        event: SyscallEvent {
            event_id: timestamp.saturating_add(1),
            timestamp,
            pid,
            tid: pid,
            ppid: 1,
            syscall_type,
            filename: match syscall_type {
                SyscallType::Openat => Some("/tmp/window-test".to_owned()),
                _ => None,
            },
            ip_address: match syscall_type {
                SyscallType::Connect => Some([10, 0, 0, 8]),
                _ => None,
            },
            port: match syscall_type {
                SyscallType::Connect => Some(443),
                _ => None,
            },
            child_pid: match syscall_type {
                SyscallType::Clone => Some(pid.saturating_add(1)),
                _ => None,
            },
            open_flags: None,
            syscall_result: Some(0),
        },
        process_name: format!("proc-{pid}"),
        binary_path: format!("/usr/bin/proc-{pid}"),
        cgroup: format!("0::/mini-edr/{pid}"),
        uid: 1_000,
        ancestry_chain: vec![
            ProcessInfo {
                pid: 1,
                process_name: "init".to_owned(),
                binary_path: "/sbin/init".to_owned(),
            },
            ProcessInfo {
                pid,
                process_name: format!("proc-{pid}"),
                binary_path: format!("/usr/bin/proc-{pid}"),
            },
        ],
        ancestry_truncated: false,
        repeat_count: 1,
    }
}
