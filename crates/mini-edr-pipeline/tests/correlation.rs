//! Property coverage for live event-to-window correlation invariants.
//!
//! The live daemon now probes `/proc` once per flush tick and asks the
//! aggregator to close any PID whose process has already exited. These tests
//! keep that multi-PID accounting honest: every accepted syscall must land in
//! exactly one emitted feature vector whether the PID exits early or crosses a
//! normal boundary.

use mini_edr_common::{EnrichedEvent, ProcessInfo, SyscallEvent, SyscallType};
use mini_edr_pipeline::WindowAggregator;
use proptest::{
    collection::vec,
    prelude::{Just, prop_oneof},
    prop_assert, prop_assert_eq, proptest,
    strategy::Strategy,
    test_runner::Config as ProptestConfig,
};
use std::collections::BTreeSet;

const WINDOW_DURATION_SECONDS: u64 = 2;
const WINDOW_DURATION_NS: u64 = WINDOW_DURATION_SECONDS * 1_000_000_000;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    #[test]
    fn exited_and_non_exited_pids_do_not_drop_events(schedule in random_schedule(), exited_pid_offsets in vec(0_u8..6, 0..6)) {
        let mut aggregator = WindowAggregator::new(WINDOW_DURATION_SECONDS);
        let total_events = schedule.len();
        let max_timestamp = schedule
            .iter()
            .map(|event| event.timestamp)
            .max()
            .unwrap_or(0);
        let input_pids = schedule
            .iter()
            .map(|event| event.pid)
            .collect::<BTreeSet<_>>();
        let exited_pids = exited_pid_offsets
            .into_iter()
            .map(|offset| 10_000_u32 + u32::from(offset))
            .collect::<BTreeSet<_>>();

        let mut emitted = Vec::new();
        for event in &schedule {
            emitted.extend(aggregator.push_event(sample_event(
                event.pid,
                event.timestamp,
                event.syscall_type,
            )));
        }

        let active_pids = aggregator.active_pids().into_iter().collect::<BTreeSet<_>>();
        emitted.extend(aggregator.close_processes(
            exited_pids
                .iter()
                .copied()
                .filter(|pid| active_pids.contains(pid)),
            max_timestamp.saturating_add(1),
        ));
        emitted.extend(aggregator.flush_expired(
            max_timestamp
                .saturating_add(WINDOW_DURATION_NS)
                .saturating_add(1),
        ));

        let emitted_total_syscalls: u64 = emitted
            .iter()
            .map(|vector| vector.total_syscalls)
            .sum();
        prop_assert_eq!(
            emitted_total_syscalls,
            u64::try_from(total_events).expect("fixture size fits into u64"),
            "every accepted syscall should appear in exactly one emitted feature vector"
        );

        for vector in &emitted {
            prop_assert!(
                input_pids.contains(&vector.pid),
                "emitted vector pid {} must come from the original schedule",
                vector.pid
            );
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ScheduledEvent {
    pid: u32,
    timestamp: u64,
    syscall_type: SyscallType,
}

fn random_schedule() -> impl Strategy<Value = Vec<ScheduledEvent>> {
    vec(
        (0_u8..6, 0_u64..6_000_000_000, syscall_type_strategy()),
        1..64,
    )
    .prop_map(|mut entries| {
        entries.sort_by_key(|(_, timestamp, _)| *timestamp);
        entries
            .into_iter()
            .map(|(pid_offset, timestamp, syscall_type)| ScheduledEvent {
                pid: 10_000_u32 + u32::from(pid_offset),
                timestamp,
                syscall_type,
            })
            .collect()
    })
}

fn syscall_type_strategy() -> impl Strategy<Value = SyscallType> {
    prop_oneof![
        Just(SyscallType::Execve),
        Just(SyscallType::Openat),
        Just(SyscallType::Connect),
        Just(SyscallType::Clone),
    ]
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
                SyscallType::Openat => Some(format!("/tmp/correlation-{pid}-{timestamp}")),
                _ => None,
            },
            ip_address: match syscall_type {
                SyscallType::Connect => Some([127, 0, 0, 1]),
                _ => None,
            },
            port: match syscall_type {
                SyscallType::Connect => Some(4_444),
                _ => None,
            },
            child_pid: match syscall_type {
                SyscallType::Clone => Some(pid.saturating_add(1)),
                _ => None,
            },
            open_flags: Some(0),
            syscall_result: Some(0),
        },
        process_name: Some(format!("proc-{pid}")),
        binary_path: Some(format!("/usr/bin/proc-{pid}")),
        cgroup: Some(format!("0::/mini-edr/{pid}")),
        uid: Some(1_000),
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
