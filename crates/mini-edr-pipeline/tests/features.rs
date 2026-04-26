//! Integration tests for `ProcessWindow` feature computation.

use mini_edr_common::{EnrichedEvent, ProcessInfo, SyscallEvent, SyscallType};
use mini_edr_pipeline::ProcessWindow;
use proptest::{
    collection::vec,
    prelude::{Just, any, prop_oneof},
    prop_assert, prop_assert_eq, proptest,
    strategy::Strategy,
    test_runner::Config as ProptestConfig,
};
use std::collections::BTreeMap;

const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;
const O_CREAT: u32 = 64;

#[test]
fn features_match_handcrafted_golden_window_within_tolerance() {
    let window = golden_window();
    let feature_vector = window.compute_features(10_000_000_000, false);

    assert_eq!(feature_vector.pid, 4_242);
    assert_eq!(feature_vector.window_start_ns, 0);
    assert_eq!(feature_vector.window_end_ns, 10_000_000_000);
    assert_eq!(feature_vector.total_syscalls, 6);
    assert_eq!(feature_vector.execve_count, 1);
    assert_eq!(feature_vector.openat_count, 2);
    assert_eq!(feature_vector.connect_count, 2);
    assert_eq!(feature_vector.clone_count, 1);
    assert_close(feature_vector.execve_ratio, 1.0 / 6.0);
    assert_close(feature_vector.openat_ratio, 2.0 / 6.0);
    assert_close(feature_vector.connect_ratio, 2.0 / 6.0);
    assert_close(feature_vector.clone_ratio, 1.0 / 6.0);

    let expected_bigrams = BTreeMap::from([
        ("Connect->Clone".to_owned(), 0.2),
        ("Connect->Connect".to_owned(), 0.2),
        ("Execve->Openat".to_owned(), 0.2),
        ("Openat->Connect".to_owned(), 0.2),
        ("Openat->Openat".to_owned(), 0.2),
    ]);
    let expected_trigrams = BTreeMap::from([
        ("Connect->Connect->Clone".to_owned(), 0.25),
        ("Execve->Openat->Openat".to_owned(), 0.25),
        ("Openat->Connect->Connect".to_owned(), 0.25),
        ("Openat->Openat->Connect".to_owned(), 0.25),
    ]);
    assert_eq!(feature_vector.bigrams, expected_bigrams);
    assert_eq!(feature_vector.trigrams, expected_trigrams);

    assert_close(feature_vector.path_entropy, std::f64::consts::LN_2);
    assert_eq!(feature_vector.unique_ips, 2);
    assert_eq!(feature_vector.unique_files, 2);
    assert_eq!(feature_vector.child_spawn_count, 1);
    assert_close(feature_vector.avg_inter_syscall_time_ns, 1_000_000_000.0);
    assert_close(feature_vector.min_inter_syscall_time_ns, 1_000_000_000.0);
    assert_close(feature_vector.max_inter_syscall_time_ns, 1_000_000_000.0);
    assert_close(feature_vector.stddev_inter_syscall_time_ns, 0.0);
    assert!(feature_vector.wrote_etc);
    assert!(!feature_vector.wrote_tmp);
    assert!(!feature_vector.wrote_dev);
    assert_eq!(feature_vector.read_sensitive_file_count, 1);
    assert_eq!(feature_vector.write_sensitive_file_count, 1);
    assert_eq!(feature_vector.outbound_connection_count, 2);
    assert_eq!(feature_vector.loopback_connection_count, 1);
    assert_eq!(feature_vector.distinct_ports, 2);
    assert_eq!(feature_vector.failed_syscall_count, 1);
    assert!(!feature_vector.short_lived);
    assert_eq!(feature_vector.window_duration_ns, 10_000_000_000);
    assert_close(feature_vector.events_per_second, 0.6);
}

#[test]
fn features_require_write_intent_for_sensitive_directory_flags() {
    let scenarios = [
        ("/etc/hosts", Some(O_WRONLY | O_CREAT), (true, false, false)),
        (
            "/tmp/marker",
            Some(O_WRONLY | O_CREAT),
            (false, true, false),
        ),
        ("/dev/null", Some(O_WRONLY), (false, false, true)),
        ("/tmp/read-only", Some(O_RDONLY), (false, false, false)),
        (
            "/home/alexm/notes.txt",
            Some(O_WRONLY | O_CREAT),
            (false, false, false),
        ),
    ];

    for (path, open_flags, expected) in scenarios {
        let mut window = ProcessWindow::new(8080, 0, 5_000_000_000);
        window.push_event(event_with_metadata(
            8080,
            1,
            SyscallType::Openat,
            EventExtras {
                filename: Some(path),
                open_flags,
                ..EventExtras::default()
            },
        ));

        let feature_vector = window.compute_features(5_000_000_000, false);
        assert_eq!(
            (
                feature_vector.wrote_etc,
                feature_vector.wrote_tmp,
                feature_vector.wrote_dev
            ),
            expected,
            "sensitive-directory write flags should only fire for write-capable opens under the documented prefixes"
        );
    }
}

#[test]
fn features_path_entropy_matches_scipy_reference_within_tolerance() {
    let mut window = ProcessWindow::new(9_001, 0, 6_000_000_000);
    let paths = ["/opt/a", "/opt/a", "/opt/a", "/opt/b", "/opt/b", "/opt/c"];

    for (index, path) in paths.into_iter().enumerate() {
        window.push_event(event_with_metadata(
            9_001,
            u64::try_from(index).expect("small fixture index fits into u64"),
            SyscallType::Openat,
            EventExtras {
                filename: Some(path),
                open_flags: Some(O_RDONLY),
                ..EventExtras::default()
            },
        ));
    }

    let feature_vector = window.compute_features(6_000_000_000, false);
    assert_close(feature_vector.path_entropy, 1.011_404_264_707_351_8);
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1_000,
        .. ProptestConfig::default()
    })]

    #[test]
    fn features_invariants_hold_for_1000_random_sequences(events in random_events()) {
        let start = events.first().map_or(0, |event| event.event.timestamp);
        let end = events
            .last()
            .map_or_else(|| start.saturating_add(1), |event| event.event.timestamp.saturating_add(1));
        let duration = end.saturating_sub(start).max(1);

        let mut window = ProcessWindow::new(7_777, start, duration);
        for event in events {
            window.push_event(event);
        }

        let feature_vector = window.compute_features(end, false);

        prop_assert_eq!(
            feature_vector.total_syscalls,
            feature_vector.execve_count
                + feature_vector.openat_count
                + feature_vector.connect_count
                + feature_vector.clone_count
        );
        prop_assert!(feature_vector.execve_ratio.is_finite());
        prop_assert!(feature_vector.openat_ratio.is_finite());
        prop_assert!(feature_vector.connect_ratio.is_finite());
        prop_assert!(feature_vector.clone_ratio.is_finite());
        prop_assert!(feature_vector.avg_inter_syscall_time_ns.is_finite());
        prop_assert!(feature_vector.min_inter_syscall_time_ns.is_finite());
        prop_assert!(feature_vector.max_inter_syscall_time_ns.is_finite());
        prop_assert!(feature_vector.stddev_inter_syscall_time_ns.is_finite());
        prop_assert!(feature_vector.events_per_second.is_finite());
        prop_assert!(feature_vector.path_entropy.is_finite());
        prop_assert!(feature_vector.unique_ips <= feature_vector.connect_count);
        prop_assert!(feature_vector.unique_files <= feature_vector.openat_count);
        prop_assert!(feature_vector.child_spawn_count <= feature_vector.clone_count);

        let ratio_sum =
            feature_vector.execve_ratio
            + feature_vector.openat_ratio
            + feature_vector.connect_ratio
            + feature_vector.clone_ratio;
        prop_assert!((ratio_sum - 1.0).abs() <= 1e-9);

        if feature_vector.total_syscalls >= 2 {
            let bigram_sum: f64 = feature_vector.bigrams.values().sum();
            prop_assert!((bigram_sum - 1.0).abs() <= 1e-9);
        } else {
            prop_assert!(feature_vector.bigrams.is_empty());
        }

        if feature_vector.total_syscalls >= 3 {
            let trigram_sum: f64 = feature_vector.trigrams.values().sum();
            prop_assert!((trigram_sum - 1.0).abs() <= 1e-9);
        } else {
            prop_assert!(feature_vector.trigrams.is_empty());
        }
    }
}

fn golden_window() -> ProcessWindow {
    let mut window = ProcessWindow::new(4_242, 0, 10_000_000_000);
    window.push_event(event_with_metadata(
        4_242,
        0,
        SyscallType::Execve,
        EventExtras::default(),
    ));
    window.push_event(event_with_metadata(
        4_242,
        1_000_000_000,
        SyscallType::Openat,
        EventExtras {
            filename: Some("/etc/passwd"),
            open_flags: Some(O_WRONLY | O_CREAT),
            ..EventExtras::default()
        },
    ));
    window.push_event(event_with_metadata(
        4_242,
        2_000_000_000,
        SyscallType::Openat,
        EventExtras {
            filename: Some("/tmp/readonly"),
            open_flags: Some(O_RDONLY),
            ..EventExtras::default()
        },
    ));
    window.push_event(event_with_metadata(
        4_242,
        3_000_000_000,
        SyscallType::Connect,
        EventExtras {
            ip_address: Some([10, 0, 0, 8]),
            port: Some(443),
            ..EventExtras::default()
        },
    ));
    window.push_event(event_with_metadata(
        4_242,
        4_000_000_000,
        SyscallType::Connect,
        EventExtras {
            ip_address: Some([127, 0, 0, 1]),
            port: Some(8_080),
            syscall_result: Some(-111),
            ..EventExtras::default()
        },
    ));
    window.push_event(event_with_metadata(
        4_242,
        5_000_000_000,
        SyscallType::Clone,
        EventExtras {
            child_pid: Some(4_243),
            syscall_result: Some(4_243),
            ..EventExtras::default()
        },
    ));
    window
}

#[derive(Clone, Copy, Debug, Default)]
struct EventExtras<'a> {
    filename: Option<&'a str>,
    ip_address: Option<[u8; 4]>,
    port: Option<u16>,
    child_pid: Option<u32>,
    open_flags: Option<u32>,
    syscall_result: Option<i32>,
}

fn event_with_metadata(
    pid: u32,
    timestamp: u64,
    syscall_type: SyscallType,
    extras: EventExtras<'_>,
) -> EnrichedEvent {
    EnrichedEvent {
        event: SyscallEvent {
            event_id: timestamp.saturating_add(1),
            timestamp,
            pid,
            tid: pid,
            ppid: 1,
            syscall_type,
            filename: extras.filename.map(str::to_owned),
            ip_address: extras.ip_address,
            port: extras.port,
            child_pid: extras.child_pid,
            open_flags: extras.open_flags,
            syscall_result: extras.syscall_result.or(Some(0)),
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

fn random_events() -> impl Strategy<Value = Vec<EnrichedEvent>> {
    vec(
        (
            prop_oneof![
                Just(SyscallType::Execve),
                Just(SyscallType::Openat),
                Just(SyscallType::Connect),
                Just(SyscallType::Clone),
            ],
            any::<u16>(),
            any::<u16>(),
            any::<bool>(),
        ),
        1..32,
    )
    .prop_map(|entries| {
        let mut timestamp = 0_u64;
        entries
            .into_iter()
            .enumerate()
            .map(|(index, (syscall_type, delta_ms, discriminator, failed))| {
                timestamp = timestamp.saturating_add(u64::from(delta_ms % 100).saturating_add(1));
                let pid = 7_777;
                let extras = match syscall_type {
                    SyscallType::Execve => EventExtras {
                        syscall_result: Some(if failed { -1 } else { 0 }),
                        ..EventExtras::default()
                    },
                    SyscallType::Openat => EventExtras {
                        filename: Some(match discriminator % 4 {
                            0 => "/etc/mini-edr.conf",
                            1 => "/tmp/mini-edr.tmp",
                            2 => "/dev/null",
                            _ => "/home/alexm/mini-edr.txt",
                        }),
                        open_flags: Some(if discriminator % 2 == 0 {
                            O_WRONLY | O_CREAT
                        } else {
                            O_RDONLY
                        }),
                        syscall_result: Some(if failed { -13 } else { 3 }),
                        ..EventExtras::default()
                    },
                    SyscallType::Connect => EventExtras {
                        ip_address: Some(if discriminator % 2 == 0 {
                            [127, 0, 0, 1]
                        } else {
                            [10, 0, 0, 8]
                        }),
                        port: Some(1_024 + (discriminator % 32)),
                        syscall_result: Some(if failed { -111 } else { 0 }),
                        ..EventExtras::default()
                    },
                    SyscallType::Clone => EventExtras {
                        child_pid: Some(
                            8_000 + u32::try_from(index).expect("small index fits into u32"),
                        ),
                        syscall_result: Some(if failed {
                            -12
                        } else {
                            8_000 + i32::try_from(index).expect("small index fits into i32")
                        }),
                        ..EventExtras::default()
                    },
                };

                event_with_metadata(pid, timestamp, syscall_type, extras)
            })
            .collect()
    })
}

fn assert_close(actual: f64, expected: f64) {
    let delta = (actual - expected).abs();
    assert!(
        delta <= 1e-6,
        "expected {expected} but observed {actual} (|delta|={delta})"
    );
}
