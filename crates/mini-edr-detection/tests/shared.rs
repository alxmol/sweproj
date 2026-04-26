//! Shared detection-test fixtures.

use std::collections::BTreeMap;

use mini_edr_common::FeatureVector;

/// Return a deterministic feature vector shared by reload/model-hash tests.
#[must_use]
pub fn sample_feature_vector() -> FeatureVector {
    let mut bigrams = BTreeMap::new();
    bigrams.insert("__process_positive_rate__".to_owned(), 0.95);
    bigrams.insert("__event_positive_rate__".to_owned(), 0.30);

    let mut trigrams = BTreeMap::new();
    trigrams.insert("__path_positive_rate__".to_owned(), 0.80);

    FeatureVector {
        pid: 4_242,
        window_start_ns: 1_713_000_000_000_000_000,
        window_end_ns: 1_713_000_005_000_000_000,
        total_syscalls: 128,
        execve_count: 1,
        openat_count: 100,
        connect_count: 3,
        clone_count: 2,
        execve_ratio: 0.007_812_5,
        openat_ratio: 0.781_25,
        connect_ratio: 0.023_437_5,
        clone_ratio: 0.015_625,
        bigrams,
        trigrams,
        path_entropy: 1.5,
        unique_ips: 2,
        unique_files: 12,
        child_spawn_count: 2,
        avg_inter_syscall_time_ns: 1_500_000.0,
        min_inter_syscall_time_ns: 10_000.0,
        max_inter_syscall_time_ns: 9_000_000.0,
        stddev_inter_syscall_time_ns: 500_000.0,
        wrote_etc: true,
        wrote_tmp: true,
        wrote_dev: false,
        read_sensitive_file_count: 4,
        write_sensitive_file_count: 2,
        outbound_connection_count: 3,
        loopback_connection_count: 1,
        distinct_ports: 2,
        failed_syscall_count: 1,
        short_lived: false,
        window_duration_ns: 5_000_000_000,
        events_per_second: 25.6,
    }
}
