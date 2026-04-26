//! Shared Mini-EDR domain and configuration foundation.
//!
//! This crate is intentionally dependency-free at workspace bootstrap time. Per
//! SDD §8.2, all other crates are allowed to depend on `mini-edr-common`, while
//! `mini-edr-common` depends on no workspace crate. That invariant prevents
//! cycles and gives later features a stable home for shared schemas.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Version marker used by downstream skeleton crates to prove they link against
/// the shared foundation without introducing reverse dependencies.
pub const WORKSPACE_TOPOLOGY_VERSION: &str = "mini-edr-workspace-v1";

/// Enumerates the syscall probes supported by the Mini-EDR sensor.
///
/// The JSON representation intentionally uses `PascalCase` (`"Openat"`) because
/// the validation contract and user-facing APIs cite variants in that form.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum SyscallType {
    /// Process image replacement through `execve`.
    Execve,
    /// File open operation through `openat`.
    Openat,
    /// Network connection attempt through `connect`.
    Connect,
    /// Process or thread creation through `clone`/`fork`.
    Clone,
}

/// Userspace domain representation of a raw kernel syscall event.
///
/// Per SDD §4.1.1 and §5.1 this is the first stable schema boundary after
/// ring-buffer deserialization. Syscall-specific arguments are optional so one
/// enum-discriminated struct can represent all monitored syscall variants
/// without losing type safety.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyscallEvent {
    /// Monotonic event identifier assigned by userspace after ring-buffer read.
    pub event_id: u64,
    /// Kernel event timestamp in nanoseconds.
    pub timestamp: u64,
    /// Thread-group/process identifier that issued the syscall.
    pub pid: u32,
    /// Kernel thread identifier that issued the syscall.
    pub tid: u32,
    /// Parent process identifier observed at capture time.
    pub ppid: u32,
    /// Which monitored syscall produced this event.
    pub syscall_type: SyscallType,
    /// Resolved filename for file-oriented syscalls such as `openat`.
    pub filename: Option<String>,
    /// IPv4 address in host-byte-order octets for `connect` events.
    pub ip_address: Option<[u8; 4]>,
    /// Destination port for `connect` events.
    pub port: Option<u16>,
    /// Child process identifier returned by `clone`/`fork` style events.
    pub child_pid: Option<u32>,
}

/// Lightweight process descriptor embedded in ancestry chains.
///
/// SDD §4.1.2 deliberately keeps this schema small so the pipeline can attach
/// enough context for TUI/Web drill-downs without copying full process state
/// into every event or alert.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessInfo {
    /// Process identifier for this ancestry entry.
    pub pid: u32,
    /// Human-readable process name from `/proc/<pid>/status`.
    pub process_name: String,
    /// Absolute binary path resolved from `/proc/<pid>/exe`.
    pub binary_path: String,
}

/// A syscall event enriched with `/proc` metadata and ancestry context.
///
/// Per SDD §4.1.2 and §5.1 this type is transient in-memory data. Optional
/// enrichment failures are represented by empty strings only in later pipeline
/// policies; the shared schema keeps fields concrete because downstream UI and
/// alert code expect a stable shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnrichedEvent {
    /// Original sensor event that anchors this enrichment.
    pub event: SyscallEvent,
    /// Process name read from `/proc/<pid>/status`.
    pub process_name: String,
    /// Absolute executable path read from `/proc/<pid>/exe`.
    pub binary_path: String,
    /// Full cgroup hierarchy read from `/proc/<pid>/cgroup`.
    pub cgroup: String,
    /// Real user identifier associated with the process.
    pub uid: u32,
    /// Parent-first process ancestry chain ending at the observed process.
    pub ancestry_chain: Vec<ProcessInfo>,
    /// Whether the pipeline truncated ancestry to its configured safety cap.
    pub ancestry_truncated: bool,
    /// Number of equivalent raw events collapsed into this enriched record.
    pub repeat_count: u32,
}

/// Fixed schema of per-process behavioral features for ML inference.
///
/// SDD §4.1.2/§5.1 and SRS FR-P05 define a stable feature-vector boundary that
/// later training and ONNX inference code will consume by field name. The
/// schema uses explicit scalar fields for model inputs and deterministic
/// `BTreeMap`s for n-gram frequency maps so JSON snapshots are reproducible in
/// tests and append-only schema evolution can add new fields at the end.
#[allow(
    clippy::struct_excessive_bools,
    reason = "FR-P05 requires explicit boolean sensitive-directory flags in the public JSON schema"
)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FeatureVector {
    /// Process identifier for the window being scored.
    pub pid: u32,
    /// Inclusive window start timestamp in nanoseconds.
    pub window_start: u64,
    /// Exclusive window end timestamp in nanoseconds.
    pub window_end: u64,
    /// Total syscall count observed in the half-open window.
    pub total_syscalls: u64,
    /// Count of `execve` events in the window.
    pub execve_count: u64,
    /// Count of `openat` events in the window.
    pub openat_count: u64,
    /// Count of `connect` events in the window.
    pub connect_count: u64,
    /// Count of `clone` events in the window.
    pub clone_count: u64,
    /// Fraction of window events that were `execve`.
    pub execve_ratio: f64,
    /// Fraction of window events that were `openat`.
    pub openat_ratio: f64,
    /// Fraction of window events that were `connect`.
    pub connect_ratio: f64,
    /// Fraction of window events that were `clone`.
    pub clone_ratio: f64,
    /// Syscall bigram frequency distribution keyed as `A->B`.
    pub bigrams: BTreeMap<String, f64>,
    /// Syscall trigram frequency distribution keyed as `A->B->C`.
    pub trigrams: BTreeMap<String, f64>,
    /// Shannon entropy of accessed file paths.
    pub path_entropy: f64,
    /// Count of distinct IPv4 addresses contacted.
    pub unique_ips: u64,
    /// Count of distinct files opened.
    pub unique_files: u64,
    /// Count of child process spawn events.
    pub child_spawn_count: u64,
    /// Mean interval between adjacent syscalls in nanoseconds.
    pub avg_inter_syscall_time_ns: f64,
    /// Minimum interval between adjacent syscalls in nanoseconds.
    pub min_inter_syscall_time_ns: f64,
    /// Maximum interval between adjacent syscalls in nanoseconds.
    pub max_inter_syscall_time_ns: f64,
    /// Standard deviation of adjacent syscall intervals in nanoseconds.
    pub stddev_inter_syscall_time_ns: f64,
    /// Whether the window wrote to `/etc`.
    pub wrote_etc: bool,
    /// Whether the window wrote to `/tmp`.
    pub wrote_tmp: bool,
    /// Whether the window wrote to `/dev`.
    pub wrote_dev: bool,
    /// Count of read attempts against sensitive filesystem paths.
    pub read_sensitive_file_count: u64,
    /// Count of write attempts against sensitive filesystem paths.
    pub write_sensitive_file_count: u64,
    /// Count of outbound connection attempts.
    pub outbound_connection_count: u64,
    /// Count of loopback connection attempts.
    pub loopback_connection_count: u64,
    /// Count of distinct destination ports contacted.
    pub distinct_ports: u64,
    /// Count of syscalls that reported failure.
    pub failed_syscall_count: u64,
    /// Whether this vector represents a partial short-lived process window.
    pub short_lived: bool,
    /// Duration represented by this vector in nanoseconds.
    pub window_duration_ns: u64,
    /// Event rate over the represented window.
    pub events_per_second: f64,
}

/// A named contribution to an ML inference result.
///
/// Detection and alerting use exactly five of these entries per FR-D04 so
/// analysts can see why a model score crossed the alert threshold.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FeatureContribution {
    /// Stable feature name matching a `FeatureVector` field or derived feature.
    pub feature_name: String,
    /// Signed or unsigned contribution score reported by the model explainer.
    pub contribution_score: f64,
}

/// Detection result persisted to the append-only alert log.
///
/// Per SDD §4.1.3/§5.1 and SRS FR-D04 this is the only shared type that is
/// durable. Alert log writers must serialize it with `serde_json::to_string`
/// rather than pretty-printing; serde escapes embedded string newlines, so each
/// alert remains a single physical JSON line for FR-A01.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Alert {
    /// Monotonic alert identifier assigned by the alert generator.
    pub alert_id: u64,
    /// Alert creation timestamp in nanoseconds since the Unix epoch.
    pub timestamp: u64,
    /// Process identifier that generated the scored feature vector.
    pub pid: u32,
    /// Human-readable process name associated with the alert.
    pub process_name: String,
    /// Absolute binary path associated with the alert.
    pub binary_path: String,
    /// Parent-first ancestry chain for analyst context.
    pub ancestry_chain: Vec<ProcessInfo>,
    /// Model threat score in the inclusive range `[0.0, 1.0]`.
    pub threat_score: f64,
    /// Top contributing features, expected to contain exactly five entries.
    pub top_features: Vec<FeatureContribution>,
    /// Human-readable one-line summary for TUI/Web alert timelines.
    pub summary: String,
}

#[cfg(test)]
mod tests {
    use super::{
        Alert, EnrichedEvent, FeatureContribution, FeatureVector, ProcessInfo, SyscallEvent,
        SyscallType, WORKSPACE_TOPOLOGY_VERSION,
    };
    use std::collections::BTreeMap;

    #[test]
    fn topology_version_names_the_bootstrap_contract() {
        // This smoke test gives `cargo nextest run --workspace` a real test to
        // execute during the bootstrap feature. Later feature work will replace
        // this with schema and validation tests, but keeping this tiny assertion
        // now proves that the common crate test harness is wired correctly.
        assert_eq!(WORKSPACE_TOPOLOGY_VERSION, "mini-edr-workspace-v1");
    }

    #[test]
    fn alert_serializes_as_one_json_line_and_round_trips() {
        let alert = sample_alert();

        let json = serde_json::to_string(&alert).expect("alert serializes");
        println!("sample_alert_json={json}");
        assert!(
            !json.contains('\n'),
            "FR-A01 requires one physical JSON line per alert record"
        );

        let reparsed: Alert = serde_json::from_str(&json).expect("alert deserializes");
        assert_eq!(reparsed, alert);
    }

    #[test]
    fn enriched_event_round_trips_through_json() {
        let enriched = sample_enriched_event();

        let json = serde_json::to_string(&enriched).expect("enriched event serializes");
        let reparsed: EnrichedEvent =
            serde_json::from_str(&json).expect("enriched event deserializes");

        assert_eq!(reparsed, enriched);
    }

    #[test]
    fn feature_vector_round_trips_and_exposes_required_schema_keys() {
        let vector = sample_feature_vector();

        let json = serde_json::to_string(&vector).expect("feature vector serializes");
        let value: serde_json::Value =
            serde_json::from_str(&json).expect("feature vector parses as JSON");
        let object = value.as_object().expect("feature vector is a JSON object");

        for key in [
            "execve_count",
            "openat_count",
            "connect_count",
            "clone_count",
            "bigrams",
            "trigrams",
            "path_entropy",
            "unique_ips",
            "unique_files",
            "child_spawn_count",
            "avg_inter_syscall_time_ns",
            "wrote_etc",
            "wrote_tmp",
            "wrote_dev",
        ] {
            assert!(object.contains_key(key), "missing schema key: {key}");
        }

        let reparsed: FeatureVector =
            serde_json::from_str(&json).expect("feature vector deserializes");
        assert_eq!(reparsed, vector);
    }

    #[test]
    fn syscall_type_uses_pascal_case_json_names() {
        let event = sample_syscall_event();

        let json = serde_json::to_string(&event).expect("syscall event serializes");
        assert!(
            json.contains(r#""syscall_type":"Openat""#),
            "validation contract expects syscall_type values like Openat"
        );

        let reparsed: SyscallEvent =
            serde_json::from_str(&json).expect("syscall event deserializes");
        assert_eq!(reparsed.syscall_type, SyscallType::Openat);
    }

    fn sample_process_info(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            process_name: name.to_owned(),
            binary_path: format!("/usr/bin/{name}"),
        }
    }

    fn sample_syscall_event() -> SyscallEvent {
        SyscallEvent {
            event_id: 42,
            timestamp: 1_713_000_000_123_456_789,
            pid: 4_242,
            tid: 4_242,
            ppid: 1_001,
            syscall_type: SyscallType::Openat,
            filename: Some("/tmp/mini-edr-marker".to_owned()),
            ip_address: Some([127, 0, 0, 1]),
            port: Some(8_080),
            child_pid: Some(4_243),
        }
    }

    fn sample_enriched_event() -> EnrichedEvent {
        EnrichedEvent {
            event: sample_syscall_event(),
            process_name: "curl".to_owned(),
            binary_path: "/usr/bin/curl".to_owned(),
            cgroup: "0::/user.slice/user-1000.slice/session-2.scope".to_owned(),
            uid: 1_000,
            ancestry_chain: vec![
                sample_process_info(1, "systemd"),
                sample_process_info(1_001, "bash"),
            ],
            ancestry_truncated: false,
            repeat_count: 1,
        }
    }

    fn sample_feature_vector() -> FeatureVector {
        let mut bigrams = BTreeMap::new();
        bigrams.insert("Execve->Openat".to_owned(), 2.0);

        let mut trigrams = BTreeMap::new();
        trigrams.insert("Execve->Openat->Connect".to_owned(), 1.0);

        FeatureVector {
            pid: 4_242,
            window_start: 1_713_000_000_000_000_000,
            window_end: 1_713_000_005_000_000_000,
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

    fn sample_alert() -> Alert {
        Alert {
            alert_id: 7,
            timestamp: 1_713_000_005_123_456_789,
            pid: 4_242,
            process_name: "curl".to_owned(),
            binary_path: "/usr/bin/curl".to_owned(),
            ancestry_chain: vec![
                sample_process_info(1, "systemd"),
                sample_process_info(1_001, "bash"),
            ],
            threat_score: 0.92,
            top_features: vec![
                FeatureContribution {
                    feature_name: "connect_count".to_owned(),
                    contribution_score: 0.31,
                },
                FeatureContribution {
                    feature_name: "path_entropy".to_owned(),
                    contribution_score: 0.22,
                },
                FeatureContribution {
                    feature_name: "wrote_etc".to_owned(),
                    contribution_score: 0.18,
                },
                FeatureContribution {
                    feature_name: "child_spawn_count".to_owned(),
                    contribution_score: 0.14,
                },
                FeatureContribution {
                    feature_name: "openat_count".to_owned(),
                    contribution_score: 0.07,
                },
            ],
            summary: "curl exhibited suspicious network and file-access behavior\nnewline escaped"
                .to_owned(),
        }
    }
}
