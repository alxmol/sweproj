//! Stress-oriented regression tests for fork storms and reload races.
//!
//! These tests lock the pipeline-side guarantees needed before the later
//! daemon integration can drive VAL-PIPELINE-022 with live probes. They focus
//! on two failure modes the pipeline can control today: ancestry cycles caused
//! by parent/child reuse races, and duplicate partial-window emission when a
//! fork storm overlaps a configuration reload.

use mini_edr_common::{EnrichedEvent, ProcessInfo, SyscallEvent, SyscallType};
use mini_edr_pipeline::{EventEnricher, ProcReader, WindowAggregator};
use std::{
    collections::HashSet,
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

#[test]
fn stress_breaks_ancestry_cycles_instead_of_repeating_pids() {
    let fixture = ProcFixture::new();
    fixture.write_process(1, 0, "init", "/sbin/init", 10);
    fixture.write_process(200, 300, "child", "/usr/bin/child", 20);
    fixture.write_process(300, 200, "parent", "/usr/bin/parent", 30);

    let proc_reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
    let mut enricher = EventEnricher::new(proc_reader);
    let enriched_event = enricher.enrich_event(sample_event(200, 300, 1));
    let pids: Vec<u32> = enriched_event
        .ancestry_chain
        .iter()
        .map(|process| process.pid)
        .collect();

    assert_eq!(
        pids.last().copied(),
        Some(200),
        "the observed process must remain present even when we cut off a corrupt parent loop"
    );
    assert_eq!(
        pids.iter().copied().collect::<HashSet<u32>>().len(),
        pids.len(),
        "a reload/fork race must not produce repeated PIDs in ancestry output"
    );
    assert_eq!(
        pids.len(),
        2,
        "the enricher should stop at the first repeated PID instead of looping until the depth cap"
    );
}

#[test]
fn stress_fork_storm_fixture_accepts_rate_and_duration_knobs() {
    let fixture = repo_root().join("tests/fixtures/fork_storm");
    let output = Command::new(&fixture)
        .args(["--rate", "64", "--duration", "50ms"])
        .output()
        .expect("fork_storm fixture should be executable");

    assert!(
        output.status.success(),
        "fixture exited with status {} and stderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("target_rate_per_sec=64"),
        "fixture stdout should echo the requested rate; stdout was:\n{stdout}"
    );
    assert!(
        stdout.contains("requested_duration_ms=50"),
        "fixture stdout should echo the requested duration; stdout was:\n{stdout}"
    );
}

#[test]
fn stress_reload_reconfiguration_does_not_duplicate_partial_windows_in_50k_process_burst() {
    let mut aggregator = WindowAggregator::new(5);
    let mut emitted_pids = HashSet::new();

    for offset in 0_u32..50_000 {
        if offset % 10_000 == 0 {
            aggregator.set_window_duration_secs(if (offset / 10_000) % 2 == 0 { 1 } else { 5 });
            aggregator.set_dedup_window_ms(100);
        }

        let pid = 10_000_u32.saturating_add(offset);
        let timestamp = u64::from(offset).saturating_mul(1_000_000);
        assert!(
            aggregator
                .push_event(sample_enriched_event(pid, timestamp))
                .is_empty(),
            "one event per forked child should only arm the active partial window"
        );

        let vector = aggregator
            .close_process(pid, timestamp.saturating_add(1))
            .expect("each child exit should emit exactly one partial vector");
        assert!(vector.short_lived);
        assert_eq!(vector.total_syscalls, 1);
        assert!(
            emitted_pids.insert(vector.pid),
            "reload updates must not cause duplicate partial windows for pid {}",
            vector.pid
        );
    }

    assert_eq!(
        emitted_pids.len(),
        50_000,
        "the synthetic fork storm should yield one partial vector per child process"
    );
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root resolves")
}

const fn sample_event(pid: u32, parent_pid: u32, event_id: u64) -> SyscallEvent {
    SyscallEvent {
        event_id,
        timestamp: event_id.saturating_mul(1_000),
        pid,
        tid: pid,
        ppid: parent_pid,
        syscall_type: SyscallType::Clone,
        filename: None,
        ip_address: None,
        port: None,
        child_pid: Some(pid.saturating_add(1)),
        open_flags: None,
        syscall_result: Some(0),
    }
}

fn sample_enriched_event(pid: u32, timestamp: u64) -> EnrichedEvent {
    EnrichedEvent {
        event: SyscallEvent {
            event_id: timestamp.saturating_add(1),
            timestamp,
            pid,
            tid: pid,
            ppid: 1,
            syscall_type: SyscallType::Clone,
            filename: None,
            ip_address: None,
            port: None,
            child_pid: Some(pid.saturating_add(1)),
            open_flags: None,
            syscall_result: Some(0),
        },
        process_name: format!("fork-child-{pid}"),
        binary_path: "/usr/bin/true".to_owned(),
        cgroup: "0::/mini-edr/stress".to_owned(),
        uid: 1_000,
        ancestry_chain: vec![
            ProcessInfo {
                pid: 1,
                process_name: "init".to_owned(),
                binary_path: "/sbin/init".to_owned(),
            },
            ProcessInfo {
                pid,
                process_name: format!("fork-child-{pid}"),
                binary_path: "/usr/bin/true".to_owned(),
            },
        ],
        ancestry_truncated: false,
        repeat_count: 1,
    }
}

struct ProcFixture {
    tempdir: TempDir,
}

impl ProcFixture {
    fn new() -> Self {
        let tempdir = tempfile::tempdir().expect("temporary proc fixture root exists");
        let fixture = Self { tempdir };
        fixture.write_mounts();
        fixture
    }

    fn root(&self) -> &Path {
        self.tempdir.path()
    }

    fn write_mounts(&self) {
        fs::write(
            self.root().join("mounts"),
            "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n",
        )
        .expect("mountinfo fixture writes");
    }

    fn write_process(
        &self,
        pid: u32,
        parent_pid: u32,
        name: &str,
        exe: &str,
        start_time_ticks: u64,
    ) {
        let pid_dir = self.root().join(pid.to_string());
        fs::create_dir_all(&pid_dir).expect("pid fixture directory exists");
        fs::write(
            pid_dir.join("status"),
            format!(
                "Name:\t{name}\nTgid:\t{pid}\nPPid:\t{parent_pid}\nUid:\t1000\t1000\t1000\t1000\n"
            ),
        )
        .expect("status fixture writes");
        fs::write(
            pid_dir.join("stat"),
            format!(
                "{pid} ({name}) S {parent_pid} {pid} {pid} 0 -1 0 0 0 0 0 0 0 0 20 0 1 0 {start_time_ticks} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
            ),
        )
        .expect("stat fixture writes");
        fs::write(pid_dir.join("cgroup"), format!("0::/proc/{pid}\n"))
            .expect("cgroup fixture writes");

        let exe_link = pid_dir.join("exe");
        let _ = fs::remove_file(&exe_link);
        symlink(exe, exe_link).expect("exe symlink fixture writes");
    }
}
