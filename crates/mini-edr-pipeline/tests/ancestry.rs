//! Integration tests for process ancestry reconstruction.

use mini_edr_common::{SyscallEvent, SyscallType};
use mini_edr_pipeline::{EventEnricher, ProcReader};
use std::{env, fs, os::unix::fs::symlink, path::Path};
use tempfile::TempDir;

#[test]
fn ancestry_reconstructs_parent_first_four_level_chain() {
    let fixture = ProcFixture::new();
    fixture.write_process(1, 0, "init", "/sbin/init", 10);
    fixture.write_process(100, 1, "bash", "/usr/bin/bash", 20);
    fixture.write_process(200, 100, "python", "/usr/bin/python3", 30);
    fixture.write_process(300, 200, "leaf", "/tmp/leaf", 40);

    let proc_reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
    let mut pipeline_enricher = EventEnricher::new(proc_reader);
    let enriched_event =
        pipeline_enricher.enrich_event(sample_event(300, 200, SyscallType::Execve, None));

    let observed_pids: Vec<u32> = enriched_event
        .ancestry_chain
        .iter()
        .map(|info| info.pid)
        .collect();
    assert_eq!(observed_pids, vec![1, 100, 200, 300]);
    assert!(!enriched_event.ancestry_truncated);
    assert_eq!(enriched_event.process_name, "leaf");
    assert_eq!(enriched_event.binary_path, "/tmp/leaf");
    assert_eq!(enriched_event.cgroup, "0::/proc/300\n");
    assert_eq!(enriched_event.uid, 1_000);
}

#[test]
fn ancestry_stops_at_pid_one_and_omits_pid_zero_sentinel() {
    let fixture = ProcFixture::new();
    fixture.write_process(1, 0, "init", "/sbin/init", 10);

    let proc_reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
    let mut pipeline_enricher = EventEnricher::new(proc_reader);
    let enriched_event =
        pipeline_enricher.enrich_event(sample_event(1, 0, SyscallType::Openat, None));

    let observed_pids: Vec<u32> = enriched_event
        .ancestry_chain
        .iter()
        .map(|info| info.pid)
        .collect();
    assert_eq!(observed_pids, vec![1]);
    assert!(
        enriched_event
            .ancestry_chain
            .iter()
            .all(|info| info.pid != 0),
        "PID 0 is a traversal sentinel and must never surface as a synthetic ancestry entry"
    );
}

#[test]
fn ancestry_truncates_deep_chain_at_default_depth_without_recursion() {
    let fixture = ProcFixture::new();
    fixture.write_linear_chain(10_000);

    let proc_reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
    let mut pipeline_enricher = EventEnricher::new(proc_reader);
    let enriched_event =
        pipeline_enricher.enrich_event(sample_event(10_000, 9_999, SyscallType::Clone, None));

    assert!(enriched_event.ancestry_truncated);
    assert_eq!(
        enriched_event.ancestry_chain.len(),
        EventEnricher::DEFAULT_MAX_ANCESTRY_DEPTH
    );
    assert_eq!(
        enriched_event.ancestry_chain.first().map(|info| info.pid),
        Some(8_977)
    );
    assert_eq!(
        enriched_event.ancestry_chain.last().map(|info| info.pid),
        Some(10_000)
    );
}

#[test]
fn ancestry_reused_pid_never_inherits_stale_cached_chain_after_clone_event() {
    let fixture = ProcFixture::new();
    fixture.write_process(1, 0, "init", "/sbin/init", 10);
    fixture.write_process(50, 1, "old-parent", "/usr/bin/old-parent", 20);
    fixture.write_process(60, 1, "new-parent", "/usr/bin/new-parent", 30);
    fixture.write_process(500, 50, "worker", "/usr/bin/worker-old", 40);

    let proc_reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
    let mut pipeline_enricher = EventEnricher::new(proc_reader);

    let first = pipeline_enricher.enrich_event(sample_event(500, 50, SyscallType::Execve, None));
    let first_chain: Vec<u32> = first.ancestry_chain.iter().map(|info| info.pid).collect();
    assert_eq!(first_chain, vec![1, 50, 500]);

    fixture.write_process(500, 60, "worker", "/usr/bin/worker-new", 4_000);
    let _ = pipeline_enricher.enrich_event(sample_event(60, 1, SyscallType::Clone, Some(500)));

    let second = pipeline_enricher.enrich_event(sample_event(500, 60, SyscallType::Execve, None));
    let second_chain: Vec<u32> = second.ancestry_chain.iter().map(|info| info.pid).collect();
    assert_eq!(second_chain, vec![1, 60, 500]);
    assert_eq!(second.binary_path, "/usr/bin/worker-new");
}

#[test]
fn ancestry_spawn_chain_fixture_matches_requested_depth() {
    let Some(depth) = configured_depth() else {
        return;
    };
    let fixture = ProcFixture::new();
    fixture.write_linear_chain(depth);

    let proc_reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
    let mut pipeline_enricher = EventEnricher::new(proc_reader);
    let parent_pid = depth.saturating_sub(1).max(1);
    let enriched_event =
        pipeline_enricher.enrich_event(sample_event(depth, parent_pid, SyscallType::Execve, None));

    assert_eq!(enriched_event.ancestry_chain.len(), depth as usize);
    assert_eq!(
        enriched_event.ancestry_chain.first().map(|info| info.pid),
        Some(1)
    );
    assert_eq!(
        enriched_event.ancestry_chain.last().map(|info| info.pid),
        Some(depth)
    );
}

#[test]
fn ancestry_deep_chain_stack_safety_fixture_matches_requested_depth() {
    let Some(depth) = configured_depth() else {
        return;
    };
    let fixture = ProcFixture::new();
    fixture.write_linear_chain(depth);

    let proc_reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
    let mut pipeline_enricher = EventEnricher::new(proc_reader);
    let parent_pid = depth.saturating_sub(1).max(1);
    let enriched_event =
        pipeline_enricher.enrich_event(sample_event(depth, parent_pid, SyscallType::Execve, None));

    assert_eq!(
        enriched_event.ancestry_chain.len(),
        EventEnricher::DEFAULT_MAX_ANCESTRY_DEPTH
    );
    assert!(enriched_event.ancestry_truncated);
    assert_eq!(
        enriched_event.ancestry_chain.last().map(|info| info.pid),
        Some(depth)
    );
}

const fn sample_event(
    pid: u32,
    parent_pid: u32,
    syscall_type: SyscallType,
    child_pid: Option<u32>,
) -> SyscallEvent {
    SyscallEvent {
        event_id: 1,
        timestamp: 123,
        pid,
        tid: pid,
        ppid: parent_pid,
        syscall_type,
        filename: None,
        ip_address: None,
        port: None,
        child_pid,
        open_flags: None,
        syscall_result: Some(0),
    }
}

fn configured_depth() -> Option<u32> {
    env::var("MINI_EDR_TEST_CHAIN_DEPTH").ok().map(|value| {
        value
            .parse()
            .expect("MINI_EDR_TEST_CHAIN_DEPTH must parse as u32")
    })
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

    fn write_linear_chain(&self, depth: u32) {
        for pid in 1..=depth {
            let parent_pid = if pid == 1 { 0 } else { pid - 1 };
            let exe = format!("/tmp/chain-{pid}");
            let name = format!("chain-{pid}");
            self.write_process(pid, parent_pid, &name, &exe, u64::from(pid) * 10);
        }
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
            self.root().join("mounts"),
            "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n",
        )
        .expect("mounts fixture is written");
        fs::write(
            pid_dir.join("status"),
            format!(
                "Name:\t{name}\nTgid:\t{pid}\nPPid:\t{parent_pid}\nUid:\t1000\t1000\t1000\t1000\n"
            ),
        )
        .expect("status fixture is written");
        fs::write(pid_dir.join("cgroup"), format!("0::/proc/{pid}\n"))
            .expect("cgroup fixture is written");
        fs::write(
            pid_dir.join("stat"),
            make_stat_record(pid, name, parent_pid, start_time_ticks),
        )
        .expect("stat fixture is written");
        let exe_path = pid_dir.join("exe");
        if fs::symlink_metadata(&exe_path).is_ok() {
            fs::remove_file(&exe_path).expect("old exe symlink is removed");
        }
        symlink(exe, exe_path).expect("exe symlink fixture is created");
    }

    fn write_mounts(&self) {
        fs::write(
            self.root().join("mounts"),
            "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n",
        )
        .expect("mounts fixture is written");
    }
}

fn make_stat_record(pid: u32, name: &str, parent_pid: u32, start_time_ticks: u64) -> String {
    format!(
        "{pid} ({name}) S {parent_pid} {pid} {pid} 0 -1 0 0 0 0 0 0 0 0 20 0 1 0 {start_time_ticks} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
    )
}
