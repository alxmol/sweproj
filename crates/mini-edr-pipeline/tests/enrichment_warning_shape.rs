//! Regression tests for partial-enrichment warning shape and missing-field semantics.
//!
//! These tests lock in the user-testing contracts behind VAL-PIPELINE-004 and
//! VAL-REL-004: missing `/proc` metadata must surface as `None`, and transient
//! enrichment failures must emit exactly one structured warning per affected
//! PID rather than one warning per missing field or per repeated event.

use mini_edr_common::{EnrichedEvent, SyscallEvent, SyscallType};
use mini_edr_pipeline::{EventEnricher, ProcReader};
use std::{
    fs, io,
    path::Path,
    sync::{Arc, Mutex},
};
use tempfile::TempDir;
use tracing::subscriber::with_default;
use tracing_subscriber::fmt::MakeWriter;

#[test]
fn single_warn_per_pid_when_proc_disappears() {
    let fixture = MissingProcFixture::new();
    let reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
    let mut enricher = EventEnricher::new(reader);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(TestWriterFactory::new(&buffer))
        .finish();

    with_default(subscriber, || {
        for event_id in 0_u64..3 {
            let _ = enricher.enrich_event(sample_event(12_345, event_id));
        }
    });

    let logs = captured_logs(&buffer);
    let matching_lines: Vec<&str> = logs
        .lines()
        .filter(|line| {
            line.contains("enrichment_partial")
                && line.contains("pid=12345")
                && contains_reason_proc_unavailable(line)
        })
        .collect();
    assert_eq!(
        matching_lines.len(),
        1,
        "expected exactly one partial-enrichment warning for pid 12345: {logs}"
    );
    assert!(
        matching_lines
            .iter()
            .any(|line| line.contains("process exited before enrichment")),
        "warning should carry the human-readable disappearance message: {logs}"
    );

    for forbidden in ["panic", "unwrap", "PoisonError", "aborted"] {
        assert!(
            !logs.contains(forbidden),
            "unexpected panic-like substring `{forbidden}` in logs: {logs}"
        );
    }
}

#[test]
fn enriched_event_has_none_when_proc_unavailable() {
    let fixture = MissingProcFixture::new();
    let reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
    let mut enricher = EventEnricher::new(reader);

    let enriched_event = enricher.enrich_event(sample_event(12_345, 1));

    assert_eq!(
        enriched_event,
        EnrichedEvent {
            event: sample_event(12_345, 1),
            process_name: None,
            binary_path: None,
            cgroup: None,
            uid: None,
            ancestry_chain: Vec::new(),
            ancestry_truncated: false,
            repeat_count: 1,
        }
    );
}

#[test]
fn n_transient_pids_emit_n_warnings_total() {
    let fixture = MissingProcFixture::new();
    let reader = ProcReader::with_root(fixture.root()).expect("fixture reader builds");
    let mut enricher = EventEnricher::new(reader);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(TestWriterFactory::new(&buffer))
        .finish();

    with_default(subscriber, || {
        for pid in 20_000_u32..20_005 {
            let _ = enricher.enrich_event(sample_event(pid, u64::from(pid)));
        }
    });

    let logs = captured_logs(&buffer);
    let warning_count = logs
        .lines()
        .filter(|line| {
            line.contains("enrichment_partial") && contains_reason_proc_unavailable(line)
        })
        .count();
    assert_eq!(
        warning_count, 5,
        "expected exactly one partial warning per transient pid: {logs}"
    );
}

#[test]
fn successful_enrichment_emits_no_partial_warnings() {
    let reader = ProcReader::new().expect("host /proc reader builds");
    let mut enricher = EventEnricher::new(reader);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(TestWriterFactory::new(&buffer))
        .finish();

    let pid = std::process::id();
    let enriched_event = with_default(subscriber, || enricher.enrich_event(sample_event(pid, 7)));
    let logs = captured_logs(&buffer);
    let pid_marker = format!("pid={pid}");

    assert!(
        !logs.contains("process exited before enrichment"),
        "successful leaf enrichment should not emit the transient proc-unavailable warning: {logs}"
    );
    assert!(
        !logs
            .lines()
            .any(|line| line.contains(&pid_marker) && contains_reason_proc_unavailable(line)),
        "successful leaf enrichment should not log a proc-unavailable warning for pid {pid}: {logs}"
    );
    assert!(enriched_event.process_name.is_some());
    assert!(enriched_event.binary_path.is_some());
    assert!(enriched_event.cgroup.is_some());
    assert!(enriched_event.uid.is_some());
}

const fn sample_event(pid: u32, event_id: u64) -> SyscallEvent {
    SyscallEvent {
        event_id,
        timestamp: 1_000 + event_id,
        pid,
        tid: pid,
        ppid: 1,
        syscall_type: SyscallType::Execve,
        filename: None,
        ip_address: None,
        port: None,
        child_pid: None,
        open_flags: None,
        syscall_result: Some(0),
    }
}

fn contains_reason_proc_unavailable(line: &str) -> bool {
    line.contains("reason=proc_unavailable") || line.contains("reason=\"proc_unavailable\"")
}

fn captured_logs(buffer: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8(buffer.lock().expect("buffer lock").clone()).expect("captured logs are utf-8")
}

#[derive(Clone)]
struct TestWriterFactory {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl TestWriterFactory {
    fn new(buffer: &Arc<Mutex<Vec<u8>>>) -> Self {
        Self {
            buffer: Arc::clone(buffer),
        }
    }
}

impl<'a> MakeWriter<'a> for TestWriterFactory {
    type Writer = TestWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TestWriter {
            buffer: Arc::clone(&self.buffer),
        }
    }
}

struct TestWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl io::Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer
            .lock()
            .expect("log capture buffer lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct MissingProcFixture {
    tempdir: TempDir,
}

impl MissingProcFixture {
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
        let mounts_path = self.root().join("mounts");
        fs::write(
            mounts_path,
            "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n",
        )
        .expect("mounts fixture is written");
    }
}
