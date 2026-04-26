//! Fuzzing helpers for Mini-EDR sensor robustness work.
//!
//! TC-74/VAL-SENSOR-018 require more than a bare `cargo-fuzz` target: the
//! mission also needs evidence showing how long the target actually ran and how
//! many inputs libFuzzer executed. This module keeps that bookkeeping close to
//! the `RingBufferConsumer::deserialize_record` surface so the fuzz target can
//! stay tiny while still emitting a machine-readable `fuzz/run_summary.json`.

use serde::{Deserialize, Serialize};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    sync::{
        Once, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

static RINGBUFFER_DESERIALIZE_RECORDER: OnceLock<FuzzRunRecorder> = OnceLock::new();
static RINGBUFFER_DESERIALIZE_ATEXIT: Once = Once::new();

/// Return the global recorder used by the ring-buffer deserializer fuzz target.
///
/// The first call lazily chooses the summary path, and then registers a process
/// exit hook so even direct `cargo +nightly fuzz run ...` invocations emit the
/// summary file without needing a wrapper script.
#[must_use]
pub fn ringbuffer_deserialize_recorder() -> &'static FuzzRunRecorder {
    let recorder = RINGBUFFER_DESERIALIZE_RECORDER.get_or_init(|| {
        let summary_path = env::var_os("MINI_EDR_FUZZ_SUMMARY_PATH")
            .map_or_else(default_ringbuffer_summary_path, PathBuf::from);
        FuzzRunRecorder::new(summary_path)
    });

    RINGBUFFER_DESERIALIZE_ATEXIT.call_once(|| {
        // SAFETY: registering an `extern "C"` callback with `atexit` is the
        // supported FFI contract. The callback only reads atomics and attempts a
        // best-effort file write, so it does not depend on any borrowed state.
        unsafe {
            let _ = libc::atexit(write_ringbuffer_deserialize_summary);
        }
    });

    recorder
}

fn default_ringbuffer_summary_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fuzz")
        .join("run_summary.json")
}

fn ringbuffer_corpus_path() -> PathBuf {
    env::var_os("MINI_EDR_FUZZ_CORPUS_PATH").map_or_else(
        || {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("fuzz")
                .join("corpus")
                .join("ringbuffer_deserialize")
        },
        PathBuf::from,
    )
}

extern "C" fn write_ringbuffer_deserialize_summary() {
    if let Some(recorder) = RINGBUFFER_DESERIALIZE_RECORDER.get() {
        let _ = recorder.write_summary(0, Some(count_corpus_entries(&ringbuffer_corpus_path())));
    }
}

/// Process-wide recorder for one fuzz target's runtime evidence.
///
/// The recorder intentionally stores only atomics plus the destination path.
/// That keeps the per-input fuzz hot path trivial: increment an iteration
/// counter, lazily stamp the first-seen wall clock, and return immediately to
/// the deserializer under test.
#[derive(Debug)]
pub struct FuzzRunRecorder {
    summary_path: PathBuf,
    start_ts_millis: AtomicU64,
    iterations: AtomicU64,
}

impl FuzzRunRecorder {
    /// Create a recorder that writes its JSON summary to `summary_path`.
    #[must_use]
    pub fn new(summary_path: impl Into<PathBuf>) -> Self {
        Self {
            summary_path: summary_path.into(),
            start_ts_millis: AtomicU64::new(0),
            iterations: AtomicU64::new(0),
        }
    }

    /// Record one libFuzzer iteration and return a monotonic iteration number.
    ///
    /// The returned number doubles as a deterministic `event_id` when the fuzz
    /// target feeds bytes into `RingBufferConsumer::deserialize_record`.
    #[must_use]
    pub fn record_iteration(&self) -> u64 {
        let now = unix_timestamp_millis();
        let _ = self
            .start_ts_millis
            .compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed);

        self.iterations.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Persist the current summary to disk.
    ///
    /// # Errors
    ///
    /// Returns any filesystem or JSON serialization error encountered while
    /// creating parent directories or writing the summary file.
    pub fn write_summary(
        &self,
        crashes: u64,
        unique_paths: Option<u64>,
    ) -> io::Result<FuzzRunSummary> {
        self.write_summary_at(unix_timestamp_millis(), crashes, unique_paths)
    }

    fn write_summary_at(
        &self,
        end_ts_millis: u64,
        crashes: u64,
        unique_paths: Option<u64>,
    ) -> io::Result<FuzzRunSummary> {
        let summary = self.summary_at(end_ts_millis, crashes, unique_paths);
        if let Some(parent) = self.summary_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let bytes = serde_json::to_vec_pretty(&summary)
            .map_err(|error| io::Error::other(format!("serialize fuzz summary: {error}")))?;
        fs::write(&self.summary_path, bytes)?;
        Ok(summary)
    }

    fn summary_at(
        &self,
        end_ts_millis: u64,
        crashes: u64,
        unique_paths: Option<u64>,
    ) -> FuzzRunSummary {
        let start_ts = match self.start_ts_millis.load(Ordering::Relaxed) {
            0 => end_ts_millis,
            start_ts => start_ts,
        };
        let iterations = self.iterations.load(Ordering::Relaxed);

        // The contract asks for the *observed* duration, not a hard-coded
        // expectation, so the summary derives seconds directly from the two
        // wall-clock timestamps written into the same JSON payload.
        let duration_secs =
            Duration::from_millis(end_ts_millis.saturating_sub(start_ts)).as_secs_f64();

        FuzzRunSummary {
            start_ts,
            end_ts: end_ts_millis,
            duration_secs,
            actual_duration_seconds: duration_secs,
            iterations,
            total_iterations: iterations,
            crashes,
            crash_count: crashes,
            unique_paths,
        }
    }
}

/// Machine-readable evidence emitted after a fuzz run.
///
/// The alias fields intentionally satisfy both the worker feature wording
/// (`duration_secs`, `iterations`, `crashes`) and the broader mission contract
/// (`actual_duration_seconds`, `total_iterations`, `crash_count`) without
/// forcing downstream tooling to special-case one naming convention.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FuzzRunSummary {
    /// Unix epoch timestamp in milliseconds for the first recorded iteration.
    pub start_ts: u64,
    /// Unix epoch timestamp in milliseconds when the run summary was written.
    pub end_ts: u64,
    /// Observed wall-clock runtime in seconds.
    pub duration_secs: f64,
    /// Alias used by the validation contract for the same duration value.
    pub actual_duration_seconds: f64,
    /// Number of inputs executed by libFuzzer.
    pub iterations: u64,
    /// Alias used by the validation contract for the same iteration count.
    pub total_iterations: u64,
    /// Number of crashing inputs observed during the run.
    pub crashes: u64,
    /// Alias used by the validation contract for the same crash count.
    pub crash_count: u64,
    /// Optional unique-path metric when a wrapper parses it from libFuzzer.
    pub unique_paths: Option<u64>,
}

fn unix_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn count_corpus_entries(path: &Path) -> u64 {
    fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.path().is_file())
                .count() as u64
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{FuzzRunRecorder, FuzzRunSummary, count_corpus_entries};
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::Ordering,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn fuzz_run_recorder_counts_iterations_and_latches_first_timestamp() {
        let recorder = FuzzRunRecorder::new(temp_summary_path("iteration-counts"));

        let first_iteration = recorder.record_iteration();
        let first_start = recorder.start_ts_millis.load(Ordering::Relaxed);
        let second_iteration = recorder.record_iteration();
        let second_start = recorder.start_ts_millis.load(Ordering::Relaxed);

        assert_eq!(first_iteration, 1);
        assert_eq!(second_iteration, 2);
        assert!(first_start > 0);
        assert_eq!(first_start, second_start);
    }

    #[test]
    fn fuzz_run_recorder_writes_summary_with_requested_and_contract_alias_fields() {
        let summary_path = temp_summary_path("summary-shape");
        let recorder = FuzzRunRecorder::new(&summary_path);
        recorder.start_ts_millis.store(1_000, Ordering::Relaxed);
        recorder.iterations.store(42, Ordering::Relaxed);

        let written = recorder
            .write_summary_at(61_250, 0, Some(17))
            .expect("summary writes to disk");

        assert_eq!(
            written,
            FuzzRunSummary {
                start_ts: 1_000,
                end_ts: 61_250,
                duration_secs: 60.25,
                actual_duration_seconds: 60.25,
                iterations: 42,
                total_iterations: 42,
                crashes: 0,
                crash_count: 0,
                unique_paths: Some(17),
            }
        );

        let reparsed: FuzzRunSummary =
            serde_json::from_slice(&fs::read(&summary_path).expect("summary file can be re-read"))
                .expect("summary json is valid");
        assert_eq!(reparsed, written);

        cleanup_temp_summary_path(&summary_path);
    }

    #[test]
    fn count_corpus_entries_only_counts_regular_files() {
        let corpus_dir = temp_summary_path("corpus-count")
            .parent()
            .expect("temp summary has parent")
            .join("corpus");
        fs::create_dir_all(corpus_dir.join("nested")).expect("corpus temp dir is created");
        fs::write(corpus_dir.join("seed-a"), b"a").expect("seed-a written");
        fs::write(corpus_dir.join("seed-b"), b"b").expect("seed-b written");

        assert_eq!(count_corpus_entries(&corpus_dir), 2);

        let _ = fs::remove_dir_all(
            corpus_dir
                .parent()
                .expect("corpus dir lives inside disposable temp dir"),
        );
    }

    fn temp_summary_path(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir()
            .join(format!("mini-edr-fuzz-{label}-{suffix}"))
            .join("run_summary.json")
    }

    fn cleanup_temp_summary_path(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
}
