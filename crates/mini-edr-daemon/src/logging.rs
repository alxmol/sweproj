//! Append-only alert, inference, and operational log sinks.
//!
//! The daemon writes three runtime artifacts under the configured log
//! directory:
//! 1. `alerts.jsonl` for durable `Alert` records,
//! 2. `events.jsonl` for structured debug inference entries, and
//! 3. `daemon.log` for operator-facing operational events.
//!
//! The sinks all keep their file descriptors open with `O_APPEND` so each
//! record is appended atomically relative to concurrent writers in the same
//! process. We flush each line after writing so clean `SIGTERM` shutdowns leave
//! the append-only artifacts on disk without requiring an expensive `fsync()`
//! per alert. When the alert target becomes unsafe (for example it is replaced
//! by a symlink before a reopen), the alert sink buffers serialized records in
//! memory until a later safe reopen succeeds.

use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use libc::{ELOOP, O_CLOEXEC, O_NOFOLLOW};
use mini_edr_common::{Alert, EnrichedEvent};
use mini_edr_detection::{
    AlertGenerationError, AlertGenerator, InferenceLogEntry, InferenceResult,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

use crate::DaemonError;

const EVENT_LOG_FILE_NAME: &str = "events.jsonl";
const OPERATIONAL_LOG_FILE_NAME: &str = "daemon.log";

const ALERT_LOG_MODE: u32 = 0o600;
const EVENT_LOG_MODE: u32 = 0o600;
const OPERATIONAL_LOG_MODE: u32 = 0o640;
const DEFAULT_LOG_TAMPER_CHECK_EVERY: u64 = 1_024;
const LOG_TAMPER_HEAD_WINDOW_BYTES: usize = 4_096;

/// Structured details about a detected daemon-log integrity violation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TamperReport {
    /// File path whose tracked bytes diverged from the daemon's in-memory view.
    pub path: String,
    /// Offset of the first byte that no longer matches the expected contents.
    pub offset: u64,
    /// UTC wall-clock timestamp recorded when the mismatch was observed.
    pub detected_at_timestamp_ns: u64,
    /// Number of bytes the daemon expected to have written so far.
    pub expected_len: u64,
    /// Current on-disk byte length observed at verification time.
    pub observed_len: u64,
    /// Optional read/open failure details when the verification itself failed.
    pub details: Option<String>,
}

impl TamperReport {
    fn mismatch(path: &Path, offset: u64, expected_len: usize, observed_len: u64) -> Self {
        Self {
            path: path.display().to_string(),
            offset,
            detected_at_timestamp_ns: crate::now_ns(),
            expected_len: expected_len as u64,
            observed_len,
            details: None,
        }
    }

    fn io_failure(path: &Path, details: String, expected_len: usize) -> Self {
        Self {
            path: path.display().to_string(),
            offset: 0,
            detected_at_timestamp_ns: crate::now_ns(),
            expected_len: expected_len as u64,
            observed_len: 0,
            details: Some(details),
        }
    }
}

struct IntegrityTracker {
    expected_bytes: Vec<u8>,
    expected_hasher: Sha256,
    full_verify_every: u64,
    writes_since_full_verification: u64,
    last_tamper_report: Option<TamperReport>,
}

impl IntegrityTracker {
    fn new(path: &Path, full_verify_every: u64) -> Result<Self, OpenError> {
        let existing_bytes = read_log_bytes(path)?;
        let mut expected_hasher = Sha256::new();
        expected_hasher.update(&existing_bytes);
        Ok(Self {
            expected_bytes: existing_bytes,
            expected_hasher,
            full_verify_every: full_verify_every.max(1),
            writes_since_full_verification: 0,
            last_tamper_report: None,
        })
    }

    fn append_line(&mut self, line: &str) {
        self.expected_bytes.extend_from_slice(line.as_bytes());
        self.expected_bytes.push(b'\n');
        self.expected_hasher.update(line.as_bytes());
        self.expected_hasher.update(b"\n");
        self.writes_since_full_verification += 1;
    }

    const fn expected_len(&self) -> usize {
        self.expected_bytes.len()
    }

    fn expected_digest(&self) -> [u8; 32] {
        self.expected_hasher.clone().finalize().into()
    }

    fn head_window_len(&self) -> usize {
        self.expected_len().min(LOG_TAMPER_HEAD_WINDOW_BYTES)
    }

    const fn needs_full_verification(&self) -> bool {
        self.writes_since_full_verification >= self.full_verify_every
    }

    const fn reset_full_verification_counter(&mut self) {
        self.writes_since_full_verification = 0;
    }

    fn last_tamper_report(&self) -> Option<TamperReport> {
        self.last_tamper_report.clone()
    }
}

#[derive(Serialize)]
struct OperationalLogEntry {
    timestamp_ns: u64,
    level: &'static str,
    event: &'static str,
    message: String,
    path: Option<String>,
    buffered_records: Option<usize>,
    details: Option<String>,
}

enum OpenError {
    UnsafeTarget,
    Io(String),
}

enum ReopenResult {
    Reopened {
        flushed_records: usize,
    },
    UnsafeTarget {
        buffered_records: usize,
    },
    Failed {
        buffered_records: usize,
        details: String,
    },
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "The parent daemon module owns the runtime and intentionally imports this child-module type directly."
)]
/// Mutable runtime log state held behind the daemon's logging mutex.
pub(super) struct LoggingRuntime {
    alert_generator: AlertGenerator,
    alert_receiver: broadcast::Receiver<Alert>,
    inference_log_receiver: broadcast::Receiver<InferenceLogEntry>,
    alert_log: BufferedLineLog,
    inference_log: BufferedLineLog,
    operational_log: BufferedLineLog,
}

impl LoggingRuntime {
    /// Build the daemon log sinks from the validated alert-log path.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] when the operational or inference logs cannot be
    /// opened, or when the alert generator cannot initialize its persisted
    /// alert-ID sequence file.
    pub(crate) fn new(
        alert_threshold: f64,
        alert_log_path: &Path,
        alert_id_state_path: &Path,
    ) -> Result<Self, DaemonError> {
        let log_directory = alert_log_path
            .parent()
            .ok_or_else(|| DaemonError::LogOpen {
                path: alert_log_path.to_path_buf(),
                details: "alert log path must have a parent directory".to_owned(),
            })?;
        let event_log_path = log_directory.join(EVENT_LOG_FILE_NAME);
        let operational_log_path = log_directory.join(OPERATIONAL_LOG_FILE_NAME);

        let (alert_sender, alert_receiver) = broadcast::channel(256);
        let (inference_log_sender, inference_log_receiver) = broadcast::channel(256);
        let alert_generator = AlertGenerator::new(
            alert_threshold,
            alert_sender,
            inference_log_sender,
            alert_id_state_path.to_path_buf(),
        )
        .map_err(DaemonError::AlertGeneration)?;

        let operational_log = BufferedLineLog::open_operational(
            operational_log_path,
            OPERATIONAL_LOG_MODE,
            operational_log_tamper_check_every(),
        )?;
        let inference_log = BufferedLineLog::open_strict(event_log_path, EVENT_LOG_MODE)?;
        let (alert_log, alert_target_unsafe) =
            BufferedLineLog::open_with_buffering(alert_log_path.to_path_buf(), ALERT_LOG_MODE)?;

        let mut runtime = Self {
            alert_generator,
            alert_receiver,
            inference_log_receiver,
            alert_log,
            inference_log,
            operational_log,
        };
        runtime.record_operational_event(
            "INFO",
            "daemon_started",
            "mini-edr daemon initialized append-only runtime logs",
            Some(log_directory),
            None,
            None,
        )?;
        if alert_target_unsafe {
            runtime.record_operational_event(
                "ERROR",
                "log_target_unsafe",
                "refused to open the alert log because the configured path is a symlink; future alerts stay buffered in memory until a safe reopen succeeds",
                Some(alert_log_path),
                Some(runtime.alert_log.buffered_len()),
                None,
            )?;
        }
        Ok(runtime)
    }

    /// Publish one inference result and persist any emitted records to disk.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] when alert generation fails or a log sink cannot
    /// serialize and flush the resulting line-oriented records.
    pub(crate) fn publish_prediction(
        &mut self,
        enriched_event: &EnrichedEvent,
        inference_result: &InferenceResult,
    ) -> Result<Option<Alert>, DaemonError> {
        let alert = match self
            .alert_generator
            .publish(enriched_event, inference_result)
        {
            Ok(alert) => alert,
            Err(error) => {
                // FR-D06 still requires one inference-log entry per scored
                // vector, even when alert emission is blocked by a durability
                // failure in `alert_id.seq`. We therefore flush the structured
                // inference record before surfacing the alert-generation error
                // to the daemon's caller.
                self.drain_inference_logs()?;
                self.record_alert_generation_failure(&error)?;
                return Err(DaemonError::AlertGeneration(error));
            }
        };
        self.drain_inference_logs()?;
        self.drain_alert_logs()?;
        Ok(alert)
    }

    /// Create a fresh broadcast subscription for the live alert stream.
    pub(crate) fn subscribe_alerts(&self) -> broadcast::Receiver<Alert> {
        self.alert_receiver.resubscribe()
    }

    /// Apply a reloaded threshold to subsequent alert-generation decisions.
    pub(crate) fn set_alert_threshold(&mut self, threshold: f64) -> Result<(), DaemonError> {
        self.alert_generator
            .set_threshold(threshold)
            .map_err(DaemonError::AlertGeneration)
    }

    /// Reopen the alert log target after a `SIGUSR1`-style rotation request.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] when a previously safe target can no longer be
    /// flushed or when the operational log cannot record the reopen result.
    pub(crate) fn reopen_alert_log(&mut self) -> Result<(), DaemonError> {
        let alert_log_path = self.alert_log.path().to_path_buf();
        match self.alert_log.reopen() {
            ReopenResult::Reopened { flushed_records } => {
                self.record_operational_event(
                    "INFO",
                    "log_reopened",
                    "reopened the append-only alert log target",
                    Some(&alert_log_path),
                    Some(flushed_records),
                    None,
                )?;
            }
            ReopenResult::UnsafeTarget { buffered_records } => {
                self.record_operational_event(
                    "ERROR",
                    "log_target_unsafe",
                    "refused to reopen the alert log because the configured path is a symlink; buffered alerts remain in memory",
                    Some(&alert_log_path),
                    Some(buffered_records),
                    None,
                )?;
            }
            ReopenResult::Failed {
                buffered_records,
                details,
            } => {
                self.record_operational_event(
                    "ERROR",
                    "log_rotate_failed",
                    "failed to reopen the alert log after closing the previous file descriptor; future alerts stay buffered in memory until a later reopen succeeds",
                    Some(&alert_log_path),
                    Some(buffered_records),
                    Some(details),
                )?;
            }
        }
        Ok(())
    }

    /// Persist a daemon lifecycle or reload event to the operational log.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] when the append-only daemon log cannot flush the
    /// structured line to disk.
    pub(crate) fn record_operational_event(
        &mut self,
        level: &'static str,
        event: &'static str,
        message: &str,
        path: Option<&Path>,
        buffered_records: Option<usize>,
        details: Option<String>,
    ) -> Result<(), DaemonError> {
        self.operational_log.write_json(&OperationalLogEntry {
            timestamp_ns: crate::now_ns(),
            level,
            event,
            message: message.to_owned(),
            path: path.map(|value| value.display().to_string()),
            buffered_records,
            details,
        })
    }

    /// Return the most recent daemon-log tamper report, if one has been observed.
    pub(crate) fn operational_log_tamper_report(&self) -> Option<TamperReport> {
        self.operational_log.tamper_report()
    }

    /// Force an immediate daemon-log integrity verification for regression tests.
    pub(crate) fn verify_operational_log_integrity(&mut self) -> Result<(), TamperReport> {
        match self.operational_log.verify_log_integrity() {
            Ok(()) => Ok(()),
            Err(report) => {
                self.operational_log.note_tamper(&report);
                Err(report)
            }
        }
    }

    fn drain_inference_logs(&mut self) -> Result<(), DaemonError> {
        while let Ok(entry) = self.inference_log_receiver.try_recv() {
            self.inference_log.write_json(&entry)?;
        }
        Ok(())
    }

    fn drain_alert_logs(&mut self) -> Result<(), DaemonError> {
        while let Ok(alert) = self.alert_receiver.try_recv() {
            self.alert_log.write_json(&alert)?;
        }
        Ok(())
    }

    fn record_alert_generation_failure(
        &mut self,
        error: &AlertGenerationError,
    ) -> Result<(), DaemonError> {
        match error {
            AlertGenerationError::AlertIdStateWriteFailed { path, details } => {
                self.record_operational_event(
                    "ERROR",
                    "alert_id_persistence_failed",
                    "failed to persist alert_id.seq; refusing to emit alerts until persistence is restored",
                    Some(path),
                    None,
                    Some(details.clone()),
                )
            }
            _ => self.record_operational_event(
                "ERROR",
                "alert_generation_failed",
                "alert generation failed before an alert could be emitted",
                None,
                None,
                Some(error.to_string()),
            ),
        }
    }
}

struct BufferedLineLog {
    path: PathBuf,
    mode: u32,
    file: Option<File>,
    buffered_lines: Vec<String>,
    integrity: Option<IntegrityTracker>,
}

impl BufferedLineLog {
    fn open_strict(path: PathBuf, mode: u32) -> Result<Self, DaemonError> {
        let file = open_append_only_file(&path, mode).map_err(|error| DaemonError::LogOpen {
            path: path.clone(),
            details: open_error_details(error),
        })?;
        Ok(Self {
            path,
            mode,
            file: Some(file),
            buffered_lines: Vec::new(),
            integrity: None,
        })
    }

    fn open_operational(
        path: PathBuf,
        mode: u32,
        full_verify_every: u64,
    ) -> Result<Self, DaemonError> {
        let file = open_append_only_file(&path, mode).map_err(|error| DaemonError::LogOpen {
            path: path.clone(),
            details: open_error_details(error),
        })?;
        let integrity = IntegrityTracker::new(&path, full_verify_every).map_err(|error| {
            DaemonError::LogOpen {
                path: path.clone(),
                details: open_error_details(error),
            }
        })?;
        Ok(Self {
            path,
            mode,
            file: Some(file),
            buffered_lines: Vec::new(),
            integrity: Some(integrity),
        })
    }

    fn open_with_buffering(path: PathBuf, mode: u32) -> Result<(Self, bool), DaemonError> {
        match open_append_only_file(&path, mode) {
            Ok(file) => Ok((
                Self {
                    path,
                    mode,
                    file: Some(file),
                    buffered_lines: Vec::new(),
                    integrity: None,
                },
                false,
            )),
            Err(OpenError::UnsafeTarget) => Ok((
                Self {
                    path,
                    mode,
                    file: None,
                    buffered_lines: Vec::new(),
                    integrity: None,
                },
                true,
            )),
            Err(error) => Err(DaemonError::LogOpen {
                path: path.clone(),
                details: open_error_details(error),
            }),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    const fn buffered_len(&self) -> usize {
        self.buffered_lines.len()
    }

    fn tamper_report(&self) -> Option<TamperReport> {
        self.integrity
            .as_ref()
            .and_then(IntegrityTracker::last_tamper_report)
    }

    fn reopen(&mut self) -> ReopenResult {
        // FR-A03 models a classic `logrotate` handoff: close the current file
        // descriptor first, then try to reopen the configured path. Closing the
        // old descriptor before the new open guarantees a renamed `.1` file
        // stops receiving writes immediately, even if the reopen attempt fails.
        self.file = None;
        match open_append_only_file(&self.path, self.mode) {
            Ok(file) => {
                self.file = Some(file);
                match self.flush_buffered_lines() {
                    Ok(flushed_records) => ReopenResult::Reopened { flushed_records },
                    Err(error) => ReopenResult::Failed {
                        buffered_records: self.buffered_lines.len(),
                        details: error.to_string(),
                    },
                }
            }
            Err(OpenError::UnsafeTarget) => ReopenResult::UnsafeTarget {
                buffered_records: self.buffered_lines.len(),
            },
            Err(error) => ReopenResult::Failed {
                buffered_records: self.buffered_lines.len(),
                details: open_error_details(error),
            },
        }
    }

    fn write_json<T: Serialize>(&mut self, value: &T) -> Result<(), DaemonError> {
        let serialized = serde_json::to_string(value).map_err(|error| DaemonError::LogWrite {
            path: self.path.clone(),
            details: error.to_string(),
        })?;
        self.write_line(&serialized)
    }

    fn write_line(&mut self, line: &str) -> Result<(), DaemonError> {
        if self.file.is_none() {
            self.buffered_lines.push(line.to_owned());
            return Ok(());
        }

        self.write_line_to_file(line)
            .map_err(|details| DaemonError::LogWrite {
                path: self.path.clone(),
                details,
            })?;
        self.record_expected_line(line);
        self.maybe_verify_integrity_after_write();
        Ok(())
    }

    fn flush_buffered_lines(&mut self) -> Result<usize, DaemonError> {
        let pending = std::mem::take(&mut self.buffered_lines);
        let flushed_records = pending.len();
        let mut pending = pending.into_iter();
        while let Some(line) = pending.next() {
            if let Err(details) = self.write_line_to_file(&line) {
                let mut restored_lines = vec![line];
                restored_lines.extend(pending);
                self.buffered_lines = restored_lines;
                return Err(DaemonError::LogWrite {
                    path: self.path.clone(),
                    details,
                });
            }
        }
        Ok(flushed_records)
    }

    fn write_line_to_file(&mut self, line: &str) -> Result<(), String> {
        // The newline is appended by the sink rather than the serialized value
        // itself so every durable record occupies exactly one physical line even
        // when callers hand us already-JSON-encoded strings.
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| "log file is temporarily unavailable".to_owned())?;
        file.write_all(line.as_bytes())
            .map_err(|error| error.to_string())?;
        file.write_all(b"\n").map_err(|error| error.to_string())?;
        file.flush().map_err(|error| error.to_string())
    }

    /// Verify the tracked on-disk bytes against the daemon's in-memory digest.
    pub fn verify_log_integrity(&self) -> Result<(), TamperReport> {
        let Some(integrity) = self.integrity.as_ref() else {
            return Ok(());
        };
        let observed = read_log_prefix(&self.path, integrity.expected_len()).map_err(|error| {
            TamperReport::io_failure(
                &self.path,
                open_error_details(error),
                integrity.expected_len(),
            )
        })?;
        if observed.file_len != integrity.expected_len() as u64 {
            return Err(TamperReport::mismatch(
                &self.path,
                observed.file_len.min(integrity.expected_len() as u64),
                integrity.expected_len(),
                observed.file_len,
            ));
        }

        let observed_digest = sha256_bytes(&observed.bytes);
        if observed_digest == integrity.expected_digest() {
            return Ok(());
        }

        Err(TamperReport::mismatch(
            &self.path,
            first_mismatch_offset(&integrity.expected_bytes, &observed.bytes),
            integrity.expected_len(),
            observed.file_len,
        ))
    }

    fn record_expected_line(&mut self, line: &str) {
        if let Some(integrity) = self.integrity.as_mut() {
            integrity.append_line(line);
        }
    }

    fn maybe_verify_integrity_after_write(&mut self) {
        let Some(head_window_len) = self
            .integrity
            .as_ref()
            .map(IntegrityTracker::head_window_len)
        else {
            return;
        };
        if head_window_len > 0
            && let Err(report) = self.verify_head_window(head_window_len)
        {
            self.note_tamper(&report);
            return;
        }

        let needs_full_verification = self
            .integrity
            .as_ref()
            .is_some_and(IntegrityTracker::needs_full_verification);
        if needs_full_verification {
            if let Some(integrity) = self.integrity.as_mut() {
                integrity.reset_full_verification_counter();
            }
            if let Err(report) = self.verify_log_integrity() {
                self.note_tamper(&report);
            }
        }
    }

    fn verify_head_window(&self, expected_len: usize) -> Result<(), TamperReport> {
        let Some(integrity) = self.integrity.as_ref() else {
            return Ok(());
        };
        let observed = read_log_prefix(&self.path, expected_len).map_err(|error| {
            TamperReport::io_failure(
                &self.path,
                open_error_details(error),
                integrity.expected_len(),
            )
        })?;
        let expected = &integrity.expected_bytes[..expected_len];
        if observed.bytes == expected {
            return Ok(());
        }

        Err(TamperReport::mismatch(
            &self.path,
            first_mismatch_offset(expected, &observed.bytes),
            integrity.expected_len(),
            observed.file_len,
        ))
    }

    fn note_tamper(&mut self, report: &TamperReport) {
        let Some(integrity) = self.integrity.as_mut() else {
            return;
        };
        let should_emit = integrity.last_tamper_report.as_ref() != Some(report);
        if integrity.last_tamper_report.is_none() {
            integrity.last_tamper_report = Some(report.clone());
        }
        if should_emit {
            tracing::error!(
                daemon_log.tamper_detected = true,
                daemon_log.offset = report.offset,
                daemon_log.timestamp_ns = report.detected_at_timestamp_ns,
                daemon_log.expected_len = report.expected_len,
                daemon_log.observed_len = report.observed_len,
                daemon_log.path = %report.path,
                daemon_log.details = report.details.as_deref().unwrap_or(""),
                "detected tampering in daemon.log"
            );
        }
    }
}

struct ObservedPrefix {
    bytes: Vec<u8>,
    file_len: u64,
}

fn operational_log_tamper_check_every() -> u64 {
    env::var("MINI_EDR_LOG_TAMPER_CHECK_EVERY")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_LOG_TAMPER_CHECK_EVERY)
}

fn read_log_bytes(path: &Path) -> Result<Vec<u8>, OpenError> {
    let mut file = open_read_only_file(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| OpenError::Io(error.to_string()))?;
    Ok(bytes)
}

fn read_log_prefix(path: &Path, prefix_len: usize) -> Result<ObservedPrefix, OpenError> {
    let mut file = open_read_only_file(path)?;
    let file_len = file
        .metadata()
        .map_err(|error| OpenError::Io(error.to_string()))?
        .len();
    let to_read = prefix_len.min(usize::try_from(file_len).unwrap_or(usize::MAX));
    let mut bytes = vec![0_u8; to_read];
    file.read_exact(&mut bytes)
        .map_err(|error| OpenError::Io(error.to_string()))?;
    Ok(ObservedPrefix { bytes, file_len })
}

fn open_read_only_file(path: &Path) -> Result<File, OpenError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(ELOOP) => OpenError::UnsafeTarget,
            _ => OpenError::Io(error.to_string()),
        })
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn first_mismatch_offset(expected: &[u8], observed: &[u8]) -> u64 {
    let comparable_len = expected.len().min(observed.len());
    for index in 0..comparable_len {
        if expected[index] != observed[index] {
            return index as u64;
        }
    }
    comparable_len as u64
}

fn open_append_only_file(path: &Path, mode: u32) -> Result<File, OpenError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| OpenError::Io(error.to_string()))?;
    }

    // `append(true)` requests `O_APPEND`, while `O_NOFOLLOW` closes the final
    // TOCTOU hole that a pre-open `symlink_metadata` check would leave. We also
    // keep `O_CLOEXEC` so future helper processes do not inherit the daemon's
    // append-only descriptors accidentally.
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .mode(mode)
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(ELOOP) => OpenError::UnsafeTarget,
            _ => OpenError::Io(error.to_string()),
        })?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| OpenError::Io(error.to_string()))?;
    Ok(file)
}

fn open_error_details(error: OpenError) -> String {
    match error {
        OpenError::UnsafeTarget => {
            "the configured path is a symlink and violates the O_NOFOLLOW safety policy".to_owned()
        }
        OpenError::Io(details) => details,
    }
}
