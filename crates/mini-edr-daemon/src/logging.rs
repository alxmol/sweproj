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
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use libc::{ELOOP, O_CLOEXEC, O_NOFOLLOW};
use mini_edr_common::{Alert, EnrichedEvent};
use mini_edr_detection::{
    AlertGenerationError, AlertGenerator, InferenceLogEntry, InferenceResult,
};
use serde::Serialize;
use tokio::sync::broadcast;

use crate::DaemonError;

const EVENT_LOG_FILE_NAME: &str = "events.jsonl";
const OPERATIONAL_LOG_FILE_NAME: &str = "daemon.log";
const ALERT_ID_SEQUENCE_FILE_NAME: &str = "alert_id.seq";

const ALERT_LOG_MODE: u32 = 0o600;
const EVENT_LOG_MODE: u32 = 0o600;
const OPERATIONAL_LOG_MODE: u32 = 0o640;

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
    pub(crate) fn new(alert_threshold: f64, alert_log_path: &Path) -> Result<Self, DaemonError> {
        let log_directory = alert_log_path
            .parent()
            .ok_or_else(|| DaemonError::LogOpen {
                path: alert_log_path.to_path_buf(),
                details: "alert log path must have a parent directory".to_owned(),
            })?;
        let event_log_path = log_directory.join(EVENT_LOG_FILE_NAME);
        let operational_log_path = log_directory.join(OPERATIONAL_LOG_FILE_NAME);
        let alert_id_state_path = log_directory.join(ALERT_ID_SEQUENCE_FILE_NAME);

        let (alert_sender, alert_receiver) = broadcast::channel(256);
        let (inference_log_sender, inference_log_receiver) = broadcast::channel(256);
        let alert_generator = AlertGenerator::new(
            alert_threshold,
            alert_sender,
            inference_log_sender,
            alert_id_state_path,
        )
        .map_err(DaemonError::AlertGeneration)?;

        let operational_log =
            BufferedLineLog::open_strict(operational_log_path, OPERATIONAL_LOG_MODE)?;
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
                },
                false,
            )),
            Err(OpenError::UnsafeTarget) => Ok((
                Self {
                    path,
                    mode,
                    file: None,
                    buffered_lines: Vec::new(),
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
            })
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
