//! Alert generation, threshold gating, and alert-ID persistence.
//!
//! Per SDD §4.1.3 and FR-D03/FR-D04/FR-D06, this module sits immediately
//! downstream of model inference. It applies the `>=` alert-threshold contract,
//! emits one broadcast alert per qualifying score, logs every inference result
//! at debug level, and persists the alert-ID high-water mark to a tiny state
//! file. We choose the sequence-file approach (rather than `UUIDv7`) because the
//! shared `Alert` schema already models `alert_id` as a monotonic `u64`, which
//! makes restart-order assertions straightforward for validators and operators.
//!
//! The persistence file is a hard durability boundary. If Mini-EDR cannot
//! durably advance the `alert_id.seq` high-water mark, it must refuse to emit
//! the alert rather than create an in-memory / on-disk split that would reuse
//! the stale sequence after restart and violate `alert_id` uniqueness.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use chrono::{DateTime, TimeDelta, Utc};
use mini_edr_common::{Alert, EnrichedEvent, FeatureContribution, ProcessInfo};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::{
    error::AlertGenerationError, feature_manifest::feature_manifest, model::InferenceResult,
};

const REDACTED_KERNEL_POINTER: &str = "[redacted-kernel-pointer]";

/// Alert-clock source split into wall-clock and monotonic readings.
///
/// The alerting contract needs both:
/// - a human-readable UTC timestamp for operators and validators, and
/// - an ordering signal that cannot move backwards when NTP or `chronyc`
///   steps the wall clock.
///
/// Keeping the two reads separate lets the generator anchor the display time
/// once with wall clock, then advance future alert timestamps only by
/// monotonic elapsed time.
trait ClockSource: Send + Sync {
    fn wall_clock_now(&self) -> DateTime<Utc>;
    fn monotonic_now(&self) -> Duration;
}

struct SystemClockSource {
    monotonic_origin: Instant,
}

impl SystemClockSource {
    const fn new(monotonic_origin: Instant) -> Self {
        Self { monotonic_origin }
    }
}

impl ClockSource for SystemClockSource {
    fn wall_clock_now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    fn monotonic_now(&self) -> Duration {
        self.monotonic_origin.elapsed()
    }
}

/// Projects a startup wall-clock reading onto the monotonic timeline.
///
/// This deliberately separates display from ordering:
/// - `wall_clock_anchor` gives operators an RFC 3339 UTC timestamp that still
///   looks like normal wall clock time.
/// - `monotonic_anchor` plus future monotonic reads provide the actual ordering
///   source, so backward wall-clock steps never make alerts appear to travel
///   back in time in `alerts.jsonl`.
struct AlertClock {
    source: Arc<dyn ClockSource>,
    wall_clock_anchor: DateTime<Utc>,
    monotonic_anchor: Duration,
}

impl AlertClock {
    fn system() -> Self {
        Self::new(Arc::new(SystemClockSource::new(Instant::now())))
    }

    fn new(source: Arc<dyn ClockSource>) -> Self {
        Self {
            wall_clock_anchor: source.wall_clock_now(),
            monotonic_anchor: source.monotonic_now(),
            source,
        }
    }

    fn display_timestamp(&self) -> DateTime<Utc> {
        let monotonic_now = self.source.monotonic_now();
        let elapsed = monotonic_now
            .checked_sub(self.monotonic_anchor)
            .unwrap_or_default();

        // The monotonic elapsed duration is the ordering truth. We convert it
        // back into a UTC timestamp only at the presentation boundary so the
        // serialized alert keeps a wall-clock shape without inheriting wall
        // clock regressions from NTP corrections.
        let chrono_elapsed =
            TimeDelta::from_std(elapsed).map_or(TimeDelta::MAX, |duration| duration);
        self.wall_clock_anchor + chrono_elapsed
    }
}

/// Gated alert publisher that turns scored process context into `Alert`s.
///
/// The generator owns two operational invariants:
/// 1. `score >= threshold` fires and `score < threshold` suppresses, including
///    the documented 0.0 and 1.0 threshold boundary values.
/// 2. Every qualifying alert gets a strictly increasing `u64` identifier that
///    survives a clean restart because the next high-water mark is persisted
///    before the alert is emitted.
pub struct AlertGenerator {
    threshold: f64,
    alert_sender: broadcast::Sender<Alert>,
    inference_log_sender: broadcast::Sender<InferenceLogEntry>,
    alert_ids: AlertIdSequence,
    clock: AlertClock,
}

/// Structured detection-domain event for FR-D06 / VAL-DETECT-011 consumers.
///
/// The alert generator emits this value on a broadcast channel instead of
/// relying on `tracing`'s debug formatter so downstream JSON-log writers can
/// serialize an actual `top_features` array rather than a Rust `Debug` string.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct InferenceLogEntry {
    /// Stable discriminator used by JSON-log consumers and validators.
    pub event_type: String,
    /// Nanosecond timestamp carried through to the JSON event log.
    pub timestamp_ns: u64,
    /// Process identifier associated with the scored event.
    pub pid: u32,
    /// Bounded inference score normalized into the inclusive `[0.0, 1.0]` range.
    pub score: f64,
    /// The exact five highest-importance features for this inference record.
    pub top_features: Vec<TopFeature>,
}

/// JSON-friendly feature contribution entry embedded in [`InferenceLogEntry`].
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TopFeature {
    /// Human-readable feature name taken from the deployed feature manifest.
    pub name: String,
    /// Finite contribution weight for the named feature.
    pub weight: f64,
}

impl AlertGenerator {
    /// Build a new alert generator around an existing broadcast channel.
    ///
    /// # Errors
    ///
    /// Returns [`AlertGenerationError`] when the threshold is outside the
    /// inclusive `[0.0, 1.0]` contract or the persisted alert-ID state cannot
    /// be read.
    pub fn new(
        threshold: f64,
        alert_sender: broadcast::Sender<Alert>,
        inference_log_sender: broadcast::Sender<InferenceLogEntry>,
        alert_id_state_path: impl Into<PathBuf>,
    ) -> Result<Self, AlertGenerationError> {
        Self::new_with_clock(
            threshold,
            alert_sender,
            inference_log_sender,
            alert_id_state_path,
            AlertClock::system().source,
        )
    }

    fn new_with_clock(
        threshold: f64,
        alert_sender: broadcast::Sender<Alert>,
        inference_log_sender: broadcast::Sender<InferenceLogEntry>,
        alert_id_state_path: impl Into<PathBuf>,
        clock_source: Arc<dyn ClockSource>,
    ) -> Result<Self, AlertGenerationError> {
        validate_threshold(threshold)?;
        Ok(Self {
            threshold,
            alert_sender,
            inference_log_sender,
            alert_ids: AlertIdSequence::load(alert_id_state_path.into())?,
            clock: AlertClock::new(clock_source),
        })
    }

    /// Publish an alert for a scored process when the configured threshold fires.
    ///
    /// Every call emits one debug inference log record, regardless of whether
    /// the score crossed the threshold, because FR-D06 explicitly requires the
    /// offline audit trail to include benign and suppressed results as well.
    /// Qualifying alerts only publish after the next alert ID is durably
    /// persisted; otherwise the call returns a structured error and emits no
    /// alert so restart cannot reuse a stale on-disk sequence.
    ///
    /// # Errors
    ///
    /// Returns [`AlertGenerationError`] when alert-ID persistence fails or the
    /// generator cannot construct a valid alert payload.
    pub fn publish(
        &self,
        enriched_event: &EnrichedEvent,
        inference_result: &InferenceResult,
    ) -> Result<Option<Alert>, AlertGenerationError> {
        let top_features = normalize_top_features(&inference_result.feature_importances);
        let inference_log_entry = InferenceLogEntry {
            event_type: "inference_result".to_owned(),
            timestamp_ns: enriched_event.event.timestamp,
            pid: enriched_event.event.pid,
            score: normalize_score_for_log(inference_result.threat_score),
            top_features: top_features
                .iter()
                .map(|feature| TopFeature {
                    name: feature.feature_name.clone(),
                    weight: normalize_feature_weight(feature.contribution_score),
                })
                .collect(),
        };
        if self.inference_log_sender.send(inference_log_entry).is_err() {
            tracing::debug!(
                event_type = "inference_log_without_receivers",
                pid = enriched_event.event.pid,
                "generated structured inference log entry while no live receivers were subscribed"
            );
        }

        if inference_result.threat_score < self.threshold {
            return Ok(None);
        }

        let alert = self.build_alert(enriched_event, inference_result, top_features)?;
        if self.alert_sender.send(alert.clone()).is_err() {
            tracing::debug!(
                event_type = "alert_broadcast_without_receivers",
                alert_id = alert.alert_id,
                pid = alert.pid,
                "generated alert while no live broadcast receivers were subscribed"
            );
        }
        Ok(Some(alert))
    }

    /// Update the runtime alert threshold used for future publish decisions.
    ///
    /// # Errors
    ///
    /// Returns [`AlertGenerationError`] when the new threshold is outside the
    /// inclusive `[0.0, 1.0]` runtime contract.
    pub fn set_threshold(&mut self, threshold: f64) -> Result<(), AlertGenerationError> {
        validate_threshold(threshold)?;
        self.threshold = threshold;
        Ok(())
    }

    fn build_alert(
        &self,
        enriched_event: &EnrichedEvent,
        inference_result: &InferenceResult,
        top_features: Vec<FeatureContribution>,
    ) -> Result<Alert, AlertGenerationError> {
        let pid = enriched_event.event.pid;
        let process_name = resolve_process_name(enriched_event);
        let binary_path = resolve_binary_path(enriched_event, pid);
        let ancestry_chain =
            normalize_ancestry_chain(enriched_event, pid, &process_name, &binary_path);
        let summary = build_summary(
            &process_name,
            pid,
            inference_result.threat_score,
            self.threshold,
            &top_features,
        );

        Ok(Alert {
            alert_id: self.alert_ids.next_id()?,
            timestamp: self.clock.display_timestamp(),
            pid,
            process_name,
            binary_path,
            ancestry_chain,
            threat_score: inference_result.threat_score,
            model_hash: inference_result.model_hash.clone(),
            top_features,
            summary,
        })
    }
}

struct AlertIdSequence {
    state_path: PathBuf,
    state: Mutex<AlertIdState>,
}

struct AlertIdState {
    last_issued: u64,
}

impl AlertIdSequence {
    fn load(state_path: PathBuf) -> Result<Self, AlertGenerationError> {
        let last_issued = if state_path.exists() {
            let raw = fs::read_to_string(&state_path).map_err(|error| {
                AlertGenerationError::AlertIdStateReadFailed {
                    path: state_path.clone(),
                    details: error.to_string(),
                }
            })?;
            parse_state_file(&state_path, &raw)?
        } else {
            0
        };

        Ok(Self {
            state_path,
            state: Mutex::new(AlertIdState { last_issued }),
        })
    }

    fn next_id(&self) -> Result<u64, AlertGenerationError> {
        let mut state = self
            .state
            .lock()
            .expect("alert-id lock must not be poisoned");
        let next_id = state
            .last_issued
            .checked_add(1)
            .ok_or(AlertGenerationError::AlertIdOverflow)?;

        // We intentionally hold the mutex across the tiny state-file rewrite so
        // concurrent publishers cannot speculatively reserve IDs while the
        // durability boundary is unresolved. If persistence fails, the guarded
        // `last_issued` value stays on the previously durable ID and the caller
        // sees a structured error instead of an emitted alert.
        if let Err(error) = persist_state_file(&self.state_path, next_id) {
            tracing::error!(
                event_type = "alert.persistence_failure",
                path = %self.state_path.display(),
                attempted_alert_id = next_id,
                error = %error,
                "failed to persist the next alert id; refusing to emit an alert"
            );
            return Err(error);
        }
        state.last_issued = next_id;
        drop(state);
        Ok(next_id)
    }
}

fn validate_threshold(threshold: f64) -> Result<(), AlertGenerationError> {
    if threshold.is_finite() && (0.0..=1.0).contains(&threshold) {
        Ok(())
    } else {
        Err(AlertGenerationError::InvalidThreshold { threshold })
    }
}

fn parse_state_file(state_path: &Path, raw: &str) -> Result<u64, AlertGenerationError> {
    raw.trim()
        .parse::<u64>()
        .map_err(|error| AlertGenerationError::AlertIdStateCorrupt {
            path: state_path.to_path_buf(),
            details: error.to_string(),
        })
}

fn persist_state_file(state_path: &Path, next_id: u64) -> Result<(), AlertGenerationError> {
    if let Some(parent) = state_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            AlertGenerationError::AlertIdStateWriteFailed {
                path: state_path.to_path_buf(),
                details: error.to_string(),
            }
        })?;
    }

    let temp_path = state_path.with_extension("seq.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp_path)
        .map_err(|error| AlertGenerationError::AlertIdStateWriteFailed {
            path: temp_path.clone(),
            details: error.to_string(),
        })?;
    file.write_all(format!("{next_id}\n").as_bytes())
        .map_err(|error| AlertGenerationError::AlertIdStateWriteFailed {
            path: temp_path.clone(),
            details: error.to_string(),
        })?;
    file.flush()
        .map_err(|error| AlertGenerationError::AlertIdStateWriteFailed {
            path: temp_path.clone(),
            details: error.to_string(),
        })?;
    fs::rename(&temp_path, state_path).map_err(|error| {
        AlertGenerationError::AlertIdStateWriteFailed {
            path: state_path.to_path_buf(),
            details: error.to_string(),
        }
    })
}

fn resolve_process_name(enriched_event: &EnrichedEvent) -> String {
    sanitize_string(
        enriched_event
            .process_name
            .as_deref()
            .or_else(|| {
                enriched_event
                    .ancestry_chain
                    .last()
                    .map(|process| process.process_name.as_str())
            })
            .unwrap_or("unknown-process"),
    )
}

fn resolve_binary_path(enriched_event: &EnrichedEvent, pid: u32) -> String {
    enriched_event.binary_path.as_deref().map_or_else(
        || {
            enriched_event
                .ancestry_chain
                .last()
                .map(|process| process.binary_path.as_str())
                .map_or_else(
                    || sanitize_string(&format!("/proc/{pid}/exe")),
                    sanitize_string,
                )
        },
        sanitize_string,
    )
}

fn normalize_ancestry_chain(
    enriched_event: &EnrichedEvent,
    pid: u32,
    process_name: &str,
    binary_path: &str,
) -> Vec<ProcessInfo> {
    let mut ancestry_chain = enriched_event
        .ancestry_chain
        .iter()
        .map(|process| ProcessInfo {
            pid: process.pid,
            process_name: sanitize_string(&process.process_name),
            binary_path: sanitize_string(&process.binary_path),
        })
        .collect::<Vec<_>>();

    if ancestry_chain.is_empty() || ancestry_chain.last().map(|process| process.pid) != Some(pid) {
        ancestry_chain.push(ProcessInfo {
            pid,
            process_name: process_name.to_owned(),
            binary_path: binary_path.to_owned(),
        });
    }

    ancestry_chain
}

fn normalize_top_features(feature_importances: &[FeatureContribution]) -> Vec<FeatureContribution> {
    let mut top_features = feature_importances
        .iter()
        .map(|feature| FeatureContribution {
            feature_name: sanitize_string(&feature.feature_name),
            contribution_score: normalize_feature_weight(feature.contribution_score),
        })
        .collect::<Vec<_>>();
    top_features.sort_by(|left, right| {
        right
            .contribution_score
            .abs()
            .total_cmp(&left.contribution_score.abs())
            .then_with(|| left.feature_name.cmp(&right.feature_name))
    });

    if top_features.len() >= 5 {
        top_features.truncate(5);
        return top_features;
    }

    let existing_names = top_features
        .iter()
        .map(|feature| feature.feature_name.clone())
        .collect::<BTreeSet<_>>();
    for manifest_name in feature_manifest() {
        if top_features.len() == 5 {
            break;
        }
        if !existing_names.contains(*manifest_name) {
            top_features.push(FeatureContribution {
                feature_name: (*manifest_name).to_owned(),
                contribution_score: 0.0,
            });
        }
    }

    top_features
}

const fn normalize_score_for_log(score: f64) -> f64 {
    if score.is_finite() {
        score.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

const fn normalize_feature_weight(weight: f64) -> f64 {
    if weight.is_finite() { weight } else { 0.0 }
}

fn build_summary(
    process_name: &str,
    pid: u32,
    threat_score: f64,
    threshold: f64,
    top_features: &[FeatureContribution],
) -> String {
    let feature_summary = top_features
        .iter()
        .take(3)
        .map(|feature| {
            format!(
                "{}={:.3}",
                sanitize_string(&feature.feature_name),
                feature.contribution_score
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    sanitize_string(&format!(
        "{process_name} (pid {pid}) scored {threat_score:.4} against threshold {threshold:.4}; top contributors: {feature_summary}"
    ))
}

fn sanitize_string(input: &str) -> String {
    kernel_pointer_regex()
        .replace_all(&input.replace('\n', " "), REDACTED_KERNEL_POINTER)
        .into_owned()
}

fn kernel_pointer_regex() -> &'static Regex {
    static REGEX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)\b(?:0x)?ffff[0-9a-f]{12}\b")
            .expect("kernel pointer redaction regex must compile")
    })
}

#[cfg(test)]
mod tests {
    use super::{AlertGenerator, ClockSource};
    use crate::model::InferenceResult;
    use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
    use mini_edr_common::{
        EnrichedEvent, FeatureContribution, ProcessInfo, SyscallEvent, SyscallType,
    };
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tempfile::TempDir;
    use tokio::sync::broadcast;

    #[test]
    fn monotonic_alert_clock_ignores_backward_wall_clock_steps() {
        let tempdir = TempDir::new().expect("tempdir");
        let (alert_sender, _alert_receiver) = broadcast::channel(8);
        let (inference_log_sender, _inference_log_receiver) = broadcast::channel(8);
        let initial_wall_clock = Utc
            .with_ymd_and_hms(2026, 4, 26, 12, 0, 0)
            .single()
            .expect("valid wall clock")
            + ChronoDuration::milliseconds(123);
        let fake_clock = Arc::new(FakeClockSource::new(
            initial_wall_clock,
            Duration::from_secs(10),
        ));
        let generator = AlertGenerator::new_with_clock(
            0.7,
            alert_sender,
            inference_log_sender,
            tempdir.path().join("alert_id.seq"),
            fake_clock.clone(),
        )
        .expect("generator constructs");

        fake_clock.advance(
            Duration::from_millis(100),
            ChronoDuration::milliseconds(100),
        );
        let first_alert = generator
            .publish(&sample_enriched_event(), &sample_result(0.85))
            .expect("first publish succeeds")
            .expect("score should alert");

        fake_clock.advance(
            Duration::from_millis(100),
            ChronoDuration::seconds(-30) + ChronoDuration::milliseconds(100),
        );
        let second_alert = generator
            .publish(&sample_enriched_event(), &sample_result(0.85))
            .expect("second publish succeeds")
            .expect("score should alert");

        assert!(
            second_alert.timestamp >= first_alert.timestamp,
            "backward wall-clock steps must not move alert timestamps backwards"
        );
        assert_eq!(
            second_alert.timestamp - first_alert.timestamp,
            ChronoDuration::milliseconds(100),
            "alert timestamps should advance by the monotonic elapsed time, not by the stepped wall clock"
        );
    }

    #[test]
    fn monotonic_alert_clock_projects_monotonic_elapsed_onto_wall_clock_display_time() {
        let tempdir = TempDir::new().expect("tempdir");
        let (alert_sender, _alert_receiver) = broadcast::channel(8);
        let (inference_log_sender, _inference_log_receiver) = broadcast::channel(8);
        let initial_wall_clock = Utc
            .with_ymd_and_hms(2026, 4, 26, 12, 0, 0)
            .single()
            .expect("valid wall clock");
        let fake_clock = Arc::new(FakeClockSource::new(
            initial_wall_clock,
            Duration::from_secs(3),
        ));
        let generator = AlertGenerator::new_with_clock(
            0.7,
            alert_sender,
            inference_log_sender,
            tempdir.path().join("alert_id.seq"),
            fake_clock.clone(),
        )
        .expect("generator constructs");

        fake_clock.advance(
            Duration::from_millis(250),
            ChronoDuration::seconds(5) + ChronoDuration::milliseconds(250),
        );
        let alert = generator
            .publish(&sample_enriched_event(), &sample_result(0.85))
            .expect("publish succeeds")
            .expect("score should alert");

        assert_eq!(
            alert.timestamp,
            initial_wall_clock + ChronoDuration::milliseconds(250),
            "display timestamps should stay anchored to the startup wall clock and move by monotonic elapsed time"
        );
    }

    struct FakeClockSource {
        state: Mutex<FakeClockState>,
    }

    struct FakeClockState {
        wall_clock: DateTime<Utc>,
        monotonic_now: Duration,
    }

    impl FakeClockSource {
        fn new(wall_clock: DateTime<Utc>, monotonic_now: Duration) -> Self {
            Self {
                state: Mutex::new(FakeClockState {
                    wall_clock,
                    monotonic_now,
                }),
            }
        }

        fn advance(&self, monotonic_delta: Duration, wall_clock_delta: ChronoDuration) {
            let mut state = self.state.lock().expect("fake clock lock");
            state.monotonic_now += monotonic_delta;
            state.wall_clock += wall_clock_delta;
        }
    }

    impl ClockSource for FakeClockSource {
        fn wall_clock_now(&self) -> DateTime<Utc> {
            self.state.lock().expect("fake clock lock").wall_clock
        }

        fn monotonic_now(&self) -> Duration {
            self.state.lock().expect("fake clock lock").monotonic_now
        }
    }

    fn sample_enriched_event() -> EnrichedEvent {
        EnrichedEvent {
            event: SyscallEvent {
                event_id: 1,
                timestamp: 1_713_000_005_123_456_789,
                pid: 4_242,
                ppid: 1_001,
                tid: 4_242,
                syscall_type: SyscallType::Connect,
                filename: None,
                ip_address: Some([127, 0, 0, 1]),
                port: Some(4_443),
                child_pid: None,
                open_flags: None,
                syscall_result: None,
            },
            process_name: Some("curl".to_owned()),
            binary_path: Some("/usr/bin/curl".to_owned()),
            cgroup: Some("0::/user.slice/user-1000.slice/session-2.scope".to_owned()),
            uid: Some(1_000),
            ancestry_chain: vec![
                ProcessInfo {
                    pid: 1,
                    process_name: "systemd".to_owned(),
                    binary_path: "/usr/lib/systemd/systemd".to_owned(),
                },
                ProcessInfo {
                    pid: 1_001,
                    process_name: "bash".to_owned(),
                    binary_path: "/usr/bin/bash".to_owned(),
                },
                ProcessInfo {
                    pid: 4_242,
                    process_name: "curl".to_owned(),
                    binary_path: "/usr/bin/curl".to_owned(),
                },
            ],
            ancestry_truncated: false,
            repeat_count: 1,
        }
    }

    fn sample_result(score: f64) -> InferenceResult {
        InferenceResult {
            threat_score: score,
            feature_importances: vec![FeatureContribution {
                feature_name: "feature_0".to_owned(),
                contribution_score: 1.0,
            }],
            model_hash: "sample-model-hash".to_owned(),
        }
    }
}
