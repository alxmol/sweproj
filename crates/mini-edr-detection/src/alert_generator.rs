//! Alert generation, threshold gating, and alert-ID persistence.
//!
//! Per SDD §4.1.3 and FR-D03/FR-D04/FR-D06, this module sits immediately
//! downstream of model inference. It applies the `>=` alert-threshold contract,
//! emits one broadcast alert per qualifying score, logs every inference result
//! at debug level, and persists the alert-ID high-water mark to a tiny state
//! file. We choose the sequence-file approach (rather than `UUIDv7`) because the
//! shared `Alert` schema already models `alert_id` as a monotonic `u64`, which
//! makes restart-order assertions straightforward for validators and operators.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
};

use chrono::Utc;
use mini_edr_common::{Alert, EnrichedEvent, FeatureContribution, ProcessInfo};
use regex::Regex;
use tokio::sync::broadcast;

use crate::{
    error::AlertGenerationError, feature_manifest::feature_manifest, model::InferenceResult,
};

const REDACTED_KERNEL_POINTER: &str = "[redacted-kernel-pointer]";

/// Gated alert publisher that turns scored process context into `Alert`s.
///
/// The generator owns two operational invariants:
/// 1. `score >= threshold` fires and `score < threshold` suppresses, including
///    the documented 0.0 and 1.0 threshold boundary values.
/// 2. Every qualifying alert gets a strictly increasing `u64` identifier that
///    survives a clean restart because the latest high-water mark is persisted
///    to the configured state file after each issuance.
pub struct AlertGenerator {
    threshold: f64,
    alert_sender: broadcast::Sender<Alert>,
    alert_ids: AlertIdSequence,
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
        alert_id_state_path: impl Into<PathBuf>,
    ) -> Result<Self, AlertGenerationError> {
        validate_threshold(threshold)?;
        Ok(Self {
            threshold,
            alert_sender,
            alert_ids: AlertIdSequence::load(alert_id_state_path.into())?,
        })
    }

    /// Publish an alert for a scored process when the configured threshold fires.
    ///
    /// Every call emits one debug inference log record, regardless of whether
    /// the score crossed the threshold, because FR-D06 explicitly requires the
    /// offline audit trail to include benign and suppressed results as well.
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
        tracing::debug!(
            event_type = "inference_result",
            pid = enriched_event.event.pid,
            score = inference_result.threat_score,
            threshold = self.threshold,
            would_alert = inference_result.threat_score >= self.threshold,
            top_features = ?top_features,
            "recorded detection inference result"
        );

        if inference_result.threat_score < self.threshold {
            return Ok(None);
        }

        let alert =
            self.build_alert(enriched_event, inference_result.threat_score, top_features)?;
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

    fn build_alert(
        &self,
        enriched_event: &EnrichedEvent,
        threat_score: f64,
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
            threat_score,
            self.threshold,
            &top_features,
        );

        Ok(Alert {
            alert_id: self.alert_ids.next_id()?,
            timestamp: Utc::now(),
            pid,
            process_name,
            binary_path,
            ancestry_chain,
            threat_score,
            top_features,
            summary,
        })
    }
}

struct AlertIdSequence {
    state_path: PathBuf,
    last_issued: Mutex<u64>,
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
            last_issued: Mutex::new(last_issued),
        })
    }

    fn next_id(&self) -> Result<u64, AlertGenerationError> {
        let mut last_issued = self
            .last_issued
            .lock()
            .expect("alert-id lock must not be poisoned");
        let next_id = last_issued
            .checked_add(1)
            .ok_or(AlertGenerationError::AlertIdOverflow)?;
        persist_state_file(&self.state_path, next_id)?;
        *last_issued = next_id;
        drop(last_issued);
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
            contribution_score: feature.contribution_score,
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
