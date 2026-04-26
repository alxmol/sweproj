//! Stable `FeatureVector` flattening shared by all inference backends.
//!
//! The Python trainer records the deployed feature ordering in ONNX metadata, so
//! the Rust runtime treats this manifest as an append-only contract. Keeping the
//! names centralized here lets both the ONNX Runtime path and the pure-Rust
//! tree evaluator use identical encoding and validation logic.

use mini_edr_common::{FeatureContribution, FeatureVector};

use crate::error::InferenceError;

const FEATURE_MANIFEST: [&str; 35] = [
    "pid",
    "window_start_ns",
    "window_end_ns",
    "total_syscalls",
    "execve_count",
    "openat_count",
    "connect_count",
    "clone_count",
    "execve_ratio",
    "openat_ratio",
    "connect_ratio",
    "clone_ratio",
    "path_entropy",
    "unique_ips",
    "unique_files",
    "child_spawn_count",
    "avg_inter_syscall_time_ns",
    "min_inter_syscall_time_ns",
    "max_inter_syscall_time_ns",
    "stddev_inter_syscall_time_ns",
    "wrote_etc",
    "wrote_tmp",
    "wrote_dev",
    "read_sensitive_file_count",
    "write_sensitive_file_count",
    "outbound_connection_count",
    "loopback_connection_count",
    "distinct_ports",
    "failed_syscall_count",
    "short_lived",
    "window_duration_ns",
    "events_per_second",
    "bigrams.__process_positive_rate__",
    "bigrams.__event_positive_rate__",
    "trigrams.__path_positive_rate__",
];

/// Return the expected ONNX metadata manifest.
#[must_use]
pub const fn feature_manifest() -> &'static [&'static str] {
    &FEATURE_MANIFEST
}

/// Convert one `FeatureVector` into the dense float row expected by the model.
///
/// # Errors
///
/// Returns [`InferenceError::InvalidFeatureValue`] when any numeric field is
/// non-finite before conversion to `f32`.
#[allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    reason = "The exported ONNX contract is a flat float tensor; keeping each field explicit preserves the append-only manifest ordering from the training pipeline."
)]
pub fn encode_feature_vector(features: &FeatureVector) -> Result<Vec<f32>, InferenceError> {
    // The trainer emits a fixed-width dense row because ONNX Runtime expects a
    // contiguous tensor input. Boolean flags become `0.0` / `1.0`, and the
    // sparse-map priors default to zero so missing runtime context remains
    // deterministic instead of shifting later columns.
    let mut encoded = Vec::with_capacity(FEATURE_MANIFEST.len());
    push_finite(&mut encoded, "pid", f64::from(features.pid))?;
    push_finite(
        &mut encoded,
        "window_start_ns",
        features.window_start_ns as f64,
    )?;
    push_finite(&mut encoded, "window_end_ns", features.window_end_ns as f64)?;
    push_finite(
        &mut encoded,
        "total_syscalls",
        features.total_syscalls as f64,
    )?;
    push_finite(&mut encoded, "execve_count", features.execve_count as f64)?;
    push_finite(&mut encoded, "openat_count", features.openat_count as f64)?;
    push_finite(&mut encoded, "connect_count", features.connect_count as f64)?;
    push_finite(&mut encoded, "clone_count", features.clone_count as f64)?;
    push_finite(&mut encoded, "execve_ratio", features.execve_ratio)?;
    push_finite(&mut encoded, "openat_ratio", features.openat_ratio)?;
    push_finite(&mut encoded, "connect_ratio", features.connect_ratio)?;
    push_finite(&mut encoded, "clone_ratio", features.clone_ratio)?;
    push_finite(&mut encoded, "path_entropy", features.path_entropy)?;
    push_finite(&mut encoded, "unique_ips", features.unique_ips as f64)?;
    push_finite(&mut encoded, "unique_files", features.unique_files as f64)?;
    push_finite(
        &mut encoded,
        "child_spawn_count",
        features.child_spawn_count as f64,
    )?;
    push_finite(
        &mut encoded,
        "avg_inter_syscall_time_ns",
        features.avg_inter_syscall_time_ns,
    )?;
    push_finite(
        &mut encoded,
        "min_inter_syscall_time_ns",
        features.min_inter_syscall_time_ns,
    )?;
    push_finite(
        &mut encoded,
        "max_inter_syscall_time_ns",
        features.max_inter_syscall_time_ns,
    )?;
    push_finite(
        &mut encoded,
        "stddev_inter_syscall_time_ns",
        features.stddev_inter_syscall_time_ns,
    )?;
    encoded.push(if features.wrote_etc { 1.0 } else { 0.0 });
    encoded.push(if features.wrote_tmp { 1.0 } else { 0.0 });
    encoded.push(if features.wrote_dev { 1.0 } else { 0.0 });
    push_finite(
        &mut encoded,
        "read_sensitive_file_count",
        features.read_sensitive_file_count as f64,
    )?;
    push_finite(
        &mut encoded,
        "write_sensitive_file_count",
        features.write_sensitive_file_count as f64,
    )?;
    push_finite(
        &mut encoded,
        "outbound_connection_count",
        features.outbound_connection_count as f64,
    )?;
    push_finite(
        &mut encoded,
        "loopback_connection_count",
        features.loopback_connection_count as f64,
    )?;
    push_finite(
        &mut encoded,
        "distinct_ports",
        features.distinct_ports as f64,
    )?;
    push_finite(
        &mut encoded,
        "failed_syscall_count",
        features.failed_syscall_count as f64,
    )?;
    encoded.push(if features.short_lived { 1.0 } else { 0.0 });
    push_finite(
        &mut encoded,
        "window_duration_ns",
        features.window_duration_ns as f64,
    )?;
    push_finite(
        &mut encoded,
        "events_per_second",
        features.events_per_second,
    )?;
    push_finite(
        &mut encoded,
        "bigrams.__process_positive_rate__",
        features
            .bigrams
            .get("__process_positive_rate__")
            .copied()
            .unwrap_or(0.0),
    )?;
    push_finite(
        &mut encoded,
        "bigrams.__event_positive_rate__",
        features
            .bigrams
            .get("__event_positive_rate__")
            .copied()
            .unwrap_or(0.0),
    )?;
    push_finite(
        &mut encoded,
        "trigrams.__path_positive_rate__",
        features
            .trigrams
            .get("__path_positive_rate__")
            .copied()
            .unwrap_or(0.0),
    )?;
    Ok(encoded)
}

/// Convert per-feature contribution totals into deterministic report entries.
#[must_use]
pub fn contribution_report(
    contributions: impl IntoIterator<Item = (usize, f64)>,
) -> Vec<FeatureContribution> {
    let mut entries = contributions
        .into_iter()
        .filter(|(_, score)| score.abs() > f64::EPSILON)
        .map(|(index, contribution_score)| FeatureContribution {
            feature_name: FEATURE_MANIFEST[index].to_owned(),
            contribution_score,
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .contribution_score
            .abs()
            .total_cmp(&left.contribution_score.abs())
            .then_with(|| left.feature_name.cmp(&right.feature_name))
    });
    entries
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "ONNX Runtime consumes `f32` tensors, so the final narrowing conversion is the deployment format."
)]
fn push_finite(
    target: &mut Vec<f32>,
    feature_name: &str,
    value: f64,
) -> Result<(), InferenceError> {
    if value.is_finite() {
        target.push(value as f32);
        Ok(())
    } else {
        Err(InferenceError::InvalidFeatureValue {
            feature_name: feature_name.to_owned(),
        })
    }
}
