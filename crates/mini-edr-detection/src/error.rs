//! Error types for the detection engine.
//!
//! The daemon's degraded-mode transitions depend on stable failure categories
//! rather than ad-hoc strings, so this module centralizes the load and
//! inference errors that higher layers inspect when deciding whether to keep
//! scoring, degrade to pass-through mode, or reject a hot-reload candidate.

use std::path::PathBuf;

use thiserror::Error;

/// Stable failure categories surfaced to the daemon state machine and logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadFailureKind {
    /// The configured model path did not exist on disk.
    ModelPathMissing,
    /// The ONNX artifact could not be decoded, typically because it was truncated.
    ModelTruncated,
    /// The model imports an ONNX opset this runtime intentionally does not support.
    OpsetUnsupported,
    /// The input tensor shape or output tensor shape violated the contract.
    TensorShapeInvalid,
    /// Required model metadata was absent or malformed.
    ModelMetadataMissing,
    /// The exported feature manifest no longer matches `FeatureVector` flattening.
    FeatureManifestMismatch,
    /// The graph shape is valid ONNX, but not the specific tree ensemble this crate supports.
    ModelSchemaInvalid,
    /// The local ONNX Runtime shared library could not be found or loaded.
    OnnxRuntimeUnavailable,
    /// ONNX Runtime accepted the library but rejected the model session.
    OnnxRuntimeSessionError,
}

impl LoadFailureKind {
    /// Return the stable machine-readable log token expected by validators.
    #[must_use]
    pub const fn as_log_event(self) -> &'static str {
        match self {
            Self::ModelPathMissing => "model_path_missing",
            Self::ModelTruncated => "model_truncated",
            Self::OpsetUnsupported => "opset_unsupported",
            Self::TensorShapeInvalid => "tensor_shape_invalid",
            Self::ModelMetadataMissing => "model_metadata_missing",
            Self::FeatureManifestMismatch => "feature_manifest_mismatch",
            Self::ModelSchemaInvalid => "model_schema_invalid",
            Self::OnnxRuntimeUnavailable => "onnxruntime_unavailable",
            Self::OnnxRuntimeSessionError => "onnxruntime_session_error",
        }
    }
}

/// Errors raised while loading or validating a model artifact.
#[derive(Debug, Error)]
pub enum ModelLoadError {
    /// The configured file path does not exist.
    #[error("model file `{path}` does not exist")]
    ModelPathMissing {
        /// Missing artifact path.
        path: PathBuf,
    },
    /// The file bytes were unreadable as a complete ONNX protobuf.
    #[error("model file `{path}` is truncated or malformed: {details}")]
    ModelTruncated {
        /// Offending file path.
        path: PathBuf,
        /// Decoder failure details.
        details: String,
    },
    /// The ONNX opset is outside the currently supported contract.
    #[error(
        "model file `{path}` imports unsupported ai.onnx.ml opset {version}; only opset 1 is supported"
    )]
    OpsetUnsupported {
        /// Offending file path.
        path: PathBuf,
        /// Unsupported opset number.
        version: i64,
    },
    /// The model's tensor shape is incompatible with the deployed feature manifest.
    #[error("model file `{path}` has invalid tensor shape: {details}")]
    TensorShapeInvalid {
        /// Offending file path.
        path: PathBuf,
        /// Validation failure details.
        details: String,
    },
    /// Required metadata or attributes were missing from the artifact.
    #[error("model file `{path}` is missing required metadata: {details}")]
    ModelMetadataMissing {
        /// Offending file path.
        path: PathBuf,
        /// Missing metadata details.
        details: String,
    },
    /// The artifact metadata no longer matches the runtime feature encoding.
    #[error(
        "model file `{path}` advertises a feature manifest that differs from the runtime contract"
    )]
    FeatureManifestMismatch {
        /// Offending file path.
        path: PathBuf,
    },
    /// The ONNX graph is valid but outside the supported tree-ensemble subset.
    #[error("model file `{path}` has an unsupported schema: {details}")]
    ModelSchemaInvalid {
        /// Offending file path.
        path: PathBuf,
        /// Schema details.
        details: String,
    },
    /// Loading the ONNX Runtime shared library failed before session construction.
    #[error("unable to initialize ONNX Runtime for `{path}`: {details}")]
    OnnxRuntimeUnavailable {
        /// Artifact path the runtime was attempting to load.
        path: PathBuf,
        /// Dynamic-library discovery or initialization error.
        details: String,
    },
    /// ONNX Runtime rejected the model while creating or running a session.
    #[error("ONNX Runtime rejected `{path}`: {details}")]
    OnnxRuntimeSessionError {
        /// Offending file path.
        path: PathBuf,
        /// Runtime error details.
        details: String,
    },
    /// A filesystem read failed for a reason other than a missing file.
    #[error("failed to read `{path}`: {details}")]
    Io {
        /// Offending file path.
        path: PathBuf,
        /// I/O error details.
        details: String,
    },
}

impl ModelLoadError {
    /// Return the stable failure category used by degraded-mode decisions.
    #[must_use]
    pub const fn failure_kind(&self) -> LoadFailureKind {
        match self {
            Self::ModelPathMissing { .. } => LoadFailureKind::ModelPathMissing,
            Self::ModelTruncated { .. } | Self::Io { .. } => LoadFailureKind::ModelTruncated,
            Self::OpsetUnsupported { .. } => LoadFailureKind::OpsetUnsupported,
            Self::TensorShapeInvalid { .. } => LoadFailureKind::TensorShapeInvalid,
            Self::ModelMetadataMissing { .. } => LoadFailureKind::ModelMetadataMissing,
            Self::FeatureManifestMismatch { .. } => LoadFailureKind::FeatureManifestMismatch,
            Self::ModelSchemaInvalid { .. } => LoadFailureKind::ModelSchemaInvalid,
            Self::OnnxRuntimeUnavailable { .. } => LoadFailureKind::OnnxRuntimeUnavailable,
            Self::OnnxRuntimeSessionError { .. } => LoadFailureKind::OnnxRuntimeSessionError,
        }
    }

    /// Build a load error from a plain filesystem failure.
    #[must_use]
    pub fn from_io(path: impl Into<PathBuf>, error: &std::io::Error) -> Self {
        let path = path.into();
        if error.kind() == std::io::ErrorKind::NotFound {
            Self::ModelPathMissing { path }
        } else {
            Self::Io {
                path,
                details: error.to_string(),
            }
        }
    }
}

/// Errors raised while scoring a single `FeatureVector`.
#[derive(Debug, Error)]
pub enum InferenceError {
    /// The manager is currently in pass-through degraded mode.
    #[error("model manager is in degraded mode ({failure_kind:?}): {message}")]
    DegradedMode {
        /// Stable degraded-mode category for logging and state transitions.
        failure_kind: LoadFailureKind,
        /// Human-readable reason preserved from the triggering load failure.
        message: String,
    },
    /// A runtime feature value could not be represented as a finite model input.
    #[error("feature `{feature_name}` must be finite before inference")]
    InvalidFeatureValue {
        /// Offending feature name from the flattened manifest.
        feature_name: String,
    },
    /// A synchronization primitive was poisoned by a previous panic.
    #[error("model session lock was poisoned")]
    LockPoisoned,
    /// ONNX Runtime returned an execution failure.
    #[error("ONNX Runtime inference failed: {details}")]
    OnnxRuntime {
        /// Runtime error details.
        details: String,
    },
    /// The model output tensor was missing or had an unexpected shape.
    #[error("model output tensor is invalid: {details}")]
    InvalidOutput {
        /// Output validation details.
        details: String,
    },
}
