//! Concrete inference backends.
//!
//! Both backends share the same feature encoder and model hash, but they differ
//! in execution strategy: `OnnxModel` uses the real ONNX Runtime session while
//! `XgboostModel` evaluates the exported tree ensemble directly in Rust. The
//! two implementations let tests cross-check determinism and score bounds
//! without introducing an extra native `XGBoost` dependency.

use std::{
    path::Path,
    sync::{Mutex, PoisonError},
};

use mini_edr_common::{FeatureContribution, FeatureVector};
use ndarray::Array2;
use ort::{session::Session, value::TensorRef};

use crate::{
    error::{InferenceError, ModelLoadError},
    feature_manifest::encode_feature_vector,
    manager::ModelBackend,
    ort_runtime::ensure_ort_initialized,
    tree_ensemble::TreeEnsembleModel,
};

/// Output of scoring one `FeatureVector`.
#[derive(Clone, Debug, PartialEq)]
pub struct InferenceResult {
    /// Threat score bounded to the inclusive `[0.0, 1.0]` contract.
    pub threat_score: f64,
    /// Deterministic per-feature contribution report for analyst context.
    pub feature_importances: Vec<FeatureContribution>,
}

/// Common behavior shared by all live and degraded model implementations.
///
/// The trait deliberately uses `&self` for `predict()` so the manager can keep
/// an `Arc<dyn InferenceModel>` behind an `RwLock` and atomically swap the
/// pointer on reload. Backend-specific interior mutability (for example the
/// ONNX Runtime session mutex) stays inside the implementation, which lets
/// in-flight predictions finish on the old `Arc` even after the manager points
/// future calls at a newly loaded model.
pub trait InferenceModel: Send + Sync {
    /// Identify the backend implementation currently serving predictions.
    fn backend(&self) -> ModelBackend;

    /// Expose the stable SHA-256 hash of the loaded model artifact.
    fn model_hash(&self) -> &str;

    /// Score one `FeatureVector`.
    ///
    /// # Errors
    ///
    /// Returns [`InferenceError`] when the backend is degraded, the encoded
    /// features are invalid, or the runtime rejects the input/output tensors.
    fn predict(&self, features: &FeatureVector) -> Result<InferenceResult, InferenceError>;
}

/// Real ONNX Runtime-backed inference session.
pub struct OnnxModel {
    session: Mutex<Session>,
    equivalent_model: XgboostModel,
}

impl OnnxModel {
    /// Load the canonical ONNX deployment artifact through `ort`.
    ///
    /// # Errors
    ///
    /// Returns [`ModelLoadError`] when the file is missing, invalid, or ONNX
    /// Runtime cannot open the artifact.
    pub fn load(model_path: &Path) -> Result<Self, ModelLoadError> {
        let equivalent_model = XgboostModel::load(model_path)?;
        ensure_ort_initialized(model_path)?;
        let mut builder =
            Session::builder().map_err(|error| ModelLoadError::OnnxRuntimeUnavailable {
                path: model_path.to_path_buf(),
                details: error.to_string(),
            })?;
        let session = builder.commit_from_file(model_path).map_err(|error| {
            ModelLoadError::OnnxRuntimeSessionError {
                path: model_path.to_path_buf(),
                details: error.to_string(),
            }
        })?;

        Ok(Self {
            session: Mutex::new(session),
            equivalent_model,
        })
    }
}

impl InferenceModel for OnnxModel {
    fn backend(&self) -> ModelBackend {
        ModelBackend::OnnxRuntime
    }

    fn model_hash(&self) -> &str {
        self.equivalent_model.model_hash()
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "ONNX Runtime output tensors borrow the live session, so the mutex guard must stay alive until the probability tensor is fully extracted."
    )]
    fn predict(&self, features: &FeatureVector) -> Result<InferenceResult, InferenceError> {
        let encoded = encode_feature_vector(features)?;
        let input_width = encoded.len();
        let array = Array2::from_shape_vec((1, input_width), encoded).map_err(|error| {
            InferenceError::InvalidOutput {
                details: format!("failed to materialize ONNX input tensor: {error}"),
            }
        })?;
        let input = TensorRef::from_array_view(array.view()).map_err(|error| {
            InferenceError::OnnxRuntime {
                details: format!("failed to create ONNX input tensor: {error}"),
            }
        })?;

        let probability = {
            let mut session = self
                .session
                .lock()
                .map_err(|_: PoisonError<_>| InferenceError::LockPoisoned)?;
            let outputs =
                session
                    .run(ort::inputs![input])
                    .map_err(|error| InferenceError::OnnxRuntime {
                        details: error.to_string(),
                    })?;
            let probabilities = outputs
                .get(self.equivalent_model.probabilities_output_name())
                .ok_or_else(|| InferenceError::InvalidOutput {
                    details: format!(
                        "probability output `{}` was not present",
                        self.equivalent_model.probabilities_output_name()
                    ),
                })?;
            let (_, tensor) = probabilities.try_extract_tensor::<f32>().map_err(|error| {
                InferenceError::InvalidOutput {
                    details: format!("failed to read probability tensor: {error}"),
                }
            })?;
            tensor
                .get(1)
                .copied()
                .ok_or_else(|| InferenceError::InvalidOutput {
                    details: "probability tensor did not contain the positive-class slot"
                        .to_owned(),
                })?
        };

        // We reuse the pure-Rust evaluator for deterministic per-feature path
        // contributions so both backends explain the same tree decisions while
        // ONNX Runtime remains the source of truth for the final score.
        let feature_importances = self.equivalent_model.predict(features)?.feature_importances;
        Ok(InferenceResult {
            threat_score: f64::from(probability).clamp(0.0, 1.0),
            feature_importances,
        })
    }
}

/// Pure-Rust evaluator for the exported `XGBoost` tree ensemble.
pub struct XgboostModel {
    ensemble: TreeEnsembleModel,
}

impl XgboostModel {
    /// Load the ONNX tree ensemble into the pure-Rust evaluator.
    ///
    /// # Errors
    ///
    /// Returns [`ModelLoadError`] when the file is missing or does not match the
    /// tree-ensemble schema exported by the training pipeline.
    pub fn load(model_path: &Path) -> Result<Self, ModelLoadError> {
        Ok(Self {
            ensemble: TreeEnsembleModel::load(model_path)?,
        })
    }

    pub(crate) fn model_hash(&self) -> &str {
        self.ensemble.model_hash()
    }

    pub(crate) fn probabilities_output_name(&self) -> &str {
        self.ensemble.probabilities_output_name()
    }
}

impl InferenceModel for XgboostModel {
    fn backend(&self) -> ModelBackend {
        ModelBackend::XgboostEquivalent
    }

    fn model_hash(&self) -> &str {
        self.ensemble.model_hash()
    }

    fn predict(&self, features: &FeatureVector) -> Result<InferenceResult, InferenceError> {
        let prediction = self.ensemble.predict(features)?;
        Ok(InferenceResult {
            threat_score: prediction.threat_score,
            feature_importances: prediction.feature_importances,
        })
    }
}
