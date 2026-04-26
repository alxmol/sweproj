//! Atomic model-manager and degraded-mode orchestration.
//!
//! This layer exists so the daemon can treat model startup and hot reload as a
//! single atomic pointer swap: readers borrow an `Arc` to the current
//! implementation, drop the lock immediately, and then score on that stable
//! snapshot. A failed reload therefore cannot tear the live model out from
//! underneath in-flight predictions.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use mini_edr_common::FeatureVector;

use crate::{
    error::{InferenceError, LoadFailureKind, ModelLoadError},
    model::{InferenceModel, InferenceResult, OnnxModel, XgboostModel},
};

/// Supported inference backends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelBackend {
    /// Canonical deployment path via `ort` and ONNX Runtime.
    OnnxRuntime,
    /// Pure-Rust evaluator for the exported tree ensemble.
    XgboostEquivalent,
}

/// Observable runtime state of the active model slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelStatus {
    /// A live model is available for scoring.
    Running {
        /// Backend implementation currently serving predictions.
        backend: ModelBackend,
        /// SHA-256 hash of the serialized artifact.
        model_hash: String,
        /// Source path of the loaded artifact.
        model_path: PathBuf,
    },
    /// The manager is in pass-through mode because no valid model could be loaded.
    Degraded {
        /// Source path that failed to load.
        model_path: PathBuf,
        /// Stable degraded-mode category surfaced to the daemon state machine.
        failure_kind: LoadFailureKind,
        /// Human-readable reason preserved for logs and user-visible health status.
        message: String,
    },
}

/// Atomic model slot plus degraded-mode bookkeeping.
pub struct ModelManager {
    preferred_backend: ModelBackend,
    active_model: Arc<RwLock<Arc<dyn InferenceModel>>>,
    status: Arc<RwLock<ModelStatus>>,
}

impl ModelManager {
    /// Load the initial model, falling back to pass-through degraded mode.
    ///
    /// # Panics
    ///
    /// Panics only if the internal `RwLock` is poisoned by a previous panic,
    /// which indicates a bug in this crate rather than an operator error.
    #[must_use]
    pub fn load_at_startup(model_path: &Path, backend: ModelBackend) -> Self {
        match load_backend(model_path, backend) {
            Ok(model) => {
                let status = ModelStatus::Running {
                    backend,
                    model_hash: model.model_hash().to_owned(),
                    model_path: model_path.to_path_buf(),
                };
                tracing::info!(
                    event = "model_loaded",
                    backend = ?backend,
                    model_path = %model_path.display(),
                    model_hash = model.model_hash(),
                    "loaded detection model at startup"
                );
                Self {
                    preferred_backend: backend,
                    active_model: Arc::new(RwLock::new(model)),
                    status: Arc::new(RwLock::new(status)),
                }
            }
            Err(error) => {
                let degraded_model =
                    Arc::new(PassThroughModel::from_error(model_path, backend, &error));
                let status = degraded_status(model_path, &error);
                tracing::warn!(
                    event = "model_load_failed",
                    failure_kind = error.failure_kind().as_log_event(),
                    model_path = %model_path.display(),
                    details = %error,
                    "model load failed; entering degraded mode"
                );
                Self {
                    preferred_backend: backend,
                    active_model: Arc::new(RwLock::new(degraded_model)),
                    status: Arc::new(RwLock::new(status)),
                }
            }
        }
    }

    /// Return a snapshot of the current status.
    ///
    /// # Panics
    ///
    /// Panics if a previous panic poisoned the internal status lock.
    #[must_use]
    pub fn status(&self) -> ModelStatus {
        self.status
            .read()
            .expect("model status lock must not be poisoned")
            .clone()
    }

    /// Score one feature vector through the current active model snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`InferenceError`] when the active model is degraded or the
    /// backend rejects the encoded feature row.
    ///
    /// # Panics
    ///
    /// Panics if a previous panic poisoned the internal model-slot lock.
    pub fn predict(&self, features: &FeatureVector) -> Result<InferenceResult, InferenceError> {
        // The clone-drop-predict pattern is the key hot-swap invariant: callers
        // take a cheap `Arc` snapshot while holding the read lock, then release
        // the lock before inference starts. Reloads only replace the pointer,
        // so in-flight predictions continue on the old `Arc` without blocking
        // the incoming writer or observing a half-initialized backend.
        let active_model = self
            .active_model
            .read()
            .expect("model slot lock must not be poisoned")
            .clone();
        active_model.predict(features)
    }

    /// Attempt to atomically swap in a newly loaded model.
    ///
    /// # Errors
    ///
    /// Returns [`ModelLoadError`] when the new artifact is invalid. If a live
    /// model is already serving traffic, that model is retained unchanged.
    ///
    /// # Panics
    ///
    /// Panics if a previous panic poisoned the internal model-slot or status
    /// locks.
    pub fn reload(&self, model_path: &Path) -> Result<(), ModelLoadError> {
        match load_backend(model_path, self.preferred_backend) {
            Ok(model) => {
                let new_status = ModelStatus::Running {
                    backend: self.preferred_backend,
                    model_hash: model.model_hash().to_owned(),
                    model_path: model_path.to_path_buf(),
                };
                *self
                    .active_model
                    .write()
                    .expect("model slot lock must not be poisoned") = model;
                *self
                    .status
                    .write()
                    .expect("model status lock must not be poisoned") = new_status;
                tracing::info!(
                    event = "model_loaded",
                    backend = ?self.preferred_backend,
                    model_path = %model_path.display(),
                    "atomically swapped detection model"
                );
                Ok(())
            }
            Err(error) => {
                let was_running = matches!(self.status(), ModelStatus::Running { .. });
                if was_running {
                    tracing::error!(
                        event = "model_validation_failed",
                        failure_kind = error.failure_kind().as_log_event(),
                        model_path = %model_path.display(),
                        details = %error,
                        "rejected reload candidate and kept the previous live model"
                    );
                } else {
                    let degraded_model = Arc::new(PassThroughModel::from_error(
                        model_path,
                        self.preferred_backend,
                        &error,
                    ));
                    *self
                        .active_model
                        .write()
                        .expect("model slot lock must not be poisoned") = degraded_model;
                    *self
                        .status
                        .write()
                        .expect("model status lock must not be poisoned") =
                        degraded_status(model_path, &error);
                    tracing::warn!(
                        event = "model_load_failed",
                        failure_kind = error.failure_kind().as_log_event(),
                        model_path = %model_path.display(),
                        details = %error,
                        "reload failed while already degraded; staying in pass-through mode"
                    );
                }
                Err(error)
            }
        }
    }
}

struct PassThroughModel {
    backend: ModelBackend,
    model_hash: String,
    failure_kind: LoadFailureKind,
    message: String,
}

impl PassThroughModel {
    fn from_error(_model_path: &Path, backend: ModelBackend, error: &ModelLoadError) -> Self {
        Self {
            backend,
            model_hash: "degraded".to_owned(),
            failure_kind: error.failure_kind(),
            message: error.to_string(),
        }
    }
}

impl InferenceModel for PassThroughModel {
    fn backend(&self) -> ModelBackend {
        self.backend
    }

    fn model_hash(&self) -> &str {
        &self.model_hash
    }

    fn predict(&self, _features: &FeatureVector) -> Result<InferenceResult, InferenceError> {
        Err(InferenceError::DegradedMode {
            failure_kind: self.failure_kind,
            message: self.message.clone(),
        })
    }
}

fn load_backend(
    model_path: &Path,
    backend: ModelBackend,
) -> Result<Arc<dyn InferenceModel>, ModelLoadError> {
    match backend {
        ModelBackend::OnnxRuntime => Ok(Arc::new(OnnxModel::load(model_path)?)),
        ModelBackend::XgboostEquivalent => Ok(Arc::new(XgboostModel::load(model_path)?)),
    }
}

fn degraded_status(model_path: &Path, error: &ModelLoadError) -> ModelStatus {
    ModelStatus::Degraded {
        model_path: model_path.to_path_buf(),
        failure_kind: error.failure_kind(),
        message: error.to_string(),
    }
}
