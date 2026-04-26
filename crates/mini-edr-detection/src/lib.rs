//! Model loading, inference, degraded-mode fallback, and hot-swap primitives.
//!
//! Per SDD §4.1.3 and §8.2, the detection crate owns the ML-facing portion of
//! the pipeline: it converts `FeatureVector`s into model inputs, executes the
//! deployed classifier, and reports deterministic threat scores plus
//! feature-importance context. The daemon will later wire these types into its
//! runtime state machine, but the core invariants live here so they can be unit
//! tested without probe or UI dependencies.

mod error;
mod feature_manifest;
mod manager;
mod model;
mod ort_runtime;
mod tree_ensemble;

/// Re-export the common crate under a stable module name so this subsystem can
/// share domain types without ad-hoc dependency aliases.
pub use mini_edr_common as common;

pub use crate::{
    error::{InferenceError, LoadFailureKind, ModelLoadError},
    manager::{ModelBackend, ModelManager, ModelStatus},
    model::{InferenceModel, InferenceResult, OnnxModel, XgboostModel},
};
