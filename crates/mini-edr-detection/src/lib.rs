//! Model loading, inference, degraded-mode fallback, and hot-swap primitives.
//!
//! Per SDD §4.1.3 and §8.2, the detection crate owns the ML-facing portion of
//! the pipeline: it converts `FeatureVector`s into model inputs, executes the
//! deployed classifier, and reports deterministic threat scores plus
//! feature-importance context. The daemon will later wire these types into its
//! runtime state machine, but the core invariants live here so they can be unit
//! tested without probe or UI dependencies.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!(
    "Mini-EDR's detection runtime is only supported on Linux x86_64; non-Linux or non-x86_64 builds are intentionally cfg-gated before Cargo reaches the platform-specific ONNX runtime backend"
);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod alert_generator;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod error;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod feature_manifest;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod manager;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod model;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod ort_runtime;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod tree_ensemble;

/// Re-export the common crate under a stable module name so this subsystem can
/// share domain types without ad-hoc dependency aliases.
pub use mini_edr_common as common;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use crate::{
    alert_generator::{AlertGenerator, InferenceLogEntry, TopFeature},
    error::{AlertGenerationError, InferenceError, LoadFailureKind, ModelLoadError},
    manager::{ModelBackend, ModelManager, ModelStatus, PreparedModel},
    model::{InferenceModel, InferenceResult, OnnxModel, XgboostModel},
};
