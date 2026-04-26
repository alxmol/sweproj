//! ONNX Runtime one-time initialization.
//!
//! The `ort` crate owns environment setup and downloaded binary management. The
//! detection crate just needs to ensure that initialization happens once before
//! any session builders are created.

use std::{path::Path, sync::OnceLock};

use crate::error::ModelLoadError;

static ORT_INIT_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

/// Initialize `ort` exactly once, preferring the mission's local venv copy.
///
/// # Errors
///
/// Returns [`ModelLoadError::OnnxRuntimeUnavailable`] when the dynamic library
/// could not be discovered or loaded.
pub fn ensure_ort_initialized(model_path: &Path) -> Result<(), ModelLoadError> {
    let outcome = ORT_INIT_RESULT.get_or_init(|| {
        let _ = ort::init().commit();
        Ok(())
    });

    outcome
        .clone()
        .map_err(|details| ModelLoadError::OnnxRuntimeUnavailable {
            path: model_path.to_path_buf(),
            details,
        })
}
