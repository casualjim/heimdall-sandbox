//! Shared ONNX model runtime infrastructure for Heimdall.
//!
//! The crate owns everything that does not depend on which model is loaded:
//! Hugging Face asset download and cache-only lookup ([`source`]), ONNX Runtime
//! session management ([`session`]), and token window planning ([`windows`]).
//! Model-specific crates such as `heimdall-privacy-filter` own their asset
//! lists, tokenization contracts, and output decoding on top of it.

pub mod session;
pub mod source;
pub mod windows;

use std::result::Result as StdResult;
use std::sync::OnceLock;

use thiserror::Error as ThisError;

/// Result of the process-wide ONNX Runtime environment initialization.
///
/// ONNX Runtime allows one environment per process, so every model crate loads
/// sessions through this crate instead of initializing the environment itself.
static ORT_INIT_RESULT: OnceLock<StdResult<(), String>> = OnceLock::new();

#[small_ctor::ctor]
unsafe fn init_onnx_runtime() {
    let result = ort::init()
        .with_name("heimdall-privacy-filter")
        .commit()
        .then_some(())
        .ok_or_else(|| "ONNX Runtime environment was already initialized".to_string());
    let _ = ORT_INIT_RESULT.set(result);
}

pub(crate) fn ensure_ort_initialized() -> Result<()> {
    match ORT_INIT_RESULT.get() {
        Some(Ok(())) => Ok(()),
        Some(Err(error)) => Err(Error::Onnx(error.clone())),
        None => Err(Error::Onnx(
            "ONNX Runtime initialization did not run".to_string(),
        )),
    }
}

/// Result type for model runtime operations.
pub type Result<T, E = Error> = StdResult<T, E>;

/// Errors returned by model download, session loading, and inference.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Hugging Face cache/download operation failed during explicit setup.
    #[error("model setup failed: {message}")]
    Setup {
        /// What setup operation failed.
        message: String,
    },
    /// Cache-only lookup failed because an asset is not cached.
    #[error(
        "model is not ready: {asset} for {repository} revision {revision}; run `heimdall-sandbox setup`"
    )]
    NotReady {
        /// Asset file that was not found in the cache.
        asset: String,
        /// Hugging Face model repository.
        repository: String,
        /// Pinned model revision.
        revision: String,
    },
    /// ONNX Runtime session loading or inference failed.
    #[error("ONNX Runtime failed: {0}")]
    Onnx(String),
    /// ONNX model inputs/outputs do not match what the caller requires.
    #[error("model schema mismatch: {detail}")]
    Schema {
        /// Description of the schema mismatch.
        detail: String,
    },
    /// Caller-supplied input cannot be processed.
    #[error("invalid model input: {detail}")]
    InvalidInput {
        /// Description of the invalid input.
        detail: String,
    },
}
