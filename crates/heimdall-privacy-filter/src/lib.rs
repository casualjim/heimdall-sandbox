//! OpenAI privacy-filter setup and local ONNX inference support.
//!
//! The crate owns model asset metadata, direct `ort` session execution, token
//! offset mapping, BIOES/Viterbi decoding, and full-text redaction
//! primitives. It intentionally depends on `ort` directly rather than through a
//! thin ONNX wrapper crate so Heimdall can adopt `ort` fixes without waiting on
//! another crate's release cadence.

mod input;
mod model;
mod output;
mod redaction;
mod runtime;
mod session;
mod setup;

#[cfg(test)]
mod testutil;

use std::sync::OnceLock;

use thiserror::Error as ThisError;

static ORT_INIT_RESULT: OnceLock<std::result::Result<(), String>> = OnceLock::new();

#[small_ctor::ctor]
unsafe fn init_onnx_runtime() {
    let result = ort::init()
        .with_name("heimdall-privacy-filter")
        .commit()
        .then_some(())
        .ok_or_else(|| "ONNX Runtime environment was already initialized".to_string());
    let _ = ORT_INIT_RESULT.set(result);
}

fn ensure_ort_initialized() -> Result<()> {
    match ORT_INIT_RESULT.get() {
        Some(Ok(())) => Ok(()),
        Some(Err(error)) => Err(Error::Onnx(error.clone())),
        None => Err(Error::Onnx(
            "ONNX Runtime initialization did not run".to_string(),
        )),
    }
}

// --- public API ---

pub use model::{
    DEFAULT_MODEL_REVISION, PrivacyExecutionProvider, PrivacyFilterConfig, PrivacyFilterVariant,
};
pub use redaction::{CapturedTextRedaction, redact_captured_text, redact_text};
pub use runtime::PrivacyFilterRuntime;
pub use setup::{SetupRequest, setup_privacy_filter};

/// Result type for privacy-filter operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by privacy-filter setup, loading, inference, and decoding.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Required model asset is missing from the cache or setup output.
    #[error("privacy filter asset missing: {asset}")]
    MissingAsset {
        /// Name of the missing asset file.
        asset: String,
    },
    /// A model/config/tokenizer file was present but invalid.
    #[error("privacy filter asset invalid: {detail}")]
    InvalidAsset {
        /// Description of the validation failure.
        detail: String,
    },
    /// Hugging Face cache/download operation failed during explicit setup.
    #[error("privacy filter setup failed: {message}")]
    Setup {
        /// What setup operation failed.
        message: String,
    },
    /// Runtime cache-only loading failed because assets are not cached.
    #[error(
        "privacy filter runtime is not ready: {asset} for {repository} revision {revision}; run `heimdall-sandbox setup`"
    )]
    NotReady {
        /// Asset file that was not found in the cache.
        asset: String,
        /// Hugging Face model repository.
        repository: String,
        /// Pinned model revision.
        revision: String,
    },
    /// Runtime rejected because privacy filtering is disabled in configuration.
    #[error("privacy filter is disabled")]
    Disabled,
    /// Tokenizer loading or encoding failed.
    #[error("privacy filter tokenizer failed: {0}")]
    Tokenizer(String),
    /// ONNX Runtime session loading or inference failed.
    #[error("privacy filter ONNX Runtime failed: {0}")]
    Onnx(String),
    /// ONNX model inputs/outputs are incompatible with the OpenAI privacy-filter contract.
    #[error("privacy filter model schema mismatch: {detail}")]
    Schema {
        /// Description of the schema mismatch.
        detail: String,
    },
    /// Logit output or label metadata could not be decoded.
    #[error("privacy filter decode failed: {detail}")]
    Decode {
        /// Description of the decode failure.
        detail: String,
    },
    /// I/O failed while reading setup assets or writing redacted output.
    #[error("privacy filter I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parsing or serialization failed.
    #[error("privacy filter JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<tokenizers::Error> for Error {
    fn from(error: tokenizers::Error) -> Self {
        Self::Tokenizer(error.to_string())
    }
}
