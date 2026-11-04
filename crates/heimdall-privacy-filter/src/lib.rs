//! OpenAI privacy-filter setup and local ONNX inference support.
//!
//! The crate owns the privacy-filter asset list, tokenization contract, token
//! offset mapping, BIOES/Viterbi decoding, and full-text redaction primitives.
//! Model download, ONNX Runtime sessions, and token window planning come from
//! `heimdall-model-runtime`.

mod input;
mod model;
mod output;
mod redaction;
mod runtime;
mod setup;

#[cfg(test)]
mod testutil;

use std::result::Result as StdResult;

use heimdall_model_runtime::Error as RuntimeError;
use thiserror::Error as ThisError;
use tokenizers::Error as TokenizerError;

// --- public API ---

pub use model::{DEFAULT_MODEL_REVISION, PrivacyFilterConfig, PrivacyFilterVariant};
pub use redaction::{CapturedTextRedaction, redact_captured_text, redact_text};
pub use runtime::PrivacyFilterRuntime;
pub use setup::{SetupRequest, setup_privacy_filter};

/// Result type for privacy-filter operations.
pub type Result<T, E = Error> = StdResult<T, E>;

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
    /// Runtime rejected because privacy filtering is disabled in configuration.
    #[error("privacy filter is disabled")]
    Disabled,
    /// Tokenizer loading or encoding failed.
    #[error("privacy filter tokenizer failed: {0}")]
    Tokenizer(String),
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
    /// Model download, cache lookup, session loading, or inference failed.
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    /// I/O failed while reading setup assets or writing redacted output.
    #[error("privacy filter I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parsing or serialization failed.
    #[error("privacy filter JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<TokenizerError> for Error {
    fn from(error: TokenizerError) -> Self {
        Self::Tokenizer(error.to_string())
    }
}
