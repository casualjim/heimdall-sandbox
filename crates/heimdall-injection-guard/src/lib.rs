//! Prompt-injection detection and redaction.
//!
//! The crate scores text with a prompt-injection classifier (Galvanize-3 by
//! default) and reports which spans of the input were flagged, so callers can
//! block or redact tool output before it reaches an LLM. Model download, ONNX
//! Runtime sessions, and token window planning come from
//! `heimdall-model-runtime`.

mod model;
mod runtime;
mod scan;
mod setup;
mod text;

use std::result::Result as StdResult;

use heimdall_model_runtime::Error as RuntimeError;
use ndarray::ShapeError;
use thiserror::Error as ThisError;
use tokenizers::Error as TokenizerError;

pub use model::{DEFAULT_MODEL_REVISION, InjectionGuardConfig, MODEL_REPOSITORY};
pub use runtime::InjectionGuardRuntime;
pub use scan::InjectionScan;
pub use setup::{SetupReport, setup_injection_guard};

/// Result type for injection-guard operations.
pub type Result<T, E = Error> = StdResult<T, E>;

/// Errors returned by injection-guard setup, loading, and scanning.
#[derive(Debug, ThisError)]
pub enum Error {
    /// A model/tokenizer/thresholds file was present but invalid.
    #[error("injection guard asset invalid: {detail}")]
    InvalidAsset {
        /// Description of the validation failure.
        detail: String,
    },
    /// Tokenizer loading or encoding failed.
    #[error("injection guard tokenizer failed: {0}")]
    Tokenizer(String),
    /// ONNX model inputs/outputs are incompatible with the injection classifier contract.
    #[error("injection guard model schema mismatch: {detail}")]
    Schema {
        /// Description of the schema mismatch.
        detail: String,
    },
    /// Model output could not be decoded into a score.
    #[error("injection guard decode failed: {detail}")]
    Decode {
        /// Description of the decode failure.
        detail: String,
    },
    /// Model download, cache lookup, session loading, or inference failed.
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    /// I/O failed while reading cached assets.
    #[error("injection guard I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parsing failed.
    #[error("injection guard JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<TokenizerError> for Error {
    fn from(error: TokenizerError) -> Self {
        Self::Tokenizer(error.to_string())
    }
}

impl From<ShapeError> for Error {
    fn from(error: ShapeError) -> Self {
        Self::Decode {
            detail: format!("tensor shape error: {error}"),
        }
    }
}
