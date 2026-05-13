//! CLI error type for heimdall-sandbox.

use thiserror::Error as ThisError;

/// Errors returned by heimdall-sandbox CLI operations.
#[derive(Debug, ThisError)]
pub enum Error {
    /// A policy document is syntactically or semantically invalid.
    #[error("invalid policy: {0}")]
    Policy(String),
    /// A CLI argument or argument combination is invalid.
    #[error("{0}")]
    Arguments(String),
    /// A required path could not be resolved or expanded.
    #[error("path error: {0}")]
    Path(String),
    /// An I/O operation failed.
    #[error("{message}: {source}")]
    Io {
        /// Description of the I/O operation.
        message: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A JSON serialization or deserialization operation failed.
    #[error("{message}: {source}")]
    Json {
        /// Description of the JSON operation.
        message: String,
        /// Underlying JSON error.
        #[source]
        source: serde_json::Error,
    },
}

impl Error {
    /// Construct a policy error.
    #[must_use]
    pub fn policy(message: impl Into<String>) -> Self {
        Self::Policy(message.into())
    }

    /// Construct an arguments error.
    #[must_use]
    pub fn arguments(message: impl Into<String>) -> Self {
        Self::Arguments(message.into())
    }

    /// Construct a path error.
    #[must_use]
    pub fn path(message: impl Into<String>) -> Self {
        Self::Path(message.into())
    }

    /// Construct an I/O error with context.
    #[must_use]
    pub fn io(message: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            message: message.into(),
            source,
        }
    }

    /// Construct a JSON error with context.
    #[must_use]
    pub fn json(message: impl Into<String>, source: serde_json::Error) -> Self {
        Self::Json {
            message: message.into(),
            source,
        }
    }
}

/// Result type for heimdall-sandbox CLI operations.
pub type Result<T> = std::result::Result<T, Error>;
