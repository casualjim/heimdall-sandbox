//! Microsandbox microVM sandbox execution backend.

mod environment;
mod naming;
mod preflight;
mod request;

use std::path::PathBuf;

use thiserror::Error as ThisError;

pub use request::MicrovmRequest;

/// Result type for microVM sandbox operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by microVM sandbox planning and execution.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Sandbox policy cannot be represented by the microVM backend.
    #[error("sandbox misconfiguration: {message}")]
    UnsupportedPolicy {
        /// Description of unsupported policy surface.
        message: String,
    },
    /// Host platform or dependency setup cannot run microsandbox safely.
    #[error("sandbox misconfiguration: {message}")]
    Platform {
        /// Description of platform/dependency misconfiguration.
        message: String,
    },
    /// Microsandbox SDK operation failed.
    #[error("sandbox misconfiguration: microsandbox failed: {0}")]
    Microsandbox(#[source] microsandbox::MicrosandboxError),
    /// Tokio runtime setup failed.
    #[error("sandbox misconfiguration: failed to create microvm async runtime: {0}")]
    Runtime(#[source] std::io::Error),
    /// Host path resolution failed.
    #[error("sandbox misconfiguration: failed to resolve microvm cwd {path}: {source}")]
    Cwd {
        /// Rejected cwd path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// Captured output forwarding failed.
    #[error("sandbox misconfiguration: failed to forward microvm output: {0}")]
    Output(#[source] std::io::Error),
}

impl Error {
    /// Construct an unsupported-policy error.
    #[must_use]
    pub fn unsupported_policy(message: impl Into<String>) -> Self {
        Self::UnsupportedPolicy {
            message: message.into(),
        }
    }

    /// Construct a platform/dependency misconfiguration error.
    #[must_use]
    pub fn platform(message: impl Into<String>) -> Self {
        Self::Platform {
            message: message.into(),
        }
    }
}

impl From<microsandbox::MicrosandboxError> for Error {
    fn from(error: microsandbox::MicrosandboxError) -> Self {
        Self::Microsandbox(error)
    }
}
