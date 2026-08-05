//! Linux bubblewrap sandbox planning and filesystem policy materialization.

mod launcher;
mod plan;
mod policy;
mod virtual_files;

use thiserror::Error as ThisError;

pub use plan::{BubblewrapPlan, BubblewrapRequest};

/// Result type for Linux sandbox operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by Linux sandbox planning and policy materialization.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Shared sandbox policy is invalid or materialization failed.
    #[error("sandbox misconfiguration: {0}")]
    SandboxPolicy(#[source] heimdall_sandbox_policy::Error),
    /// Sandbox policy or platform setup is invalid for reasons not covered by shared policy errors.
    #[error("sandbox misconfiguration: {message}")]
    Platform {
        /// Description of the platform misconfiguration.
        message: String,
    },
}

impl Error {
    /// Construct a platform sandbox misconfiguration error.
    #[must_use]
    pub fn sandbox_misconfiguration(message: impl Into<String>) -> Self {
        Self::Platform {
            message: message.into(),
        }
    }
}

impl From<heimdall_sandbox_policy::Error> for Error {
    fn from(error: heimdall_sandbox_policy::Error) -> Self {
        Self::SandboxPolicy(error)
    }
}
