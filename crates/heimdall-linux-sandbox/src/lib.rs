//! Linux bubblewrap sandbox planning and filesystem policy materialization.

mod launcher;
mod plan;
mod policy;
mod virtual_files;

use thiserror::Error as ThisError;

pub use plan::{BubblewrapPlan, BubblewrapRequest};
pub use policy::validate_filesystem_policy;
pub use policy::{FilesystemPolicy, NetworkMode, ProcMode};

/// Result type for Linux sandbox operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by Linux sandbox planning and policy materialization.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Sandbox policy or platform setup is invalid.
    #[error("sandbox misconfiguration: {0}")]
    SandboxMisconfiguration(String),
}

impl Error {
    /// Construct a sandbox misconfiguration error.
    #[must_use]
    pub fn sandbox_misconfiguration(message: impl Into<String>) -> Self {
        Self::SandboxMisconfiguration(message.into())
    }
}

impl From<heimdall_sandbox_policy::Error> for Error {
    fn from(error: heimdall_sandbox_policy::Error) -> Self {
        Self::sandbox_misconfiguration(error.to_string())
    }
}
