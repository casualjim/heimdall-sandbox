//! Reusable sandbox runtime behavior.

mod child;
mod environment;
mod error;
mod executor;
mod outcome;
mod request;
#[cfg(unix)]
mod signal;

pub use error::{Error, SANDBOX_MISCONFIGURATION_EXIT_CODE};
pub use executor::Executor;

/// Apply the Landlock read-rejection universe planned by the Linux sandbox.
#[cfg(target_os = "linux")]
pub use heimdall_linux_sandbox::restrict_fs_read_universe;
pub use heimdall_sandbox_policy::{
    AgentPolicy, FilesystemPolicy, NetworkMode, ProcMode, validate_filesystem_policy,
};
pub use request::{EnvPolicy, ExecRequest, StdioPolicy, validate_cwd};

/// Result type for sandbox runtime operations.
pub type Result<T> = std::result::Result<T, Error>;
