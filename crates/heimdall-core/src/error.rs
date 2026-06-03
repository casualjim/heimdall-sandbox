use std::path::PathBuf;

use thiserror::Error as ThisError;

/// Exit code used when the sandbox cannot be configured safely.
pub const SANDBOX_MISCONFIGURATION_EXIT_CODE: i32 = 2;

/// Errors returned by sandbox runtime operations.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Command argv was empty.
    #[error("missing command")]
    MissingCommand,
    /// Requested child working directory is not an existing directory.
    #[error("invalid cwd: {0}")]
    InvalidCwd(PathBuf),
    /// Process hardening failed.
    #[error("sandbox hardening failed: {0}")]
    Hardening(#[source] std::io::Error),
    /// Child process spawning failed.
    #[error("failed to spawn child command: {0}")]
    Spawn(#[source] std::io::Error),
    /// Waiting for the child process failed.
    #[error("failed to wait for child command: {0}")]
    Wait(#[source] std::io::Error),
    /// Shared sandbox policy is invalid.
    #[error(transparent)]
    SandboxPolicy(#[from] heimdall_sandbox_policy::Error),
    /// Linux sandbox planning failed.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    LinuxSandbox(#[from] heimdall_linux_sandbox::Error),
    /// macOS sandbox planning failed.
    #[cfg(target_os = "macos")]
    #[error(transparent)]
    MacosSandbox(#[from] heimdall_macos_sandbox::Error),
    /// MicroVM sandbox execution failed.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[error(transparent)]
    MicrovmSandbox(#[from] heimdall_microvm_sandbox::Error),
    /// Sandbox policy or platform setup is invalid.
    #[error("sandbox misconfiguration: {0}")]
    SandboxMisconfiguration(String),
}

impl Error {
    /// Construct a missing command error.
    #[must_use]
    pub const fn missing_command() -> Self {
        Self::MissingCommand
    }

    /// Construct an invalid cwd error from the rejected path.
    #[must_use]
    pub fn invalid_cwd(cwd: PathBuf) -> Self {
        Self::InvalidCwd(cwd)
    }

    /// Wrap a process hardening I/O error.
    #[must_use]
    pub fn hardening(error: std::io::Error) -> Self {
        Self::Hardening(error)
    }

    /// Wrap a child spawn I/O error.
    #[must_use]
    pub fn spawn(error: std::io::Error) -> Self {
        Self::Spawn(error)
    }

    /// Construct a sandbox misconfiguration error with a descriptive message.
    #[must_use]
    pub fn sandbox_misconfiguration(message: impl Into<String>) -> Self {
        Self::SandboxMisconfiguration(message.into())
    }

    /// Return the documented process exit code for this error.
    ///
    /// All sandbox errors currently map to [`SANDBOX_MISCONFIGURATION_EXIT_CODE`].
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::MissingCommand
            | Self::InvalidCwd(_)
            | Self::Hardening(_)
            | Self::Spawn(_)
            | Self::Wait(_)
            | Self::SandboxPolicy(_)
            | Self::SandboxMisconfiguration(_) => SANDBOX_MISCONFIGURATION_EXIT_CODE,
            #[cfg(target_os = "linux")]
            Self::LinuxSandbox(_) => SANDBOX_MISCONFIGURATION_EXIT_CODE,
            #[cfg(target_os = "macos")]
            Self::MacosSandbox(_) => SANDBOX_MISCONFIGURATION_EXIT_CODE,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::MicrovmSandbox(_) => SANDBOX_MISCONFIGURATION_EXIT_CODE,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn runtime_errors_map_to_documented_exit_codes() {
        assert_eq!(
            Error::missing_command().exit_code(),
            SANDBOX_MISCONFIGURATION_EXIT_CODE
        );
        assert_eq!(
            Error::invalid_cwd(PathBuf::from("missing")).exit_code(),
            SANDBOX_MISCONFIGURATION_EXIT_CODE
        );
        assert_eq!(
            Error::hardening(io::Error::other("failed")).exit_code(),
            SANDBOX_MISCONFIGURATION_EXIT_CODE
        );
        assert_eq!(
            Error::spawn(io::Error::other("failed")).exit_code(),
            SANDBOX_MISCONFIGURATION_EXIT_CODE
        );
    }
}
