//! Reusable sandbox runtime behavior.

mod child;
mod environment;
mod error;
mod executor;
mod executor_warn;
mod outcome;
mod request;
#[cfg(unix)]
mod signal;

pub use error::{Error, SANDBOX_MISCONFIGURATION_EXIT_CODE};
pub use executor::Executor;
pub use heimdall_sandbox_policy::{
    AgentPolicy, FilesystemPolicy, MicrovmGuest, MicrovmImage, MicrovmInit, MicrovmLifecycle,
    MicrovmPolicy, MicrovmResources, MicrovmSecret, NetworkMode, ProcMode, PullPolicy,
    RlimitResource, RlimitSpec, SecretHostPattern, SecurityProfile, validate_filesystem_policy,
    validate_microvm_policy,
};
pub use request::{EnvPolicy, ExecRequest, RuntimeMode, StdioPolicy, validate_cwd};

/// Result type for sandbox runtime operations.
pub type Result<T> = std::result::Result<T, Error>;
