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
pub use executor::execute;
pub use request::{EnvPolicy, ExecRequest, StdioPolicy, validate_cwd};

/// Result type for sandbox runtime operations.
pub type Result<T> = std::result::Result<T, Error>;
