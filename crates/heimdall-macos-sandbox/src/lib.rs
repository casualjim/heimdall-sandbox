//! macOS Seatbelt sandbox planning.

mod builder;
mod paths;
mod plan;
mod request;

use thiserror::Error as ThisError;

/// Absolute path to the macOS Seatbelt launcher.
pub const SEATBELT_EXECUTABLE: &str = "/usr/bin/sandbox-exec";

const BASE_POLICY: &str = include_str!("seatbelt_base_policy.sbpl");

const PLATFORM_DEFAULTS: &str = include_str!("restricted_read_only_platform_defaults.sbpl");

const NETWORK_SUPPORT_POLICY: &str = include_str!("seatbelt_network_policy.sbpl");

const GPG_RUNTIME_SOCKET_NAMES: &[&str] = &[
    "S.gpg-agent",
    "S.gpg-agent.extra",
    "S.gpg-agent.ssh",
    "S.gpg-agent.browser",
    "S.keyboxd",
    "S.dirmngr",
];

const GPGCONF_SOCKET_KEYS: &[&str] = &[
    "agent-socket",
    "agent-ssh-socket",
    "agent-extra-socket",
    "agent-browser-socket",
    "keyboxd-socket",
    "dirmngr-socket",
];

/// Result type for macOS sandbox operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by macOS sandbox planning.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Shared sandbox policy materialization failed.
    #[error(transparent)]
    Policy(#[from] heimdall_sandbox_policy::Error),
    /// A required platform directory path could not be resolved.
    #[error("failed to resolve platform directory: {message}")]
    PlatformDirectory {
        /// Description of the missing directory.
        message: String,
    },
    /// Agent socket discovery failed.
    #[error("failed to discover agent runtime paths: {message}")]
    AgentDiscovery {
        /// Discovery failure details.
        message: String,
    },
}

pub use plan::SeatbeltPlan;
pub use request::SeatbeltRequest;
