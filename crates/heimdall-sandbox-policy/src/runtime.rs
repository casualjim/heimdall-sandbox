//! Runtime-level sandbox policy enums and agent socket policy.

use std::fmt;

/// Child network isolation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Preserve host networking.
    Host,
    /// Isolate host networking.
    None,
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host => formatter.write_str("host"),
            Self::None => formatter.write_str("none"),
        }
    }
}

/// Child proc filesystem mount policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcMode {
    /// Mount `/proc` when host preflight allows it.
    Default,
    /// Do not mount `/proc` inside the sandbox.
    Disabled,
}

impl fmt::Display for ProcMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => formatter.write_str("default"),
            Self::Disabled => formatter.write_str("disabled"),
        }
    }
}

/// Host agent socket mount policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgentPolicy {
    ssh_agent: bool,
    gpg_agent: bool,
    age_agent: bool,
}

impl AgentPolicy {
    /// Create an agent policy from boolean feature toggles.
    #[must_use]
    pub const fn new(ssh_agent: bool, gpg_agent: bool, age_agent: bool) -> Self {
        Self {
            ssh_agent,
            gpg_agent,
            age_agent,
        }
    }

    /// Return true when no host agent sockets are enabled.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        !self.ssh_agent && !self.gpg_agent && !self.age_agent
    }

    /// Whether `SSH_AUTH_SOCK` should be mounted.
    #[must_use]
    pub const fn ssh_agent(&self) -> bool {
        self.ssh_agent
    }

    /// Whether GnuPG agent, keyboxd, and dirmngr sockets should be mounted.
    #[must_use]
    pub const fn gpg_agent(&self) -> bool {
        self.gpg_agent
    }

    /// Whether age-compatible agent sockets should be mounted.
    #[must_use]
    pub const fn age_agent(&self) -> bool {
        self.age_agent
    }
}
