use std::path::{Path, PathBuf};

use heimdall_sandbox_policy::{
    AgentPolicy, FilesystemPolicy, NetworkMode, ProcMode, validate_filesystem_policy,
};

use crate::{Error, Result};

/// Child stdio handling policy.
///
/// Controls how stdin, stdout, and stderr are connected between the sandbox
/// parent process and the sandboxed child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioPolicy {
    /// Inherit stdin, stdout, and stderr from the sandbox process.
    Inherit,
    /// Null stdin and pipe stdout/stderr.
    Piped,
}

impl std::str::FromStr for StdioPolicy {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "inherit" => Ok(Self::Inherit),
            "piped" => Ok(Self::Piped),
            _ => Err(format!("unknown stdio policy: {s}")),
        }
    }
}

impl std::fmt::Display for StdioPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inherit => formatter.write_str("inherit"),
            Self::Piped => formatter.write_str("piped"),
        }
    }
}

/// Child environment filtering policy.
///
/// Determines which parent environment variables are inherited by the sandboxed
/// child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvPolicy {
    /// Pass only explicitly allowed parent environment variables.
    Allowlist,
    /// Pass parent environment variables except explicitly denied keys.
    Blocklist,
}

impl std::str::FromStr for EnvPolicy {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "allowlist" => Ok(Self::Allowlist),
            "blocklist" => Ok(Self::Blocklist),
            _ => Err(format!("unknown env policy: {s}")),
        }
    }
}

impl std::fmt::Display for EnvPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allowlist => formatter.write_str("allowlist"),
            Self::Blocklist => formatter.write_str("blocklist"),
        }
    }
}

/// Structured child execution request independent from CLI parsing.
///
/// Built via `new` followed by builder methods. Validates that the working
/// directory exists and that a command is provided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    cwd: PathBuf,
    argv: Vec<String>,
    allowed_env: Vec<String>,
    denied_env: Vec<String>,
    env_policy: EnvPolicy,
    stdio_policy: StdioPolicy,
    network_mode: NetworkMode,
    filesystem_policy: FilesystemPolicy,
    proc_mode: ProcMode,
    agent_policy: AgentPolicy,
}

impl ExecRequest {
    /// Create a validated execution request.
    ///
    /// Returns [`Error::MissingCommand`] when `argv` is empty and
    /// [`Error::InvalidCwd`] when `cwd` is not an existing directory.
    pub fn new(
        cwd: impl Into<PathBuf>,
        argv: Vec<String>,
        allowed_env: Vec<String>,
    ) -> Result<Self> {
        if argv.is_empty() {
            return Err(Error::MissingCommand);
        }

        let cwd = cwd.into();
        validate_cwd(&cwd)?;

        Ok(Self {
            cwd,
            argv,
            allowed_env,
            denied_env: Vec::new(),
            env_policy: EnvPolicy::Allowlist,
            stdio_policy: StdioPolicy::Inherit,
            network_mode: NetworkMode::Host,
            filesystem_policy: FilesystemPolicy::default(),
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        })
    }

    /// Set the child stdio handling policy.
    #[must_use]
    pub const fn with_stdio_policy(mut self, stdio_policy: StdioPolicy) -> Self {
        self.stdio_policy = stdio_policy;
        self
    }

    /// Set the environment policy and denied keys.
    #[must_use]
    pub fn with_env_policy(mut self, env_policy: EnvPolicy, denied_env: Vec<String>) -> Self {
        self.env_policy = env_policy;
        self.denied_env = denied_env;
        self
    }

    /// Set both allowed and denied environment keys.
    ///
    /// Sets the policy to [`EnvPolicy::Allowlist`].
    #[must_use]
    pub fn with_env(mut self, allowed_env: Vec<String>, denied_env: Vec<String>) -> Self {
        self.allowed_env = allowed_env;
        self.denied_env = denied_env;
        self.env_policy = EnvPolicy::Allowlist;
        self
    }

    /// Set the child network isolation mode.
    #[must_use]
    pub const fn with_network_mode(mut self, network_mode: NetworkMode) -> Self {
        self.network_mode = network_mode;
        self
    }

    /// Set the filesystem sandbox policy.
    ///
    /// Returns an error when filesystem policy validation fails.
    pub fn with_filesystem_policy(mut self, filesystem_policy: FilesystemPolicy) -> Result<Self> {
        validate_filesystem_policy(&filesystem_policy)?;
        self.filesystem_policy = filesystem_policy;
        Ok(self)
    }

    /// Set the `/proc` mount policy.
    #[must_use]
    pub const fn with_proc_mode(mut self, proc_mode: ProcMode) -> Self {
        self.proc_mode = proc_mode;
        self
    }

    /// Set the host agent socket mount policy.
    #[must_use]
    pub const fn with_agent_policy(mut self, agent_policy: AgentPolicy) -> Self {
        self.agent_policy = agent_policy;
        self
    }

    /// Whether this request needs OS-level isolation.
    ///
    /// Returns `true` when network isolation is requested or filesystem policy is non-empty.
    #[must_use]
    pub fn needs_isolation(&self) -> bool {
        self.network_mode == NetworkMode::None
            || !self.filesystem_policy.is_empty()
            || !self.agent_policy.is_empty()
    }

    /// Child working directory.
    #[must_use]
    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    /// Child command argv, including program name at index zero.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// Parent environment keys allowed in the child environment.
    #[must_use]
    pub fn allowed_env(&self) -> &[String] {
        &self.allowed_env
    }

    /// Parent environment keys denied in blocklist mode.
    #[must_use]
    pub fn denied_env(&self) -> &[String] {
        &self.denied_env
    }

    /// Child environment filtering policy.
    #[must_use]
    pub const fn env_policy(&self) -> EnvPolicy {
        self.env_policy
    }

    /// Child stdio handling policy.
    #[must_use]
    pub const fn stdio_policy(&self) -> StdioPolicy {
        self.stdio_policy
    }

    /// Child network isolation policy.
    #[must_use]
    pub const fn network_mode(&self) -> NetworkMode {
        self.network_mode
    }

    /// Filesystem sandbox policy.
    #[must_use]
    pub const fn filesystem_policy(&self) -> &FilesystemPolicy {
        &self.filesystem_policy
    }

    /// Proc filesystem mount policy.
    #[must_use]
    pub const fn proc_mode(&self) -> ProcMode {
        self.proc_mode
    }

    /// Host agent socket mount policy.
    #[must_use]
    pub const fn agent_policy(&self) -> AgentPolicy {
        self.agent_policy
    }
}

/// Validate a child working directory.
///
/// Returns [`Error::InvalidCwd`] when the path is not an existing directory.
pub fn validate_cwd(cwd: &Path) -> Result<()> {
    if cwd.is_dir() {
        Ok(())
    } else {
        Err(Error::InvalidCwd(cwd.to_path_buf()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn request_accepts_valid_cwd_and_command() {
        let request = ExecRequest::new(
            std::env::current_dir().expect("current dir exists"),
            vec!["printf".into(), "hello".into()],
            vec!["PATH".into()],
        )
        .expect("valid request is accepted");

        assert_eq!(request.argv(), ["printf", "hello"]);
        assert_eq!(request.allowed_env(), ["PATH"]);
        assert_eq!(request.stdio_policy(), StdioPolicy::Inherit);
    }

    #[test]
    fn request_accepts_piped_stdio_policy() {
        let request = ExecRequest::new(
            std::env::current_dir().expect("current dir exists"),
            vec!["printf".into(), "hello".into()],
            vec!["PATH".into()],
        )
        .expect("valid request is accepted")
        .with_stdio_policy(StdioPolicy::Piped);

        assert_eq!(request.stdio_policy(), StdioPolicy::Piped);
    }

    #[test]
    fn request_rejects_missing_command() {
        let error = ExecRequest::new(
            std::env::current_dir().expect("current dir exists"),
            Vec::<String>::new(),
            Vec::<String>::new(),
        )
        .expect_err("empty command is rejected");

        assert_eq!(error.exit_code(), crate::SANDBOX_MISCONFIGURATION_EXIT_CODE);
    }

    #[test]
    fn request_rejects_invalid_cwd() {
        let error = ExecRequest::new(
            PathBuf::from("/definitely/not/a/heimdall/sandbox/path"),
            vec!["true".into()],
            Vec::<String>::new(),
        )
        .expect_err("invalid cwd is rejected");

        assert_eq!(error.exit_code(), crate::SANDBOX_MISCONFIGURATION_EXIT_CODE);
    }

    #[test]
    fn request_rejects_invalid_filesystem_policy() {
        let request = ExecRequest::new(
            std::env::current_dir().expect("current dir exists"),
            vec!["true".into()],
            Vec::<String>::new(),
        )
        .expect("valid request is accepted");
        let filesystem_policy = FilesystemPolicy::new(
            Vec::new(),
            Vec::new(),
            BTreeMap::from([(PathBuf::from("etc/passwd"), "content".to_string())]),
        );

        let error = request
            .with_filesystem_policy(filesystem_policy)
            .expect_err("relative virtual path is rejected");

        assert_eq!(error.exit_code(), crate::SANDBOX_MISCONFIGURATION_EXIT_CODE);
    }
}
