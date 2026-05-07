use std::path::{Path, PathBuf};

use heimdall_sandbox_policy::{
    FilesystemPolicy, NetworkMode, ProcMode, validate_filesystem_policy,
};

use crate::{Error, Result};

/// Child stdio handling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioPolicy {
    /// Inherit stdin, stdout, and stderr from the sandbox process.
    Inherit,
    /// Null stdin and pipe stdout/stderr.
    Piped,
}

/// Child environment filtering policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvPolicy {
    /// Pass only explicitly allowed parent environment variables.
    Allowlist,
    /// Pass parent environment variables except explicitly denied keys.
    Blocklist,
}

/// Structured child execution request independent from CLI parsing.
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
}

impl ExecRequest {
    /// Create a validated execution request.
    ///
    /// # Errors
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
        })
    }

    /// Return a copy of this request using the provided stdio policy.
    #[must_use]
    pub const fn with_stdio_policy(mut self, stdio_policy: StdioPolicy) -> Self {
        self.stdio_policy = stdio_policy;
        self
    }

    /// Return a copy of this request using the provided environment policy and denied keys.
    #[must_use]
    pub fn with_env_policy(mut self, env_policy: EnvPolicy, denied_env: Vec<String>) -> Self {
        self.env_policy = env_policy;
        self.denied_env = denied_env;
        self
    }

    /// Return a copy of this request using the provided allowed and denied environment keys.
    #[must_use]
    pub fn with_env(mut self, allowed_env: Vec<String>, denied_env: Vec<String>) -> Self {
        self.allowed_env = allowed_env;
        self.denied_env = denied_env;
        self.env_policy = EnvPolicy::Allowlist;
        self
    }

    /// Return a copy of this request using the provided network mode.
    #[must_use]
    pub const fn with_network_mode(mut self, network_mode: NetworkMode) -> Self {
        self.network_mode = network_mode;
        self
    }

    /// Return a copy of this request using the provided filesystem policy.
    ///
    /// # Errors
    ///
    /// Returns an error when filesystem policy validation fails.
    pub fn with_filesystem_policy(mut self, filesystem_policy: FilesystemPolicy) -> Result<Self> {
        validate_filesystem_policy(&filesystem_policy)?;
        self.filesystem_policy = filesystem_policy;
        Ok(self)
    }

    /// Return a copy of this request using the provided proc mount policy.
    #[must_use]
    pub const fn with_proc_mode(mut self, proc_mode: ProcMode) -> Self {
        self.proc_mode = proc_mode;
        self
    }

    /// Return true when this request needs OS-level isolation.
    #[must_use]
    pub fn needs_isolation(&self) -> bool {
        self.network_mode == NetworkMode::None || !self.filesystem_policy.is_empty()
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
}

/// Validate a child working directory.
///
/// # Errors
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
