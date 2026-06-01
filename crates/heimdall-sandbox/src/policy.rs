//! Policy document types, validation, and conversion helpers.

use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::ValueEnum;
use heimdall_core::{
    AgentPolicy, EnvPolicy, ExecRequest, FilesystemPolicy, NetworkMode, ProcMode, StdioPolicy,
};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::error::{Error, Result};

use crate::commands::exec::ExecArgs;
use crate::commands::inner_exec::InnerExecArgs;

/// CLI stdio policy mirrored from core [`StdioPolicy`](heimdall_core::StdioPolicy).
///
/// Used in CLI argument parsing and JSON policy documents.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum CliStdioPolicy {
    /// Inherit stdin, stdout, and stderr from the sandbox process.
    Inherit,
    /// Null stdin and pipe stdout/stderr.
    Piped,
}

impl std::fmt::Display for CliStdioPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inherit => formatter.write_str("inherit"),
            Self::Piped => formatter.write_str("piped"),
        }
    }
}

impl From<CliStdioPolicy> for StdioPolicy {
    fn from(policy: CliStdioPolicy) -> Self {
        match policy {
            CliStdioPolicy::Inherit => Self::Inherit,
            CliStdioPolicy::Piped => Self::Piped,
        }
    }
}

/// Top-level JSON policy document accepted by `exec --policy`.
///
/// Unknown fields are rejected at both the JSON and schemars level.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PolicyDocument {
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) command: Vec<String>,
    #[serde(flatten)]
    pub(crate) sandbox: SandboxConfig,
    pub(crate) stdio: Option<CliStdioPolicy>,
}

/// Sandbox configuration embedded in a [`PolicyDocument`].
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct SandboxConfig {
    /// Explicit opt-in flag (currently must be absent or `true`).
    pub(crate) enabled: Option<bool>,
    /// Network isolation mode.
    pub(crate) network: Option<SandboxNetwork>,
    /// `/proc` mounting mode.
    pub(crate) proc: Option<SandboxProc>,
    /// Filesystem sandboxing rules.
    pub(crate) filesystem: Option<PolicyFilesystem>,
    /// Environment variable filtering rules.
    pub(crate) env: Option<PolicyEnvironment>,
    /// Mount `SSH_AUTH_SOCK` when Linux isolation is used.
    #[serde(rename = "sshAgent")]
    pub(crate) ssh_agent: Option<bool>,
    /// Mount GnuPG agent, keyboxd, and dirmngr sockets when Linux isolation is used.
    #[serde(rename = "gpgAgent")]
    pub(crate) gpg_agent: Option<bool>,
    /// Mount age-compatible agent sockets when Linux isolation is used.
    #[serde(rename = "ageAgent")]
    pub(crate) age_agent: Option<bool>,
}

/// Network isolation mode in a [`PolicyDocument`].
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxNetwork {
    Host,
    None,
}

/// `/proc` mounting mode in a [`PolicyDocument`].
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxProc {
    Default,
    None,
}

/// Filesystem sandboxing configuration in a [`PolicyDocument`].
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PolicyFilesystem {
    pub(crate) deny: Option<Vec<String>>,
    pub(crate) writable: Option<Vec<String>>,
    #[serde(rename = "virtual")]
    pub(crate) virtual_files: Option<BTreeMap<PathBuf, String>>,
}

/// Environment variable policy in a [`PolicyDocument`].
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PolicyEnvironment {
    pub(crate) allow: Option<Vec<String>>,
    pub(crate) deny: Option<Vec<String>>,
}

/// Read a [`PolicyDocument`] from a file path or stdin (`-`)..
pub fn read_policy_document(policy: &str) -> Result<PolicyDocument> {
    use std::io::Read;

    let json = if policy == "-" {
        let mut json = String::new();
        std::io::stdin()
            .read_to_string(&mut json)
            .map_err(|source| Error::io("failed to read policy from stdin", source))?;
        json
    } else {
        let policy_path = expand_path(PathBuf::from(policy))?;
        std::fs::read_to_string(&policy_path).map_err(|source| {
            Error::io(
                format!("failed to read policy {}", policy_path.display()),
                source,
            )
        })?
    };
    let value = serde_json::from_str::<serde_json::Value>(&json)
        .map_err(|error| Error::policy(format!("failed to parse policy JSON: {error}")))?;
    reject_unknown_policy_fields(&value)?;
    serde_json::from_value(value)
        .map_err(|error| Error::policy(format!("failed to parse policy JSON: {error}")))
}

/// Reject unknown top-level fields in a policy JSON value.
///
/// This supplements serde's `deny_unknown_fields` by checking before deserialization
/// to produce a more helpful error message.
pub fn reject_unknown_policy_fields(value: &serde_json::Value) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| Error::policy("policy JSON must be an object"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "cwd"
                | "command"
                | "enabled"
                | "network"
                | "proc"
                | "filesystem"
                | "env"
                | "stdio"
                | "sshAgent"
                | "gpgAgent"
                | "ageAgent"
        ) {
            return Err(Error::policy(format!("unknown policy field: {key}")));
        }
    }
    Ok(())
}

/// Convert a parsed policy document into a core execution request.
pub fn policy_document_request(policy: PolicyDocument) -> Result<ExecRequest> {
    let PolicyDocument {
        cwd,
        command,
        sandbox,
        stdio,
    } = policy;
    let (network_mode, proc_mode, filesystem_policy, agent_policy) =
        validate_sandbox_config(&sandbox)?;

    let env = sandbox.env.unwrap_or(PolicyEnvironment {
        allow: None,
        deny: None,
    });
    let denied_env = env.deny.unwrap_or_default();
    let (env_policy, allowed_env) = match env.allow {
        Some(allowed_env) => (EnvPolicy::Allowlist, allowed_env),
        None => (EnvPolicy::Blocklist, Vec::new()),
    };
    let cwd = match cwd {
        Some(cwd) => expand_path(cwd)?,
        None => current_directory()?,
    };
    ExecRequest::new(cwd, command, allowed_env)
        .map(|request| {
            request
                .with_env_policy(env_policy, denied_env)
                .with_stdio_policy(stdio.unwrap_or(CliStdioPolicy::Inherit).into())
                .with_network_mode(network_mode)
                .with_proc_mode(proc_mode)
                .with_agent_policy(agent_policy)
        })
        .and_then(|request| request.with_filesystem_policy(filesystem_policy))
        .map_err(|error| Error::policy(error.to_string()))
}

/// Expand shell variables and `~` in a path.
pub fn expand_path(path: PathBuf) -> Result<PathBuf> {
    let Some(path) = path.to_str() else {
        return Ok(path);
    };
    shellexpand::full(path)
        .map(|expanded| PathBuf::from(expanded.into_owned()))
        .map_err(|error| Error::path(format!("failed to expand path {path:?}: {error}")))
}

/// Return the current working directory.
///
/// # Errors
///
/// Returns an error when the current directory cannot be determined.
pub fn current_directory() -> Result<PathBuf> {
    std::env::current_dir()
        .map_err(|error| Error::path(format!("failed to determine current directory: {error}")))
}

pub(crate) fn validate_sandbox_config(
    config: &SandboxConfig,
) -> Result<(NetworkMode, ProcMode, FilesystemPolicy, AgentPolicy)> {
    if config.enabled == Some(false) {
        return Err(Error::arguments(
            "policy enabled=false is not supported by heimdall-sandbox exec",
        ));
    }

    let network_mode = match config.network {
        Some(SandboxNetwork::None) => NetworkMode::None,
        Some(SandboxNetwork::Host) | None => NetworkMode::Host,
    };
    let proc_mode = match config.proc {
        Some(SandboxProc::None) => ProcMode::Disabled,
        Some(SandboxProc::Default) | None => ProcMode::Default,
    };
    let filesystem_policy = filesystem_policy(config.filesystem.as_ref())?;
    let agent_policy = AgentPolicy::new(
        config.ssh_agent.unwrap_or(false),
        config.gpg_agent.unwrap_or(false),
        config.age_agent.unwrap_or(false),
    );

    Ok((network_mode, proc_mode, filesystem_policy, agent_policy))
}

pub(crate) fn filesystem_policy(filesystem: Option<&PolicyFilesystem>) -> Result<FilesystemPolicy> {
    let Some(filesystem) = filesystem else {
        return Ok(FilesystemPolicy::default());
    };
    Ok(FilesystemPolicy::new(
        filesystem.deny.clone().unwrap_or_default(),
        filesystem.writable.clone().unwrap_or_default(),
        filesystem.virtual_files.clone().unwrap_or_default(),
    ))
}

/// Convert an `ExecArgs` into a core `ExecRequest`.
///
/// When `--deny-env` is omitted and `--allow-env` is empty, the env policy defaults to
/// `Allowlist` with an empty allowlist, meaning no parent environment variables are
/// inherited. This is the safest default for sandboxed execution.
pub fn exec_args_to_request(args: ExecArgs) -> Result<ExecRequest> {
    if let Some(policy) = args.policy {
        if args.cwd.is_some()
            || !args.allow_env.is_empty()
            || !args.deny_env.is_empty()
            || args.stdio != CliStdioPolicy::Inherit
            || args.no_proc
            || !args.command.is_empty()
        {
            return Err(Error::arguments(
                "--policy cannot be combined with direct exec arguments",
            ));
        }
        return policy_document_request(read_policy_document(&policy)?);
    }

    let cwd = match args.cwd {
        Some(cwd) => expand_path(cwd)?,
        None => current_directory()?,
    };
    if args.command.is_empty() {
        return Err(Error::arguments("missing command"));
    }
    let env_policy = if args.deny_env.is_empty() {
        EnvPolicy::Allowlist
    } else {
        EnvPolicy::Blocklist
    };
    ExecRequest::new(cwd, args.command, args.allow_env)
        .map(|request| {
            request
                .with_env_policy(env_policy, args.deny_env)
                .with_stdio_policy(args.stdio.into())
                .with_proc_mode(if args.no_proc {
                    ProcMode::Disabled
                } else {
                    ProcMode::Default
                })
        })
        .map_err(|error| Error::arguments(error.to_string()))
}

/// Convert `InnerExecArgs` into a core `ExecRequest`.
pub fn inner_exec_args_to_request(args: InnerExecArgs) -> Result<ExecRequest> {
    if args.command.is_empty() {
        return Err(Error::arguments("missing command"));
    }
    ExecRequest::new(expand_path(args.cwd)?, args.command, Vec::new())
        .map(|request| {
            request
                .with_env_policy(EnvPolicy::Blocklist, Vec::new())
                .with_stdio_policy(args.stdio.into())
        })
        .map_err(|error| Error::arguments(error.to_string()))
}
