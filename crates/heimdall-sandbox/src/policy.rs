//! Policy document types, validation, and conversion helpers.

use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::ValueEnum;
use heimdall_core::{
    AgentPolicy, EnvPolicy, ExecRequest, FilesystemPolicy, MicrovmGuest, MicrovmImage, MicrovmInit,
    MicrovmLifecycle, MicrovmPolicy, MicrovmResources, MicrovmSecret, NetworkMode, ProcMode,
    PullPolicy, RlimitResource, RlimitSpec, RuntimeMode, SecretHostPattern, SecurityProfile,
    StdioPolicy,
};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::error::{Error, Result};

use crate::commands::exec::ExecArgs;
use crate::commands::inner_exec::InnerExecArgs;

/// CLI runtime policy mirrored from core [`RuntimeMode`](heimdall_core::RuntimeMode).
///
/// Used in CLI argument parsing and JSON policy documents.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum CliRuntimeMode {
    /// Use the current platform sandbox backend.
    Platform,
    /// Use the microsandbox microVM backend.
    Microvm,
}

impl std::fmt::Display for CliRuntimeMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Platform => formatter.write_str("platform"),
            Self::Microvm => formatter.write_str("microvm"),
        }
    }
}

impl From<CliRuntimeMode> for RuntimeMode {
    fn from(mode: CliRuntimeMode) -> Self {
        match mode {
            CliRuntimeMode::Platform => Self::Platform,
            CliRuntimeMode::Microvm => Self::Microvm,
        }
    }
}

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
    pub(crate) runtime: Option<CliRuntimeMode>,
    pub(crate) image: Option<String>,
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
    /// Allow `SSH_AUTH_SOCK` when OS isolation is used.
    #[serde(rename = "sshAgent")]
    pub(crate) ssh_agent: Option<bool>,
    /// Allow GnuPG agent, keyboxd, and dirmngr sockets when OS isolation is used.
    #[serde(rename = "gpgAgent")]
    pub(crate) gpg_agent: Option<bool>,
    /// Allow age-compatible agent sockets when OS isolation is used.
    #[serde(rename = "ageAgent")]
    pub(crate) age_agent: Option<bool>,
    /// MicroVM-only policy. Applies only when `runtime` is `microvm`.
    pub(crate) microvm: Option<PolicyMicrovm>,
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

/// MicroVM-only policy in a [`PolicyDocument`]. Applies only when `runtime` is `microvm`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PolicyMicrovm {
    /// Resource limits.
    pub(crate) resources: Option<PolicyMicrovmResources>,
    /// Lifecycle timeouts.
    pub(crate) lifecycle: Option<PolicyMicrovmLifecycle>,
    /// Guest identity and boot configuration.
    pub(crate) guest: Option<PolicyMicrovmGuest>,
    /// Secrets injected via the TLS proxy with host-allowlist gating.
    pub(crate) secrets: Option<Vec<PolicyMicrovmSecret>>,
    /// Image pull and snapshot pinning.
    pub(crate) image: Option<PolicyMicrovmImage>,
    /// In-guest security profile.
    pub(crate) security: Option<PolicyMicrovmSecurityProfile>,
}

/// Resource limits for a [`PolicyMicrovm`].
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PolicyMicrovmResources {
    pub(crate) cpus: Option<u8>,
    /// Guest memory in mebibytes.
    pub(crate) memory: Option<u32>,
    /// Writable overlay upper size in mebibytes (OCI images only).
    pub(crate) upper_size: Option<u32>,
    pub(crate) rlimits: Option<Vec<PolicyMicrovmRlimit>>,
}

/// Lifecycle timeouts for a [`PolicyMicrovm`].
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PolicyMicrovmLifecycle {
    /// Maximum sandbox lifetime in seconds.
    pub(crate) max_duration: Option<u64>,
    /// Auto-stop after this many seconds of inactivity.
    pub(crate) idle_timeout: Option<u64>,
}

/// Guest identity and boot configuration for a [`PolicyMicrovm`].
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PolicyMicrovmGuest {
    pub(crate) user: Option<String>,
    pub(crate) hostname: Option<String>,
    pub(crate) shell: Option<String>,
    pub(crate) entrypoint: Option<Vec<String>>,
    pub(crate) init: Option<PolicyMicrovmInit>,
}

/// PID 1 init handoff for a [`PolicyMicrovmGuest`].
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PolicyMicrovmInit {
    /// Init binary path or the literal `"auto"`.
    pub(crate) cmd: String,
    pub(crate) args: Option<Vec<String>>,
    pub(crate) env: Option<Vec<(String, String)>>,
}

/// A secret injected via the TLS proxy.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PolicyMicrovmSecret {
    pub(crate) env_var: String,
    pub(crate) value: String,
    pub(crate) allowed_hosts: Vec<PolicySecretHostPattern>,
}

/// Host pattern for secret allowlisting.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PolicySecretHostPattern {
    /// Exact hostname match.
    Exact { host: String },
    /// Wildcard match (e.g., `*.openai.com`).
    Wildcard { pattern: String },
    /// Any host (dangerous: secret can be exfiltrated).
    Any,
}

/// Image pull and snapshot pinning for a [`PolicyMicrovm`].
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PolicyMicrovmImage {
    pub(crate) pull_policy: Option<PolicyPullPolicy>,
    /// Snapshot artifact path or bare name (mutually exclusive with `image`).
    pub(crate) snapshot: Option<String>,
}

/// OCI image pull policy.
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyPullPolicy {
    IfMissing,
    Always,
    Never,
}

/// In-guest security profile.
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyMicrovmSecurityProfile {
    Default,
    Restricted,
}

/// A POSIX resource limit.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PolicyMicrovmRlimit {
    pub(crate) resource: PolicyRlimitResource,
    pub(crate) soft: u64,
    pub(crate) hard: u64,
}

/// POSIX resource limit identifier.
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyRlimitResource {
    Cpu,
    Fsize,
    Data,
    Stack,
    Core,
    Rss,
    Nproc,
    Nofile,
    Memlock,
    As,
    Locks,
    Sigpending,
    Msgqueue,
    Nice,
    Rtprio,
    Rttime,
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
                | "runtime"
                | "image"
                | "enabled"
                | "network"
                | "proc"
                | "filesystem"
                | "env"
                | "stdio"
                | "sshAgent"
                | "gpgAgent"
                | "ageAgent"
                | "microvm"
        ) {
            return Err(Error::policy(format!("unknown policy field: {key}")));
        }
    }
    Ok(())
}

/// Convert a parsed policy document into a core execution request.
pub fn policy_document_request(policy: PolicyDocument) -> Result<ExecRequest> {
    policy_document_request_with_runtime(policy, None)
}

/// Convert a parsed policy document into a core execution request with an optional runtime override.
pub fn policy_document_request_with_runtime(
    policy: PolicyDocument,
    runtime_override: Option<CliRuntimeMode>,
) -> Result<ExecRequest> {
    let PolicyDocument {
        cwd,
        command,
        runtime,
        image,
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
    let effective_runtime = runtime_override
        .or(runtime)
        .unwrap_or(CliRuntimeMode::Platform);
    let microvm_policy = microvm_policy_from(sandbox.microvm.as_ref())?;
    let request = ExecRequest::new(cwd, command, allowed_env).map(|request| {
        request
            .with_env_policy(env_policy, denied_env)
            .with_runtime_mode(effective_runtime.into())
            .with_stdio_policy(stdio.unwrap_or(CliStdioPolicy::Inherit).into())
            .with_network_mode(network_mode)
            .with_proc_mode(proc_mode)
            .with_agent_policy(agent_policy)
    });
    // Runtime/image cross-field validation. A snapshot pins the image, so it
    // satisfies the microvm image requirement and is mutually exclusive with an
    // explicit image reference. The microvm-only policy block is accepted under
    // any runtime: the platform backends warn and ignore knobs they cannot honor.
    let has_snapshot = microvm_policy.image().snapshot().is_some();
    let request = match (effective_runtime, image, has_snapshot) {
        (CliRuntimeMode::Microvm, Some(image), false) if !image.is_empty() => {
            request.map(|request| request.with_microvm_image(image))
        }
        (CliRuntimeMode::Microvm, Some(image), true) if !image.is_empty() => {
            Err(heimdall_core::Error::sandbox_misconfiguration(
                "policy image is mutually exclusive with microvm.image.snapshot",
            ))
        }
        (CliRuntimeMode::Microvm, _, true) => request,
        (CliRuntimeMode::Microvm, _, false) => Err(heimdall_core::Error::sandbox_misconfiguration(
            "microvm runtime requires non-empty policy image or microvm.image.snapshot",
        )),
        // Platform runtime ignores the image reference and the microvm-only
        // policy block; the executor warns about knobs it cannot honor.
        (CliRuntimeMode::Platform, Some(image), _) if !image.is_empty() => {
            request.map(|request| request.with_microvm_image(image))
        }
        (CliRuntimeMode::Platform, _, _) => request,
    };
    let request = request.and_then(|request| request.with_microvm_policy(microvm_policy));
    request
        .and_then(|request| request.with_filesystem_policy(filesystem_policy))
        .map_err(|error| Error::policy(error.to_string()))
}

/// Convert a [`PolicyMicrovm`] into a core [`MicrovmPolicy`].
///
/// Returns the default (empty) policy when `config` is `None`.
fn microvm_policy_from(config: Option<&PolicyMicrovm>) -> Result<MicrovmPolicy> {
    let Some(config) = config else {
        return Ok(MicrovmPolicy::default());
    };
    let resources = config
        .resources
        .as_ref()
        .map(|resources| {
            MicrovmResources::new(
                resources.cpus,
                resources.memory,
                resources.upper_size,
                resources
                    .rlimits
                    .as_ref()
                    .map(|rlimits| {
                        rlimits
                            .iter()
                            .map(|rlimit| {
                                RlimitSpec::new(
                                    map_rlimit_resource(rlimit.resource),
                                    rlimit.soft,
                                    rlimit.hard,
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    let lifecycle = config
        .lifecycle
        .as_ref()
        .map(|lifecycle| MicrovmLifecycle::new(lifecycle.max_duration, lifecycle.idle_timeout))
        .unwrap_or_default();
    let guest = config
        .guest
        .as_ref()
        .map(|guest| {
            MicrovmGuest::new(
                guest.user.clone(),
                guest.hostname.clone(),
                guest.shell.clone(),
                guest.entrypoint.clone(),
                guest.init.as_ref().map(|init| {
                    MicrovmInit::new(
                        init.cmd.clone(),
                        init.args.clone().unwrap_or_default(),
                        init.env.clone().unwrap_or_default(),
                    )
                }),
            )
        })
        .unwrap_or_default();
    let secrets = config
        .secrets
        .as_ref()
        .map(|secrets| {
            secrets
                .iter()
                .map(|secret| {
                    MicrovmSecret::new(
                        secret.env_var.clone(),
                        secret.value.clone(),
                        secret
                            .allowed_hosts
                            .iter()
                            .cloned()
                            .map(map_host_pattern)
                            .collect(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let image = config
        .image
        .as_ref()
        .map(|image| {
            MicrovmImage::new(
                image.pull_policy.map(map_pull_policy),
                image.snapshot.clone(),
            )
        })
        .unwrap_or_default();
    let security_profile = config.security.map(map_security_profile);
    Ok(MicrovmPolicy::new(
        resources,
        lifecycle,
        guest,
        secrets,
        image,
        security_profile,
    ))
}

/// Map a [`PolicyPullPolicy`] to a core [`PullPolicy`].
fn map_pull_policy(policy: PolicyPullPolicy) -> PullPolicy {
    match policy {
        PolicyPullPolicy::IfMissing => PullPolicy::IfMissing,
        PolicyPullPolicy::Always => PullPolicy::Always,
        PolicyPullPolicy::Never => PullPolicy::Never,
    }
}

/// Map a [`PolicyMicrovmSecurityProfile`] to a core [`SecurityProfile`].
fn map_security_profile(profile: PolicyMicrovmSecurityProfile) -> SecurityProfile {
    match profile {
        PolicyMicrovmSecurityProfile::Default => SecurityProfile::Default,
        PolicyMicrovmSecurityProfile::Restricted => SecurityProfile::Restricted,
    }
}

/// Map a [`PolicyRlimitResource`] to a core [`RlimitResource`].
fn map_rlimit_resource(resource: PolicyRlimitResource) -> RlimitResource {
    match resource {
        PolicyRlimitResource::Cpu => RlimitResource::Cpu,
        PolicyRlimitResource::Fsize => RlimitResource::Fsize,
        PolicyRlimitResource::Data => RlimitResource::Data,
        PolicyRlimitResource::Stack => RlimitResource::Stack,
        PolicyRlimitResource::Core => RlimitResource::Core,
        PolicyRlimitResource::Rss => RlimitResource::Rss,
        PolicyRlimitResource::Nproc => RlimitResource::Nproc,
        PolicyRlimitResource::Nofile => RlimitResource::Nofile,
        PolicyRlimitResource::Memlock => RlimitResource::Memlock,
        PolicyRlimitResource::As => RlimitResource::As,
        PolicyRlimitResource::Locks => RlimitResource::Locks,
        PolicyRlimitResource::Sigpending => RlimitResource::Sigpending,
        PolicyRlimitResource::Msgqueue => RlimitResource::Msgqueue,
        PolicyRlimitResource::Nice => RlimitResource::Nice,
        PolicyRlimitResource::Rtprio => RlimitResource::Rtprio,
        PolicyRlimitResource::Rttime => RlimitResource::Rttime,
    }
}

/// Map a [`PolicySecretHostPattern`] to a core [`SecretHostPattern`].
fn map_host_pattern(pattern: PolicySecretHostPattern) -> SecretHostPattern {
    match pattern {
        PolicySecretHostPattern::Exact { host } => SecretHostPattern::Exact(host),
        PolicySecretHostPattern::Wildcard { pattern } => SecretHostPattern::Wildcard(pattern),
        PolicySecretHostPattern::Any => SecretHostPattern::Any,
    }
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
        return policy_document_request_with_runtime(read_policy_document(&policy)?, args.runtime);
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
    let runtime = args.runtime.unwrap_or(CliRuntimeMode::Platform);
    if runtime == CliRuntimeMode::Microvm {
        return Err(Error::arguments(
            "--runtime microvm requires --policy with non-empty image",
        ));
    }
    ExecRequest::new(cwd, args.command, args.allow_env)
        .map(|request| {
            request
                .with_env_policy(env_policy, args.deny_env)
                .with_runtime_mode(runtime.into())
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use heimdall_core::{AgentPolicy, EnvPolicy, ProcMode, RuntimeMode, StdioPolicy};

    use super::*;

    #[test]
    fn policy_document_with_allow_and_deny_uses_allowlist_with_deny_override() {
        let request = policy_document_request(PolicyDocument {
            cwd: Some(PathBuf::from(".")),
            command: vec!["printf".to_string(), "hello".to_string()],
            runtime: None,
            image: None,
            sandbox: SandboxConfig {
                env: Some(PolicyEnvironment {
                    allow: Some(vec!["PATH".to_string(), "SECRET".to_string()]),
                    deny: Some(vec!["SECRET".to_string()]),
                }),
                ..SandboxConfig::default()
            },
            stdio: Some(CliStdioPolicy::Piped),
        })
        .expect("policy converts");

        assert_eq!(request.env_policy(), EnvPolicy::Allowlist);
        assert_eq!(request.allowed_env(), ["PATH", "SECRET"]);
        assert_eq!(request.denied_env(), ["SECRET"]);
        assert_eq!(request.stdio_policy(), StdioPolicy::Piped);
    }

    #[test]
    fn policy_document_without_allow_uses_blocklist() {
        let request = policy_document_request(PolicyDocument {
            cwd: Some(PathBuf::from(".")),
            command: vec!["printf".to_string(), "hello".to_string()],
            runtime: None,
            image: None,
            sandbox: SandboxConfig {
                env: Some(PolicyEnvironment {
                    allow: None,
                    deny: Some(vec!["SECRET".to_string()]),
                }),
                ..SandboxConfig::default()
            },
            stdio: None,
        })
        .expect("policy converts");

        assert_eq!(request.env_policy(), EnvPolicy::Blocklist);
        assert_eq!(request.denied_env(), ["SECRET"]);
        assert_eq!(request.stdio_policy(), StdioPolicy::Inherit);
    }

    #[test]
    fn policy_document_accepts_shared_sandbox_config_shape() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "enabled": true,
              "network": "host",
              "cwd": ".",
              "command": ["printf", "hello"],
              "env": { "allow": ["PATH"], "deny": null },
              "stdio": "piped"
            }"#,
        )
        .expect("shared policy JSON parses");

        let request = policy_document_request(policy).expect("policy converts");

        assert_eq!(request.env_policy(), EnvPolicy::Allowlist);
        assert_eq!(request.allowed_env(), ["PATH"]);
        assert!(request.denied_env().is_empty());
        assert_eq!(request.stdio_policy(), StdioPolicy::Piped);
    }

    #[test]
    fn policy_document_accepts_microvm_runtime() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "runtime": "microvm",
              "image": "alpine",
              "cwd": ".",
              "command": ["printf", "hello"]
            }"#,
        )
        .expect("policy JSON parses");

        let request = policy_document_request(policy).expect("runtime converts");

        assert_eq!(request.runtime_mode(), RuntimeMode::Microvm);
        assert_eq!(request.microvm_image(), Some("alpine"));
    }

    #[test]
    fn policy_document_rejects_microvm_runtime_without_image() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "runtime": "microvm",
              "cwd": ".",
              "command": ["printf", "hello"]
            }"#,
        )
        .expect("policy JSON parses");

        let error = policy_document_request(policy).expect_err("microvm image is required");

        assert!(
            error
                .to_string()
                .contains("requires non-empty policy image")
        );
    }

    #[test]
    fn cli_runtime_overrides_policy_runtime() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "runtime": "platform",
              "image": "alpine",
              "cwd": ".",
              "command": ["printf", "hello"]
            }"#,
        )
        .expect("policy JSON parses");

        let request = policy_document_request_with_runtime(policy, Some(CliRuntimeMode::Microvm))
            .expect("runtime override converts");

        assert_eq!(request.runtime_mode(), RuntimeMode::Microvm);
        assert_eq!(request.microvm_image(), Some("alpine"));
    }

    #[test]
    fn cli_platform_override_accepts_policy_image_with_warning() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "runtime": "microvm",
              "image": "alpine",
              "cwd": ".",
              "command": ["printf", "hello"]
            }"#,
        )
        .expect("policy JSON parses");

        // Platform runtime ignores the image reference (warns at exec time);
        // config conversion no longer rejects it.
        let request = policy_document_request_with_runtime(policy, Some(CliRuntimeMode::Platform))
            .expect("platform runtime accepts image");

        assert_eq!(request.runtime_mode(), RuntimeMode::Platform);
        assert_eq!(request.microvm_image(), Some("alpine"));
    }

    #[test]
    fn policy_document_accepts_no_proc_mode() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "proc": "none",
              "cwd": ".",
              "command": ["printf", "hello"]
            }"#,
        )
        .expect("policy JSON parses");

        let request = policy_document_request(policy).expect("proc mode converts");

        assert_eq!(request.proc_mode(), ProcMode::Disabled);
    }

    #[test]
    fn policy_document_accepts_agent_socket_opt_ins() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "gpgAgent": true,
              "sshAgent": true,
              "ageAgent": false,
              "cwd": ".",
              "command": ["printf", "hello"]
            }"#,
        )
        .expect("policy JSON parses");

        let request = policy_document_request(policy).expect("agent policy converts");

        assert_eq!(request.agent_policy(), AgentPolicy::new(true, true, false));
        assert!(request.needs_isolation());
    }

    #[test]
    fn policy_document_accepts_network_isolation() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "network": "none",
              "cwd": ".",
              "command": ["printf", "hello"]
            }"#,
        )
        .expect("policy JSON parses");

        let request = policy_document_request(policy).expect("network isolation converts");

        assert_eq!(request.network_mode(), heimdall_core::NetworkMode::None);
        assert!(request.needs_isolation());
    }

    #[test]
    fn policy_document_accepts_filesystem_policy() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "cwd": ".",
              "command": ["printf", "hello"],
              "filesystem": {
                "deny": ["**/.env*", "!**/.env.example"],
                "writable": ["src/**"],
                "virtual": { "/etc/passwd": "nobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n" }
              }
            }"#,
        )
        .expect("policy JSON parses");

        let request = policy_document_request(policy).expect("filesystem isolation converts");

        assert_eq!(
            request.filesystem_policy().deny(),
            ["**/.env*", "!**/.env.example"]
        );
        assert_eq!(request.filesystem_policy().writable(), ["src/**"]);
        assert!(
            request
                .filesystem_policy()
                .virtual_files()
                .contains_key(&PathBuf::from("/etc/passwd"))
        );
        assert!(request.needs_isolation());
    }

    #[test]
    fn policy_document_accepts_omitted_filesystem_fields() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "cwd": ".",
              "command": ["printf", "hello"],
              "filesystem": {}
            }"#,
        )
        .expect("policy JSON parses");

        let request = policy_document_request(policy).expect("empty filesystem converts");

        assert!(request.filesystem_policy().is_empty());
    }

    #[test]
    fn policy_document_rejects_relative_virtual_path() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "cwd": ".",
              "command": ["printf", "hello"],
              "filesystem": { "virtual": { "etc/passwd": "content" } }
            }"#,
        )
        .expect("policy JSON parses");

        let error = policy_document_request(policy).expect_err("relative virtual path is rejected");

        assert!(error.to_string().contains("filesystem.virtual"));
        assert!(error.to_string().contains("must be absolute"));
    }

    #[test]
    fn policy_schema_has_expected_shape() {
        let schema = serde_json::to_value(schemars::schema_for!(PolicyDocument))
            .expect("policy schema serializes");

        assert_eq!(schema["additionalProperties"], false);
        assert!(schema["required"].as_array().is_some_and(|required| {
            required
                .iter()
                .any(|field| field.as_str() == Some("command"))
        }));
        assert!(schema["properties"].get("filesystem").is_some());
        assert!(schema["properties"].get("runtime").is_some());
        assert!(schema["properties"].get("image").is_some());
        assert!(schema["properties"].get("gpgAgent").is_some());
        assert!(schema["properties"].get("sshAgent").is_some());
        assert!(schema["properties"].get("ageAgent").is_some());
        assert_eq!(
            schema["$defs"]["PolicyFilesystem"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["$defs"]["PolicyEnvironment"]["additionalProperties"],
            false
        );
    }

    #[test]
    fn policy_document_rejects_unknown_fields() {
        let value = serde_json::from_str::<serde_json::Value>(
            r#"{
              "cwd": ".",
              "command": ["printf", "hello"],
              "bogus": true
            }"#,
        )
        .expect("policy JSON parses");

        let error = reject_unknown_policy_fields(&value).expect_err("unknown field is rejected");

        assert!(error.to_string().contains("unknown policy field: bogus"));
    }

    #[test]
    fn policy_document_accepts_microvm_resources_and_user() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "runtime": "microvm",
              "image": "alpine",
              "cwd": ".",
              "command": ["printf", "hello"],
              "microvm": {
                "resources": { "cpus": 2, "memory": 512, "upper_size": 256 },
                "guest": { "user": "appuser", "hostname": "worker" },
                "image": { "pull_policy": "always" },
                "security": "restricted"
              }
            }"#,
        )
        .expect("policy JSON parses");

        let request = policy_document_request(policy).expect("microvm policy converts");

        assert_eq!(request.runtime_mode(), RuntimeMode::Microvm);
        assert_eq!(request.microvm_policy().resources().cpus(), Some(2));
        assert_eq!(request.microvm_policy().resources().memory_mib(), Some(512));
        assert_eq!(
            request.microvm_policy().resources().upper_size_mib(),
            Some(256)
        );
        assert_eq!(request.microvm_policy().guest().user(), Some("appuser"));
        assert_eq!(request.microvm_policy().guest().hostname(), Some("worker"));
        assert_eq!(
            request.microvm_policy().security_profile(),
            Some(heimdall_core::SecurityProfile::Restricted)
        );
        assert_eq!(
            request.microvm_policy().image().pull_policy(),
            Some(heimdall_core::PullPolicy::Always)
        );
    }

    #[test]
    fn policy_document_accepts_microvm_secret() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "runtime": "microvm",
              "image": "alpine",
              "cwd": ".",
              "command": ["printf", "hello"],
              "microvm": {
                "secrets": [
                  {
                    "env_var": "OPENAI_API_KEY",
                    "value": "sk-test",
                    "allowed_hosts": [
                      { "kind": "exact", "host": "api.openai.com" },
                      { "kind": "wildcard", "pattern": "*.openai.com" }
                    ]
                  }
                ]
              }
            }"#,
        )
        .expect("policy JSON parses");

        let request = policy_document_request(policy).expect("secret policy converts");

        let secrets = request.microvm_policy().secrets();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].env_var(), "OPENAI_API_KEY");
        assert_eq!(secrets[0].value(), "sk-test");
        assert_eq!(secrets[0].allowed_hosts().len(), 2);
    }

    #[test]
    fn policy_document_accepts_microvm_snapshot_without_image() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "runtime": "microvm",
              "cwd": ".",
              "command": ["printf", "hello"],
              "microvm": { "image": { "snapshot": "pinned-v1" } }
            }"#,
        )
        .expect("policy JSON parses");

        let request = policy_document_request(policy).expect("snapshot satisfies image");

        assert_eq!(request.runtime_mode(), RuntimeMode::Microvm);
        assert_eq!(request.microvm_image(), None);
        assert_eq!(
            request.microvm_policy().image().snapshot(),
            Some("pinned-v1")
        );
    }

    #[test]
    fn policy_document_rejects_snapshot_with_image() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "runtime": "microvm",
              "image": "alpine",
              "cwd": ".",
              "command": ["printf", "hello"],
              "microvm": { "image": { "snapshot": "pinned-v1" } }
            }"#,
        )
        .expect("policy JSON parses");

        let error = policy_document_request(policy).expect_err("snapshot+image rejects");

        assert!(error.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn policy_document_accepts_microvm_policy_under_platform_runtime() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "cwd": ".",
              "command": ["printf", "hello"],
              "microvm": { "resources": { "cpus": 2 } }
            }"#,
        )
        .expect("policy JSON parses");

        // Platform runtime carries the microvm-only policy; the platform backend
        // warns and ignores knobs it cannot honor instead of rejecting config.
        let request = policy_document_request(policy).expect("platform+microvm accepts");

        assert_eq!(request.runtime_mode(), RuntimeMode::Platform);
        assert_eq!(request.microvm_policy().resources().cpus(), Some(2));
    }

    #[test]
    fn policy_document_rejects_microvm_without_image_or_snapshot() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "runtime": "microvm",
              "cwd": ".",
              "command": ["printf", "hello"],
              "microvm": { "resources": { "cpus": 2 } }
            }"#,
        )
        .expect("policy JSON parses");

        let error = policy_document_request(policy).expect_err("microvm without image rejects");

        assert!(error.to_string().contains("non-empty policy image"));
    }

    #[test]
    fn policy_document_rejects_microvm_zero_cpus() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "runtime": "microvm",
              "image": "alpine",
              "cwd": ".",
              "command": ["printf", "hello"],
              "microvm": { "resources": { "cpus": 0 } }
            }"#,
        )
        .expect("policy JSON parses");

        let error = policy_document_request(policy).expect_err("zero cpus rejects");

        assert!(error.to_string().contains("cpus"));
    }

    #[test]
    fn policy_document_accepts_microvm_rlimit() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "runtime": "microvm",
              "image": "alpine",
              "cwd": ".",
              "command": ["printf", "hello"],
              "microvm": {
                "resources": {
                  "rlimits": [{ "resource": "nofile", "soft": 1024, "hard": 2048 }]
                }
              }
            }"#,
        )
        .expect("policy JSON parses");

        let request = policy_document_request(policy).expect("rlimit policy converts");

        let rlimits = request.microvm_policy().resources().rlimits();
        assert_eq!(rlimits.len(), 1);
        assert_eq!(rlimits[0].resource(), heimdall_core::RlimitResource::Nofile);
        assert_eq!(rlimits[0].soft(), 1024);
        assert_eq!(rlimits[0].hard(), 2048);
    }
}
