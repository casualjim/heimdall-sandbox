//! Command-line parsing for the heimdall sandbox executable.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use heimdall_core::{
    EnvPolicy, ExecRequest, Executor, FilesystemPolicy, NetworkMode, ProcMode,
    SANDBOX_MISCONFIGURATION_EXIT_CODE, StdioPolicy,
};
use schemars::{JsonSchema, schema_for};
use serde::Deserialize;

/// `heimdall-sandbox` command-line interface.
#[derive(Debug, Parser)]
#[command(
    name = "heimdall-sandbox",
    version,
    about = "Minimal Heimdall sandbox runtime"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Execute a command in the minimal sandbox runtime.
    Exec(ExecArgs),
    /// Work with JSON policy documents.
    Policy(PolicyArgs),
    /// Internal re-entry point used inside a Linux bubblewrap namespace.
    #[command(name = "__heimdall-inner-exec", hide = true)]
    InnerExec(InnerExecArgs),
}

#[derive(Debug, Parser)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommands,
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    /// Print the JSON schema for policy documents accepted by `exec --policy`.
    Schema,
    /// Validate a JSON policy document without executing it.
    Validate(PolicyValidateArgs),
}

#[derive(Debug, Parser)]
struct PolicyValidateArgs {
    /// JSON sandbox policy path, or `-` to read the policy from stdin.
    policy: String,
}

#[derive(Debug, Parser)]
struct InnerExecArgs {
    /// Child process working directory inside the namespace.
    #[arg(long)]
    cwd: PathBuf,

    /// Child process stdio handling policy.
    #[arg(long = "stdio", value_enum, default_value_t = CliStdioPolicy::Inherit)]
    stdio: CliStdioPolicy,

    /// Command argv to execute directly without shell parsing.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[derive(Debug, Parser)]
struct ExecArgs {
    /// JSON sandbox policy path, or `-` to read the policy from stdin.
    #[arg(long = "policy")]
    policy: Option<String>,

    /// Child process working directory.
    #[arg(long)]
    cwd: Option<PathBuf>,

    /// Parent environment variable key to preserve in the child process.
    #[arg(long = "allow-env")]
    allow_env: Vec<String>,

    /// Parent environment variable key to remove in blocklist mode.
    #[arg(long = "deny-env", conflicts_with = "allow_env")]
    deny_env: Vec<String>,

    /// Child process stdio handling policy.
    #[arg(long = "stdio", value_enum, default_value_t = CliStdioPolicy::Inherit)]
    stdio: CliStdioPolicy,

    /// Disable `/proc` mounting for Linux bubblewrap isolation.
    #[arg(long = "no-proc")]
    no_proc: bool,

    /// Command argv to execute directly without shell parsing.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum CliStdioPolicy {
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

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
struct PolicyDocument {
    cwd: Option<PathBuf>,
    command: Vec<String>,
    #[serde(flatten)]
    sandbox: SandboxConfig,
    stdio: Option<CliStdioPolicy>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct SandboxConfig {
    enabled: Option<bool>,
    network: Option<SandboxNetwork>,
    proc: Option<SandboxProc>,
    filesystem: Option<PolicyFilesystem>,
    env: Option<PolicyEnvironment>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
enum SandboxNetwork {
    Host,
    None,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
enum SandboxProc {
    Default,
    None,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
struct PolicyFilesystem {
    deny: Option<Vec<String>>,
    writable: Option<Vec<String>>,
    #[serde(rename = "virtual")]
    virtual_files: Option<BTreeMap<PathBuf, String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
struct PolicyEnvironment {
    allow: Option<Vec<String>>,
    deny: Option<Vec<String>>,
}

impl Cli {
    /// Parse CLI args from the process environment.
    #[must_use]
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Convert a parsed CLI invocation into a core execution request.
    ///
    /// # Errors
    ///
    /// Returns an error when parsing, policy loading, or core request validation fails.
    pub fn into_exec_request(self) -> std::result::Result<ExecRequest, String> {
        match self.command {
            Commands::Exec(args) => args.into_exec_request(),
            Commands::Policy(_) => {
                Err("policy commands do not create execution requests".to_string())
            }
            Commands::InnerExec(args) => args.into_exec_request(),
        }
    }
}

fn run_policy_command(args: PolicyArgs) -> std::result::Result<(), String> {
    match args.command {
        PolicyCommands::Schema => print_policy_schema(),
        PolicyCommands::Validate(args) => validate_policy_document(&args.policy),
    }
}

fn print_policy_schema() -> std::result::Result<(), String> {
    let schema = schema_for!(PolicyDocument);
    let json = serde_json::to_string_pretty(&schema)
        .map_err(|error| format!("failed to serialize policy schema: {error}"))?;
    println!("{json}");
    Ok(())
}

fn validate_policy_document(policy: &str) -> std::result::Result<(), String> {
    let policy = read_policy_document(policy)?;
    policy_document_request(policy).map(|_| ())
}

impl InnerExecArgs {
    fn into_exec_request(self) -> std::result::Result<ExecRequest, String> {
        if self.command.is_empty() {
            return Err("missing command".to_string());
        }
        ExecRequest::new(expand_path(self.cwd)?, self.command, Vec::new())
            .map(|request| {
                request
                    .with_env_policy(EnvPolicy::Blocklist, Vec::new())
                    .with_stdio_policy(self.stdio.into())
            })
            .map_err(|error| error.to_string())
    }
}

impl ExecArgs {
    fn into_exec_request(self) -> std::result::Result<ExecRequest, String> {
        if let Some(policy) = self.policy {
            if self.cwd.is_some()
                || !self.allow_env.is_empty()
                || !self.deny_env.is_empty()
                || self.stdio != CliStdioPolicy::Inherit
                || self.no_proc
                || !self.command.is_empty()
            {
                return Err("--policy cannot be combined with direct exec arguments".to_string());
            }
            return policy_document_request(read_policy_document(&policy)?);
        }

        let cwd = self
            .cwd
            .map(expand_path)
            .transpose()?
            .unwrap_or_else(current_directory);
        if self.command.is_empty() {
            return Err("missing command".to_string());
        }
        let env_policy = if self.deny_env.is_empty() {
            EnvPolicy::Allowlist
        } else {
            EnvPolicy::Blocklist
        };
        ExecRequest::new(cwd, self.command, self.allow_env)
            .map(|request| {
                request
                    .with_env_policy(env_policy, self.deny_env)
                    .with_stdio_policy(self.stdio.into())
                    .with_proc_mode(if self.no_proc {
                        ProcMode::Disabled
                    } else {
                        ProcMode::Default
                    })
            })
            .map_err(|error| error.to_string())
    }
}

fn current_directory() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn read_policy_document(policy: &str) -> std::result::Result<PolicyDocument, String> {
    let json = if policy == "-" {
        let mut json = String::new();
        std::io::stdin()
            .read_to_string(&mut json)
            .map_err(|error| format!("failed to read policy from stdin: {error}"))?;
        json
    } else {
        let policy_path = expand_path(PathBuf::from(policy))?;
        std::fs::read_to_string(&policy_path)
            .map_err(|error| format!("failed to read policy {}: {error}", policy_path.display()))?
    };
    let value = serde_json::from_str::<serde_json::Value>(&json)
        .map_err(|error| format!("failed to parse policy JSON: {error}"))?;
    reject_unknown_policy_fields(&value)?;
    serde_json::from_value(value).map_err(|error| format!("failed to parse policy JSON: {error}"))
}

fn reject_unknown_policy_fields(value: &serde_json::Value) -> std::result::Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "policy JSON must be an object".to_string())?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "cwd" | "command" | "enabled" | "network" | "proc" | "filesystem" | "env" | "stdio"
        ) {
            return Err(format!("unknown policy field: {key}"));
        }
    }
    Ok(())
}

fn policy_document_request(policy: PolicyDocument) -> std::result::Result<ExecRequest, String> {
    let PolicyDocument {
        cwd,
        command,
        sandbox,
        stdio,
    } = policy;
    let (network_mode, proc_mode, filesystem_policy) = validate_sandbox_config(&sandbox)?;

    let env = sandbox.env.unwrap_or(PolicyEnvironment {
        allow: None,
        deny: None,
    });
    let denied_env = env.deny.unwrap_or_default();
    let (env_policy, allowed_env) = match env.allow {
        Some(allowed_env) => (EnvPolicy::Allowlist, allowed_env),
        None => (EnvPolicy::Blocklist, Vec::new()),
    };
    let cwd = cwd
        .map(expand_path)
        .transpose()?
        .unwrap_or_else(current_directory);
    ExecRequest::new(cwd, command, allowed_env)
        .map(|request| {
            request
                .with_env_policy(env_policy, denied_env)
                .with_stdio_policy(stdio.unwrap_or(CliStdioPolicy::Inherit).into())
                .with_network_mode(network_mode)
                .with_proc_mode(proc_mode)
        })
        .and_then(|request| request.with_filesystem_policy(filesystem_policy))
        .map_err(|error| error.to_string())
}

fn validate_sandbox_config(
    config: &SandboxConfig,
) -> std::result::Result<(NetworkMode, ProcMode, FilesystemPolicy), String> {
    if config.enabled == Some(false) {
        return Err("policy enabled=false is not supported by heimdall-sandbox exec".to_string());
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

    Ok((network_mode, proc_mode, filesystem_policy))
}

fn expand_path(path: PathBuf) -> std::result::Result<PathBuf, String> {
    let Some(path) = path.to_str() else {
        return Ok(path);
    };
    shellexpand::full(path)
        .map(|expanded| PathBuf::from(expanded.into_owned()))
        .map_err(|error| format!("failed to expand path {path:?}: {error}"))
}

fn filesystem_policy(
    filesystem: Option<&PolicyFilesystem>,
) -> std::result::Result<FilesystemPolicy, String> {
    let Some(filesystem) = filesystem else {
        return Ok(FilesystemPolicy::default());
    };
    Ok(FilesystemPolicy::new(
        filesystem.deny.clone().unwrap_or_default(),
        filesystem.writable.clone().unwrap_or_default(),
        filesystem.virtual_files.clone().unwrap_or_default(),
    ))
}

/// Run the sandbox CLI and return the process exit code.
#[must_use]
pub fn run() -> i32 {
    run_cli(Cli::parse_args())
}

/// Run CLI parsing and map clap parse errors to the sandbox misconfiguration code.
#[must_use]
pub fn run_from<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    match Cli::try_parse_from(args) {
        Ok(cli) => run_cli(cli),
        Err(error) => {
            eprintln!("{error}");
            SANDBOX_MISCONFIGURATION_EXIT_CODE
        }
    }
}

fn run_cli(cli: Cli) -> i32 {
    let Cli { command } = cli;
    if let Commands::Policy(args) = command {
        return match run_policy_command(args) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("{error}");
                SANDBOX_MISCONFIGURATION_EXIT_CODE
            }
        };
    }

    if let Err(error) = heimdall_process_hardening::apply_process_hardening() {
        eprintln!("sandbox hardening failed: {error}");
        return SANDBOX_MISCONFIGURATION_EXIT_CODE;
    }

    match (Cli { command }).into_exec_request() {
        Ok(request) => match Executor.execute(&request) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("{error}");
                error.exit_code()
            }
        },
        Err(error) => {
            eprintln!("{error}");
            SANDBOX_MISCONFIGURATION_EXIT_CODE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;

    use super::*;

    #[test]
    fn parses_valid_exec_invocation() {
        let command = Cli::try_parse_from([
            "heimdall-sandbox",
            "exec",
            "--cwd",
            ".",
            "--allow-env",
            "PATH",
            "--",
            "printf",
            "hello",
        ])
        .expect("valid invocation parses");

        let request = command.into_exec_request().expect("valid request converts");

        assert_eq!(request.cwd(), PathBuf::from("."));
        assert_eq!(request.argv(), ["printf", "hello"]);
        assert_eq!(request.allowed_env(), ["PATH"]);
        assert_eq!(request.stdio_policy(), StdioPolicy::Inherit);
    }

    #[test]
    fn parses_piped_stdio_policy() {
        let command = Cli::try_parse_from([
            "heimdall-sandbox",
            "exec",
            "--cwd",
            ".",
            "--stdio",
            "piped",
            "--",
            "printf",
            "hello",
        ])
        .expect("valid invocation parses");

        let request = command.into_exec_request().expect("valid request converts");

        assert_eq!(request.stdio_policy(), StdioPolicy::Piped);
    }

    #[test]
    fn parses_deny_env_as_blocklist_policy() {
        let command = Cli::try_parse_from([
            "heimdall-sandbox",
            "exec",
            "--cwd",
            ".",
            "--deny-env",
            "SECRET",
            "--",
            "printf",
            "hello",
        ])
        .expect("valid invocation parses");

        let request = command.into_exec_request().expect("valid request converts");

        assert_eq!(request.env_policy(), EnvPolicy::Blocklist);
        assert_eq!(request.denied_env(), ["SECRET"]);
    }

    #[test]
    fn rejects_mixed_allow_env_and_deny_env() {
        let error = Cli::try_parse_from([
            "heimdall-sandbox",
            "exec",
            "--cwd",
            ".",
            "--allow-env",
            "PATH",
            "--deny-env",
            "SECRET",
            "--",
            "printf",
            "hello",
        ])
        .expect_err("allowlist and blocklist modes are mutually exclusive");

        assert!(error.to_string().contains("--allow-env"));
    }

    #[test]
    fn policy_document_with_allow_and_deny_uses_allowlist_with_deny_override() {
        let request = policy_document_request(PolicyDocument {
            cwd: Some(PathBuf::from(".")),
            command: vec!["printf".to_string(), "hello".to_string()],
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
    fn cli_accepts_no_proc_mode() {
        let command = Cli::try_parse_from([
            "heimdall-sandbox",
            "exec",
            "--cwd",
            ".",
            "--no-proc",
            "--",
            "printf",
            "hello",
        ])
        .expect("valid invocation parses");

        let request = command.into_exec_request().expect("valid request converts");

        assert_eq!(request.proc_mode(), ProcMode::Disabled);
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

        assert_eq!(request.network_mode(), NetworkMode::None);
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

        assert!(error.contains("filesystem.virtual"));
        assert!(error.contains("must be absolute"));
    }

    #[test]
    fn policy_schema_has_expected_shape() {
        let schema =
            serde_json::to_value(schema_for!(PolicyDocument)).expect("policy schema serializes");

        assert_eq!(schema["additionalProperties"], false);
        assert!(schema["required"].as_array().is_some_and(|required| {
            required
                .iter()
                .any(|field| field.as_str() == Some("command"))
        }));
        assert!(schema["properties"].get("filesystem").is_some());
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

        assert!(error.contains("unknown policy field: bogus"));
    }

    #[test]
    fn missing_cwd_defaults_to_current_directory() {
        let command = Cli::try_parse_from(["heimdall-sandbox", "exec", "--", "true"])
            .expect("syntax is valid");

        let request = command.into_exec_request().expect("request converts");

        assert_eq!(request.cwd(), current_directory());
    }

    #[test]
    fn rejects_missing_command() {
        let command = Cli::try_parse_from(["heimdall-sandbox", "exec", "--cwd", ".", "--"])
            .expect("syntax is valid");

        let error = command
            .into_exec_request()
            .expect_err("command is required");

        assert!(error.contains("missing command"));
    }

    #[test]
    fn rejects_invalid_cwd_during_request_conversion() {
        let command = Cli::try_parse_from([
            "heimdall-sandbox",
            "exec",
            "--cwd",
            "/definitely/not/a/heimdall/sandbox/path",
            "--",
            "true",
        ])
        .expect("syntax is valid");

        let error = command
            .into_exec_request()
            .expect_err("invalid cwd is rejected");

        assert!(error.contains("invalid cwd"));
    }

    #[test]
    fn rejects_config_arguments() {
        let error = Cli::try_parse_from([
            "heimdall-sandbox",
            "exec",
            "--config",
            "sandbox.toml",
            "--cwd",
            ".",
            "--",
            "true",
        ])
        .expect_err("config files are not accepted");

        assert!(error.to_string().contains("--config"));
    }
}
