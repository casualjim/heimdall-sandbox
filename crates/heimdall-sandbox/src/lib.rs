//! Command-line parsing for the heimdall sandbox executable.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use heimdall_core::{
    EnvPolicy, ExecRequest, SANDBOX_MISCONFIGURATION_EXIT_CODE, StdioPolicy, execute,
};
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

    /// Command argv to execute directly without shell parsing.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, ValueEnum)]
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

#[derive(Debug, Deserialize)]
struct PolicyDocument {
    cwd: Option<PathBuf>,
    command: Vec<String>,
    #[serde(flatten)]
    sandbox: SandboxConfig,
    stdio: Option<CliStdioPolicy>,
}

#[derive(Debug, Default, Deserialize)]
struct SandboxConfig {
    enabled: Option<bool>,
    network: Option<SandboxNetwork>,
    paths: Option<BTreeMap<String, SandboxPathEntries>>,
    env: Option<PolicyEnvironment>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SandboxNetwork {
    Host,
    None,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SandboxPathEntries {
    One(SandboxPathEntry),
    Many(Vec<SandboxPathEntry>),
}

#[derive(Debug, Deserialize)]
struct SandboxPathEntry {
    path: Option<String>,
    content: Option<String>,
    mode: Option<SandboxPathMode>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SandboxPathMode {
    Read,
    Write,
}

#[derive(Debug, Deserialize)]
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
        }
    }
}

impl ExecArgs {
    fn into_exec_request(self) -> std::result::Result<ExecRequest, String> {
        if let Some(policy) = self.policy {
            if self.cwd.is_some()
                || !self.allow_env.is_empty()
                || !self.deny_env.is_empty()
                || self.stdio != CliStdioPolicy::Inherit
                || !self.command.is_empty()
            {
                return Err("--policy cannot be combined with direct exec arguments".to_string());
            }
            return policy_document_request(read_policy_document(&policy)?);
        }

        let cwd = self.cwd.unwrap_or_else(current_directory);
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
        std::fs::read_to_string(policy)
            .map_err(|error| format!("failed to read policy {policy}: {error}"))?
    };
    serde_json::from_str(&json).map_err(|error| format!("failed to parse policy JSON: {error}"))
}

fn policy_document_request(policy: PolicyDocument) -> std::result::Result<ExecRequest, String> {
    let PolicyDocument {
        cwd,
        command,
        sandbox,
        stdio,
    } = policy;
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
    ExecRequest::new(cwd.unwrap_or_else(current_directory), command, allowed_env)
        .map(|request| {
            request
                .with_env_policy(env_policy, denied_env)
                .with_stdio_policy(stdio.unwrap_or(CliStdioPolicy::Inherit).into())
        })
        .map_err(|error| error.to_string())
}

fn validate_sandbox_config(config: &SandboxConfig) -> std::result::Result<(), String> {
    if config.enabled == Some(false) {
        return Err("policy enabled=false is not supported by heimdall-sandbox exec".to_string());
    }

    if matches!(config.network, Some(SandboxNetwork::None)) {
        return Err(
            "policy network=none requires filesystem/network isolation not implemented by this runtime"
                .to_string(),
        );
    }

    if let Some(paths) = &config.paths {
        validate_sandbox_paths(paths)?;
        if !paths.is_empty() {
            return Err(
                "policy paths require filesystem isolation not implemented by this runtime"
                    .to_string(),
            );
        }
    }

    Ok(())
}

fn validate_sandbox_paths(
    paths: &BTreeMap<String, SandboxPathEntries>,
) -> std::result::Result<(), String> {
    for (name, entries) in paths {
        match entries {
            SandboxPathEntries::One(entry) => validate_sandbox_path_entry(name, entry)?,
            SandboxPathEntries::Many(entries) => {
                for entry in entries {
                    validate_sandbox_path_entry(name, entry)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_sandbox_path_entry(
    name: &str,
    entry: &SandboxPathEntry,
) -> std::result::Result<(), String> {
    if entry.path.is_none() && entry.content.is_none() {
        return Err(format!(
            "policy path entry {name} must define either path or content"
        ));
    }

    match entry.mode {
        Some(SandboxPathMode::Read | SandboxPathMode::Write) | None => Ok(()),
    }
}

/// Run the sandbox CLI and return the process exit code.
#[must_use]
pub fn run() -> i32 {
    if let Err(error) = heimdall_process_hardening::apply_process_hardening() {
        eprintln!("sandbox hardening failed: {error}");
        return SANDBOX_MISCONFIGURATION_EXIT_CODE;
    }

    match Cli::parse_args().into_exec_request() {
        Ok(request) => match execute(&request) {
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

/// Run CLI parsing and map clap parse errors to the sandbox misconfiguration code.
#[must_use]
pub fn run_from<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    match Cli::try_parse_from(args) {
        Ok(cli) => match cli.into_exec_request() {
            Ok(request) => match execute(&request) {
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
    fn policy_document_rejects_unimplemented_network_isolation() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "network": "none",
              "cwd": ".",
              "command": ["printf", "hello"]
            }"#,
        )
        .expect("policy JSON parses");

        let error = policy_document_request(policy).expect_err("network isolation is rejected");

        assert!(error.contains("network=none"));
    }

    #[test]
    fn policy_document_rejects_unimplemented_path_isolation() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "cwd": ".",
              "command": ["printf", "hello"],
              "paths": {
                "workspace": { "path": ".", "mode": "write" }
              }
            }"#,
        )
        .expect("policy JSON parses");

        let error = policy_document_request(policy).expect_err("path isolation is rejected");

        assert!(error.contains("policy paths"));
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
