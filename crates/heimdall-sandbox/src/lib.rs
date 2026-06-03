//! Command-line parsing for the heimdall sandbox executable.

use clap::{Parser, Subcommand};

use heimdall_core::{Executor, SANDBOX_MISCONFIGURATION_EXIT_CODE};

use commands::exec::ExecArgs;
use commands::inner_exec::InnerExecArgs;
use commands::policy::PolicyArgs;
use commands::privacy_filter::PrivacyFilterArgs;
use commands::setup::SetupArgs;

pub mod commands;
mod error;
pub mod policy;

pub use error::{Error, Result};

/// `heimdall-sandbox` command-line interface.
///
/// Parses CLI arguments into typed command structs that can be converted to
/// [`heimdall_core::ExecRequest`] or dispatched to subcommands.
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
    /// Download privacy-filter model assets into the Hugging Face cache.
    Setup(SetupArgs),
    /// Privacy-filter model download and text redaction.
    #[command(name = "privacy-filter")]
    PrivacyFilter(PrivacyFilterArgs),
}

impl Cli {
    /// Parse CLI args from the process environment.
    #[must_use]
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Convert a parsed CLI invocation into a core execution request.
    ///
    /// Returns an error when parsing, policy loading, or core request validation fails.
    pub fn into_exec_request(self) -> error::Result<heimdall_core::ExecRequest> {
        match self.command {
            Commands::Exec(args) => policy::exec_args_to_request(args),
            Commands::Policy(_) => Err(Error::arguments(
                "policy commands do not create execution requests",
            )),
            Commands::InnerExec(args) => policy::inner_exec_args_to_request(args),
            Commands::Setup(_) | Commands::PrivacyFilter(_) => Err(Error::arguments(
                "setup/privacy-filter commands do not create execution requests",
            )),
        }
    }
}

/// Run the sandbox CLI and return the process exit code.
///
/// Parses arguments from `std::env::args`, runs the appropriate subcommand,
/// and returns `0` on success or a non-zero exit code on failure.
#[must_use]
pub fn run() -> i32 {
    run_cli(Cli::parse_args())
}

/// Run CLI parsing from an explicit argument iterator.
///
/// Maps clap parse errors to the sandbox misconfiguration exit code.
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
        return match commands::policy::run_policy_command(args) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("{error}");
                SANDBOX_MISCONFIGURATION_EXIT_CODE
            }
        };
    }

    if let Commands::Setup(args) = command {
        return commands::setup::run_setup_command(args);
    }

    if let Commands::PrivacyFilter(args) = command {
        return commands::privacy_filter::run_privacy_filter_command(args);
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
    use heimdall_core::{AgentPolicy, EnvPolicy, ProcMode, RuntimeMode, StdioPolicy};

    use super::*;
    use crate::policy::*;

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
        assert_eq!(request.runtime_mode(), RuntimeMode::Platform);
        assert_eq!(request.stdio_policy(), StdioPolicy::Inherit);
    }

    #[test]
    fn direct_microvm_runtime_requires_policy_image() {
        let command = Cli::try_parse_from([
            "heimdall-sandbox",
            "exec",
            "--runtime",
            "microvm",
            "--cwd",
            ".",
            "--",
            "printf",
            "hello",
        ])
        .expect("valid invocation parses");

        let error = command
            .into_exec_request()
            .expect_err("direct microvm runtime has no image source");

        assert!(error.to_string().contains("requires --policy"));
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
    fn cli_platform_override_rejects_policy_image() {
        let policy = serde_json::from_str::<PolicyDocument>(
            r#"{
              "runtime": "microvm",
              "image": "alpine",
              "cwd": ".",
              "command": ["printf", "hello"]
            }"#,
        )
        .expect("policy JSON parses");

        let error = policy_document_request_with_runtime(policy, Some(CliRuntimeMode::Platform))
            .expect_err("platform runtime rejects image");

        assert!(
            error
                .to_string()
                .contains("policy image requires runtime microvm")
        );
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
    fn missing_cwd_defaults_to_current_directory() {
        let command = Cli::try_parse_from(["heimdall-sandbox", "exec", "--", "true"])
            .expect("syntax is valid");

        let request = command.into_exec_request().expect("request converts");

        assert_eq!(request.cwd(), current_directory().expect("cwd exists"));
    }

    #[test]
    fn rejects_missing_command() {
        let command = Cli::try_parse_from(["heimdall-sandbox", "exec", "--cwd", ".", "--"])
            .expect("syntax is valid");

        let error = command
            .into_exec_request()
            .expect_err("command is required");

        assert!(error.to_string().contains("missing command"));
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

        assert!(error.to_string().contains("invalid cwd"));
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
