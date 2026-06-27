//! `heimdall-sandbox` command-line interface and dispatch.

use clap::{Parser, Subcommand};

use heimdall_core::{Executor, SANDBOX_MISCONFIGURATION_EXIT_CODE};

use crate::Error;
use crate::commands::exec::ExecArgs;
use crate::commands::inner_exec::InnerExecArgs;
use crate::commands::policy::PolicyArgs;
use crate::commands::privacy_filter::PrivacyFilterArgs;
use crate::commands::setup::SetupArgs;
use crate::policy::{exec_args_to_request, inner_exec_args_to_request};

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
    pub fn into_exec_request(self) -> crate::Result<heimdall_core::ExecRequest> {
        match self.command {
            Commands::Exec(args) => exec_args_to_request(args),
            Commands::Policy(_) => Err(Error::arguments(
                "policy commands do not create execution requests",
            )),
            Commands::InnerExec(args) => inner_exec_args_to_request(args),
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
        return match crate::commands::policy::run_policy_command(args) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("{error}");
                SANDBOX_MISCONFIGURATION_EXIT_CODE
            }
        };
    }

    if let Commands::Setup(args) = command {
        return crate::commands::setup::run_setup_command(args);
    }

    if let Commands::PrivacyFilter(args) = command {
        return crate::commands::privacy_filter::run_privacy_filter_command(args);
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
    use heimdall_core::{EnvPolicy, ProcMode, RuntimeMode, StdioPolicy};

    use super::Cli;
    use crate::policy::current_directory;

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
