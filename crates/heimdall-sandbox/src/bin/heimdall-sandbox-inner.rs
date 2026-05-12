use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use heimdall_core::{
    EnvPolicy, ExecRequest, Executor, SANDBOX_MISCONFIGURATION_EXIT_CODE, StdioPolicy,
};

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let args = std::env::args_os().collect::<Vec<_>>();
    let argv0 = args
        .first()
        .cloned()
        .unwrap_or_else(|| "heimdall-sandbox-inner".into());
    let parsed_args = if args
        .get(1)
        .is_some_and(|arg| arg == "__heimdall-inner-exec")
    {
        std::iter::once(argv0)
            .chain(args.into_iter().skip(2))
            .collect::<Vec<_>>()
    } else {
        args
    };

    match InnerExecArgs::try_parse_from(parsed_args) {
        Ok(args) => run_inner(args),
        Err(error) => {
            eprintln!("{error}");
            SANDBOX_MISCONFIGURATION_EXIT_CODE
        }
    }
}

fn run_inner(args: InnerExecArgs) -> i32 {
    if let Err(error) = heimdall_process_hardening::apply_process_hardening() {
        eprintln!("sandbox hardening failed: {error}");
        return SANDBOX_MISCONFIGURATION_EXIT_CODE;
    }

    if args.command.is_empty() {
        eprintln!("missing command");
        return SANDBOX_MISCONFIGURATION_EXIT_CODE;
    }

    let request = match ExecRequest::new(args.cwd, args.command, Vec::new()).map(|request| {
        request
            .with_env_policy(EnvPolicy::Blocklist, Vec::new())
            .with_stdio_policy(args.stdio.into())
    }) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("{error}");
            return SANDBOX_MISCONFIGURATION_EXIT_CODE;
        }
    };

    match Executor.execute(&request) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            error.exit_code()
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "heimdall-sandbox-inner",
    disable_help_flag = true,
    disable_version_flag = true
)]
struct InnerExecArgs {
    #[arg(long)]
    cwd: PathBuf,

    #[arg(long = "stdio", value_enum, default_value_t = CliStdioPolicy::Inherit)]
    stdio: CliStdioPolicy,

    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliStdioPolicy {
    Inherit,
    Piped,
}

impl From<CliStdioPolicy> for StdioPolicy {
    fn from(policy: CliStdioPolicy) -> Self {
        match policy {
            CliStdioPolicy::Inherit => Self::Inherit,
            CliStdioPolicy::Piped => Self::Piped,
        }
    }
}
