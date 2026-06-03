//! `heimdall-sandbox exec` command.

use std::path::PathBuf;

use clap::Parser;

use crate::policy::{CliRuntimeMode, CliStdioPolicy};

/// Execute a command in the minimal sandbox runtime.
#[derive(Debug, Parser)]
pub struct ExecArgs {
    /// JSON sandbox policy path, or `-` to read the policy from stdin.
    #[arg(long = "policy")]
    pub policy: Option<String>,

    /// Sandbox runtime backend.
    #[arg(long = "runtime", value_enum)]
    pub runtime: Option<CliRuntimeMode>,

    /// Child process working directory.
    #[arg(long)]
    pub cwd: Option<PathBuf>,

    /// Parent environment variable key to preserve in the child process.
    #[arg(long = "allow-env")]
    pub allow_env: Vec<String>,

    /// Parent environment variable key to remove in blocklist mode.
    #[arg(long = "deny-env", conflicts_with = "allow_env")]
    pub deny_env: Vec<String>,

    /// Child process stdio handling policy.
    #[arg(long = "stdio", value_enum, default_value_t = CliStdioPolicy::Inherit)]
    pub stdio: CliStdioPolicy,

    /// Disable `/proc` mounting for Linux bubblewrap isolation.
    #[arg(long = "no-proc")]
    pub no_proc: bool,

    /// Command argv to execute directly without shell parsing.
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}
