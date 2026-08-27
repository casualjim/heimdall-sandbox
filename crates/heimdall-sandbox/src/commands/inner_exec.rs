//! `heimdall-sandbox __heimdall-inner-exec` internal re-entry command.

use std::path::PathBuf;

use clap::Parser;

use crate::policy::CliStdioPolicy;

/// Internal re-entry point used inside a Linux bubblewrap namespace.
#[derive(Debug, Parser)]
pub struct InnerExecArgs {
    /// Child process working directory inside the namespace.
    #[arg(long)]
    pub cwd: PathBuf,

    /// Child process stdio handling policy.
    #[arg(long = "stdio", value_enum, default_value_t = CliStdioPolicy::Inherit)]
    pub stdio: CliStdioPolicy,

    /// Landlock read-grant roots planned by the Linux sandbox launcher.
    #[arg(long = "read-grant", hide = true)]
    pub read_grant: Vec<PathBuf>,

    /// Landlock traversal-only (execute) roots planned by the Linux sandbox launcher.
    #[arg(long = "read-traverse", hide = true)]
    pub read_traverse: Vec<PathBuf>,

    /// Command argv to execute directly without shell parsing.
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}
