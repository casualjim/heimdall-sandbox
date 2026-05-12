//! `heimdall-sandbox policy` command and subcommands.

use clap::{Parser, Subcommand};
use schemars::schema_for;

use crate::error::{Error, Result};
use crate::policy::{PolicyDocument, policy_document_request, read_policy_document};

/// Work with JSON policy documents.
#[derive(Debug, Parser)]
pub struct PolicyArgs {
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

/// Run a policy subcommand.
pub fn run_policy_command(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommands::Schema => print_policy_schema(),
        PolicyCommands::Validate(args) => validate_policy_document(&args.policy),
    }
}

fn print_policy_schema() -> Result<()> {
    let schema = schema_for!(PolicyDocument);
    let json = serde_json::to_string_pretty(&schema)
        .map_err(|source| Error::json("failed to serialize policy schema", source))?;
    println!("{json}");
    Ok(())
}

fn validate_policy_document(policy: &str) -> Result<()> {
    let policy = read_policy_document(policy)?;
    policy_document_request(policy).map(|_| ())
}
