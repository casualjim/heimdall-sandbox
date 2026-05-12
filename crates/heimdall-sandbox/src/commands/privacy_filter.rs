//! `heimdall-sandbox privacy-filter` command and subcommands.

use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use heimdall_privacy_filter::{
    DEFAULT_MODEL_REVISION, PrivacyExecutionProvider, PrivacyFilterConfig, PrivacyFilterRuntime,
    PrivacyFilterVariant, redact_text,
};

use super::cli_privacy_types::{CliExecutionProvider, CliPrivacyVariant};

/// Privacy-filter model download and text redaction.
#[derive(Debug, Parser)]
pub struct PrivacyFilterArgs {
    #[command(subcommand)]
    command: PrivacyFilterCommands,
}

#[derive(Debug, Subcommand)]
enum PrivacyFilterCommands {
    /// Redact sensitive information from text using the local privacy-filter model.
    Redact(RedactArgs),
}

/// Redact sensitive information from text.
///
/// Input is read from a positional argument, a file, or stdin:
///
///   heimdall-sandbox privacy-filter redact "alice@example.com"
///   echo "alice@example.com" | heimdall-sandbox privacy-filter redact
///   heimdall-sandbox privacy-filter redact input.txt
#[derive(Debug, Parser)]
pub struct RedactArgs {
    /// Text to redact, or a file path. When omitted, reads from stdin.
    #[arg(value_name = "TEXT_OR_FILE")]
    input: Option<String>,

    /// Override the Hugging Face cache directory for model storage.
    #[arg(long = "cache-dir")]
    cache_dir: Option<PathBuf>,

    /// Model quantization variant to use.
    #[arg(long, value_enum, default_value_t = CliPrivacyVariant::Q4)]
    variant: CliPrivacyVariant,

    /// Hugging Face model revision to use.
    #[arg(long, default_value = DEFAULT_MODEL_REVISION)]
    revision: String,

    /// ONNX Runtime execution provider.
    #[arg(long = "execution-provider", value_enum, default_value_t = CliExecutionProvider::Cpu)]
    execution_provider: CliExecutionProvider,
}

/// Run a privacy-filter subcommand and return a process exit code.
pub fn run_privacy_filter_command(args: PrivacyFilterArgs) -> i32 {
    match args.command {
        PrivacyFilterCommands::Redact(args) => run_redact_command(args),
    }
}

fn run_redact_command(args: RedactArgs) -> i32 {
    let variant = args.variant;
    let revision = args.revision.clone();
    let execution_provider = args.execution_provider;
    let cache_dir = args.cache_dir.clone();

    let text = match read_input(args.input) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("{error}");
            return heimdall_core::SANDBOX_MISCONFIGURATION_EXIT_CODE;
        }
    };

    let mut config = PrivacyFilterConfig::enabled()
        .with_variant(PrivacyFilterVariant::from(variant))
        .with_revision(&revision)
        .with_execution_provider(PrivacyExecutionProvider::from(execution_provider));
    if let Some(cache_dir) = cache_dir {
        config = config.with_cache_dir(cache_dir);
    }

    let mut runtime = match PrivacyFilterRuntime::load(config) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("privacy filter runtime failed: {error}");
            return 1;
        }
    };

    match redact_text(&mut runtime, &text) {
        Ok(redacted) => {
            println!("{redacted}");
            0
        }
        Err(error) => {
            eprintln!("privacy filter redaction failed: {error}");
            1
        }
    }
}

/// Read input text from a positional arg, file, or stdin.
///
/// - `Some(arg)` where `arg` is a path to an existing file → read file
/// - `Some(arg)` literal text → use as-is
/// - `None` + stdin is a pipe/redirect → read stdin
/// - `None` + stdin is a terminal → error
fn read_input(input: Option<String>) -> Result<String, String> {
    if let Some(arg) = input {
        let path = PathBuf::from(&arg);
        if path.is_file() {
            return std::fs::read_to_string(&path)
                .map_err(|error| format!("{}: {error}", path.display()));
        }
        if arg.is_empty() {
            return Err("input text is empty".to_string());
        }
        return Ok(arg);
    }

    if io::stdin().is_terminal() {
        return Err("no input: provide text argument, pipe input, or redirect a file".to_string());
    }

    let mut text = String::new();
    io::stdin()
        .read_to_string(&mut text)
        .map_err(|error| format!("failed to read stdin: {error}"))?;
    if text.is_empty() {
        return Err("stdin is empty".to_string());
    }
    Ok(text)
}
