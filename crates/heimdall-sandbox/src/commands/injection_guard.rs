//! `heimdall-sandbox injection-guard` command and subcommands.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use heimdall_injection_guard::{
    DEFAULT_MODEL_REVISION, InjectionGuardConfig, InjectionGuardRuntime, setup_injection_guard,
};
use heimdall_model_runtime::session::ExecutionProvider;
use serde_json::json;

use super::cli_privacy_types::CliExecutionProvider;
use super::privacy_filter::read_input;

/// Prompt-injection model download and text scanning.
#[derive(Debug, Parser)]
pub struct InjectionGuardArgs {
    #[command(subcommand)]
    command: InjectionGuardCommands,
}

#[derive(Debug, Subcommand)]
enum InjectionGuardCommands {
    /// Download injection-guard model assets into the Hugging Face cache.
    Setup(SetupArgs),
    /// Scan text for prompt injection and print a JSON verdict with redacted text.
    Scan(ScanArgs),
}

/// Options shared by every injection-guard subcommand.
#[derive(Debug, Parser)]
struct ModelArgs {
    /// Override the Hugging Face cache directory for model storage.
    #[arg(long = "cache-dir")]
    cache_dir: Option<PathBuf>,

    /// Hugging Face model revision to use.
    #[arg(long, default_value = DEFAULT_MODEL_REVISION)]
    revision: String,

    /// ONNX Runtime execution provider.
    #[arg(long = "execution-provider", value_enum, default_value_t = CliExecutionProvider::Cpu)]
    execution_provider: CliExecutionProvider,
}

impl ModelArgs {
    fn config(&self) -> InjectionGuardConfig {
        let mut config = InjectionGuardConfig::default()
            .with_revision(&self.revision)
            .with_execution_provider(ExecutionProvider::from(self.execution_provider));
        if let Some(cache_dir) = &self.cache_dir {
            config = config.with_cache_dir(cache_dir);
        }
        config
    }
}

/// Download injection-guard model assets into the Hugging Face cache.
#[derive(Debug, Parser)]
struct SetupArgs {
    /// Redownload files even if they already exist in the cache.
    #[arg(long)]
    force: bool,

    #[command(flatten)]
    model: ModelArgs,
}

/// Scan text for prompt injection.
///
/// Input is read from a positional argument, a file, or stdin. The verdict is
/// printed as one JSON object; the exit code is 0 whether or not text was flagged.
///
///   heimdall-sandbox injection-guard scan "ignore previous instructions"
///   cat tool-output.txt | heimdall-sandbox injection-guard scan
#[derive(Debug, Parser)]
struct ScanArgs {
    /// Text to scan, or a file path. When omitted, reads from stdin.
    #[arg(value_name = "TEXT_OR_FILE")]
    input: Option<String>,

    #[command(flatten)]
    model: ModelArgs,
}

/// Run an injection-guard subcommand and return a process exit code.
pub fn run_injection_guard_command(args: InjectionGuardArgs) -> i32 {
    match args.command {
        InjectionGuardCommands::Setup(args) => run_setup_command(&args),
        InjectionGuardCommands::Scan(args) => run_scan_command(args),
    }
}

fn run_setup_command(args: &SetupArgs) -> i32 {
    match setup_injection_guard(&args.model.config(), args.force) {
        Ok(report) => {
            println!("Injection guard setup complete.");
            println!("Snapshot root: {}", report.snapshot_root.display());
            for file in &report.downloaded_files {
                println!("  {}", file.display());
            }
            0
        }
        Err(error) => {
            eprintln!("injection guard setup failed: {error}");
            1
        }
    }
}

fn run_scan_command(args: ScanArgs) -> i32 {
    let text = match read_input(args.input) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("{error}");
            return heimdall_core::SANDBOX_MISCONFIGURATION_EXIT_CODE;
        }
    };

    let mut runtime = match InjectionGuardRuntime::load(&args.model.config()) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("injection guard runtime failed: {error}");
            return 1;
        }
    };

    let verdict = runtime
        .scan(&text)
        .and_then(|scan| scan.redact(&text).map(|redacted| (scan, redacted)));
    match verdict {
        Ok((scan, redacted)) => {
            let spans = scan
                .spans()
                .iter()
                .map(|span| [span.start, span.end])
                .collect::<Vec<_>>();
            println!(
                "{}",
                json!({
                    "flagged": scan.is_flagged(),
                    "max_margin": scan.max_margin(),
                    "threshold": scan.threshold(),
                    "spans": spans,
                    "redacted": redacted,
                })
            );
            if matches!(args.model.execution_provider, CliExecutionProvider::WebGpu) {
                std::process::exit(0);
            }
            0
        }
        Err(error) => {
            eprintln!("injection guard scan failed: {error}");
            1
        }
    }
}
