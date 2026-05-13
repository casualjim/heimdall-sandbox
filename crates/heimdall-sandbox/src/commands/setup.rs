//! `heimdall-sandbox setup` command — download privacy-filter model assets.

use std::path::PathBuf;

use clap::Parser;
use heimdall_privacy_filter::{
    DEFAULT_MODEL_REVISION, PrivacyFilterConfig, PrivacyFilterVariant, SetupRequest,
    setup_privacy_filter,
};

use super::cli_privacy_types::CliPrivacyVariant;

/// Download privacy-filter model assets into the Hugging Face cache.
#[derive(Debug, Parser)]
pub struct SetupArgs {
    /// Redownload files even if they already exist in the cache.
    #[arg(long)]
    pub force: bool,

    /// Override the Hugging Face cache directory for model storage.
    #[arg(long = "cache-dir")]
    pub cache_dir: Option<PathBuf>,

    /// Model quantization variant to download.
    #[arg(long, value_enum, default_value_t = CliPrivacyVariant::Q4)]
    pub variant: CliPrivacyVariant,

    /// Hugging Face model revision to download.
    #[arg(long, default_value = DEFAULT_MODEL_REVISION)]
    pub revision: String,
}

/// Run the setup command and return a process exit code.
pub fn run_setup_command(args: SetupArgs) -> i32 {
    let mut config = PrivacyFilterConfig::enabled()
        .with_variant(PrivacyFilterVariant::from(args.variant))
        .with_revision(&args.revision);
    if let Some(cache_dir) = args.cache_dir {
        config = config.with_cache_dir(cache_dir);
    }

    let request = SetupRequest::new(config).with_force(args.force);

    match setup_privacy_filter(request) {
        Ok(report) => {
            println!("Privacy filter setup complete.");
            println!("Snapshot root: {}", report.snapshot_root.display());
            for file in &report.downloaded_files {
                let display: std::path::Display<'_> = file.display();
                println!("  {display}");
            }
            0
        }
        Err(error) => {
            eprintln!("privacy filter setup failed: {error}");
            1
        }
    }
}
