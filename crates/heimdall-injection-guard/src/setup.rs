use std::path::PathBuf;

use crate::Result;
use crate::model::{InjectionGuardConfig, REQUIRED_FILES};

/// Report returned by successful setup.
#[derive(Clone, Debug)]
pub struct SetupReport {
    /// Hugging Face snapshot root containing the model files.
    pub snapshot_root: PathBuf,
    /// Files downloaded or verified by setup.
    pub downloaded_files: Vec<PathBuf>,
}

/// Download injection-guard model assets into the Hugging Face cache.
///
/// `force` redownloads files that already exist in the cache.
pub fn setup_injection_guard(config: &InjectionGuardConfig, force: bool) -> Result<SetupReport> {
    let snapshot = config.model_source().download(&REQUIRED_FILES, force)?;
    Ok(SetupReport {
        snapshot_root: snapshot.root().to_path_buf(),
        downloaded_files: snapshot.files().to_vec(),
    })
}
