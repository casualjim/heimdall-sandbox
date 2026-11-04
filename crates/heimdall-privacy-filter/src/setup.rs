use std::path::PathBuf;

use crate::Result;
use crate::model::PrivacyFilterConfig;

/// Request for explicit privacy-filter setup.
#[derive(Clone, Debug)]
pub struct SetupRequest {
    /// Setup/runtime configuration to download.
    pub config: PrivacyFilterConfig,
    /// Redownload files even if cache entries already exist.
    pub force: bool,
}

impl SetupRequest {
    /// Create a setup request with safe defaults.
    #[must_use]
    pub fn new(config: PrivacyFilterConfig) -> Self {
        Self {
            config,
            force: false,
        }
    }

    /// Return a copy that redownloads files even if present in cache.
    #[must_use]
    pub const fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }
}

/// Report returned by successful setup.
#[derive(Clone, Debug)]
pub struct SetupReport {
    /// Hugging Face snapshot root containing the model files.
    pub snapshot_root: PathBuf,
    /// Files downloaded or verified by setup.
    pub downloaded_files: Vec<PathBuf>,
}

/// Download privacy-filter model assets into the Hugging Face cache.
pub fn setup_privacy_filter(request: SetupRequest) -> Result<SetupReport> {
    let files = request.config.variant().required_files();
    let snapshot = request
        .config
        .model_source()
        .download(&files, request.force)?;
    Ok(SetupReport {
        snapshot_root: snapshot.root().to_path_buf(),
        downloaded_files: snapshot.files().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_produces_report_with_files() {
        let config = PrivacyFilterConfig::enabled();
        let report = setup_privacy_filter(SetupRequest::new(config.clone())).unwrap();
        assert!(report.snapshot_root.exists());
        assert!(!report.downloaded_files.is_empty());
        // config.json must be one of the downloaded files.
        assert!(
            report
                .downloaded_files
                .iter()
                .any(|p| p.file_name().is_some_and(|n| n == "config.json"))
        );
    }
}
