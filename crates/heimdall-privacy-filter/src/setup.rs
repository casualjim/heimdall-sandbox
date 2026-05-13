use std::path::{Path, PathBuf};

use hf_hub::api::sync::ApiBuilder;
use hf_hub::{Repo, RepoType};

use crate::model::{MODEL_REPOSITORY, PrivacyFilterConfig};
use crate::{Error, Result};

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
    let api = build_api(&request.config)?;
    let repo = Repo::with_revision(
        MODEL_REPOSITORY.to_string(),
        RepoType::Model,
        request.config.revision().to_string(),
    );
    let repo = api.repo(repo);

    let mut downloaded_files = Vec::new();
    for file in request.config.variant().required_files() {
        let path = if request.force {
            repo.download(file)
        } else {
            repo.get(file)
        }
        .map_err(|error| Error::Setup {
            message: format!("failed to download {file}: {error}"),
        })?;
        downloaded_files.push(path);
    }

    let config_path = downloaded_files
        .iter()
        .find(|path| path.file_name().is_some_and(|name| name == "config.json"))
        .ok_or_else(|| Error::Setup {
            message: "config.json was not downloaded".to_string(),
        })?;
    let snapshot_root = snapshot_root_for(config_path, "config.json")?;

    Ok(SetupReport {
        snapshot_root,
        downloaded_files,
    })
}

fn build_api(config: &PrivacyFilterConfig) -> Result<hf_hub::api::sync::Api> {
    let mut builder = ApiBuilder::from_env().with_progress(true);
    if let Some(cache_dir) = config.cache_dir() {
        builder = builder.with_cache_dir(cache_dir.to_path_buf());
    }
    builder.build().map_err(|error| Error::Setup {
        message: format!("failed to initialize Hugging Face API: {error}"),
    })
}

fn snapshot_root_for(downloaded_file: &Path, repo_relative: &str) -> Result<PathBuf> {
    let mut root = downloaded_file.to_path_buf();
    for _ in Path::new(repo_relative).components() {
        root.pop();
    }
    if root.as_os_str().is_empty() {
        return Err(Error::Setup {
            message: format!(
                "failed to derive snapshot root from {}",
                downloaded_file.display()
            ),
        });
    }
    Ok(root)
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
