//! Test-only utilities shared across `#[cfg(test)]` blocks.

use std::fs::{File, OpenOptions};
use std::sync::OnceLock;

use crate::model::{
    ModelAssetPaths, PrivacyFilterConfig, usable_token_limit_from_tokenizer_config_json,
};
use crate::output::{PrivacyLabels, ViterbiCalibration};
use crate::setup::{SetupRequest, setup_privacy_filter};

/// Shared model fixture — downloaded once, reused by all test threads.
pub(crate) struct ModelFixture {
    pub config: PrivacyFilterConfig,
    pub assets: ModelAssetPaths,
    pub labels: PrivacyLabels,
    pub calibration: ViterbiCalibration,
    pub usable_token_limit: usize,
}

static FIXTURE: OnceLock<ModelFixture> = OnceLock::new();

struct DownloadLock {
    _file: File,
}

fn acquire_download_lock() -> DownloadLock {
    let path = std::env::temp_dir().join("heimdall-privacy-filter-model-download.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .unwrap_or_else(|error| {
            panic!(
                "failed to open privacy-filter model download lock at {}: {error}",
                path.display()
            )
        });
    file.lock().unwrap_or_else(|error| {
        panic!(
            "failed to acquire privacy-filter model download lock at {}: {error}",
            path.display()
        )
    });
    DownloadLock { _file: file }
}

pub(crate) fn fixture() -> &'static ModelFixture {
    FIXTURE.get_or_init(|| {
        let config = PrivacyFilterConfig::enabled();
        let _download_lock = acquire_download_lock();
        let report = setup_privacy_filter(SetupRequest::new(config.clone()))
            .expect("model download must succeed");
        let assets = ModelAssetPaths::from_snapshot(&report.snapshot_root, config.variant());
        let labels = PrivacyLabels::from_config_json(
            &std::fs::read_to_string(&assets.config).expect("config.json"),
        )
        .expect("labels");
        let calibration = ViterbiCalibration::from_json(
            &std::fs::read_to_string(&assets.viterbi).expect("viterbi"),
        )
        .expect("calibration");
        let usable_token_limit = usable_token_limit_from_tokenizer_config_json(
            &std::fs::read_to_string(&assets.tokenizer_config).expect("tokenizer_config"),
        )
        .expect("usable token limit");
        ModelFixture {
            config,
            assets,
            labels,
            calibration,
            usable_token_limit,
        }
    })
}
