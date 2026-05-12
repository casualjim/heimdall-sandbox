//! Test-only utilities shared across `#[cfg(test)]` blocks.

use std::sync::OnceLock;

use crate::model::{ModelAssetPaths, PrivacyFilterConfig};
use crate::output::{PrivacyLabels, ViterbiCalibration};
use crate::setup::{SetupRequest, setup_privacy_filter};

/// Shared model fixture — downloaded once, reused by all test threads.
pub(crate) struct ModelFixture {
    pub config: PrivacyFilterConfig,
    pub assets: ModelAssetPaths,
    pub labels: PrivacyLabels,
    pub calibration: ViterbiCalibration,
}

static FIXTURE: OnceLock<ModelFixture> = OnceLock::new();

pub(crate) fn fixture() -> &'static ModelFixture {
    FIXTURE.get_or_init(|| {
        let config = PrivacyFilterConfig::enabled();
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
        ModelFixture {
            config,
            assets,
            labels,
            calibration,
        }
    })
}
