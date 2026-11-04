use std::path::{Path, PathBuf};

use heimdall_model_runtime::session::ExecutionProvider;
use heimdall_model_runtime::source::ModelSource;
use serde::Deserialize;

use crate::{Error, Result};

/// Hugging Face model repository for the default injection classifier.
pub const MODEL_REPOSITORY: &str = "usezn/Galvanize-3";

/// Pinned model revision used by default setup/runtime configuration.
pub const DEFAULT_MODEL_REVISION: &str = "597237be3b0fabbf5d70ff16ce95fad14a591f20";

pub(crate) const TOKENIZER_FILE: &str = "tokenizer.json";
pub(crate) const THRESHOLDS_FILE: &str = "thresholds.json";
pub(crate) const ONNX_FILE: &str = "onnx/model.onnx";

/// Repository files setup downloads and the runtime requires, in this order.
pub(crate) const REQUIRED_FILES: [&str; 3] = [TOKENIZER_FILE, THRESHOLDS_FILE, ONNX_FILE];

/// Setup/runtime configuration for injection detection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InjectionGuardConfig {
    revision: String,
    cache_dir: Option<PathBuf>,
    execution_provider: ExecutionProvider,
}

impl Default for InjectionGuardConfig {
    fn default() -> Self {
        Self {
            revision: DEFAULT_MODEL_REVISION.to_string(),
            cache_dir: None,
            execution_provider: ExecutionProvider::default(),
        }
    }
}

impl InjectionGuardConfig {
    /// Return the selected Hugging Face revision.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Return the optional Hugging Face cache directory override.
    #[must_use]
    pub fn cache_dir(&self) -> Option<&Path> {
        self.cache_dir.as_deref()
    }

    /// Return the selected execution provider.
    #[must_use]
    pub const fn execution_provider(&self) -> ExecutionProvider {
        self.execution_provider
    }

    /// Return a copy with the selected Hugging Face revision.
    #[must_use]
    pub fn with_revision(mut self, revision: impl Into<String>) -> Self {
        self.revision = revision.into();
        self
    }

    /// Return a copy with a Hugging Face cache directory override.
    #[must_use]
    pub fn with_cache_dir(mut self, cache_dir: impl Into<PathBuf>) -> Self {
        self.cache_dir = Some(cache_dir.into());
        self
    }

    /// Return a copy with the selected execution provider.
    #[must_use]
    pub const fn with_execution_provider(mut self, provider: ExecutionProvider) -> Self {
        self.execution_provider = provider;
        self
    }

    /// Return the Hugging Face source for the configured revision and cache directory.
    #[must_use]
    pub(crate) fn model_source(&self) -> ModelSource {
        ModelSource::new(MODEL_REPOSITORY, &self.revision, self.cache_dir.clone())
    }
}

#[derive(Debug, Deserialize)]
struct Thresholds {
    margin_threshold: f32,
}

/// Parse the serving margin threshold from cached `thresholds.json`.
pub(crate) fn margin_threshold_from_json(json: &str) -> Result<f32> {
    let thresholds = serde_json::from_str::<Thresholds>(json)?;
    if !thresholds.margin_threshold.is_finite() {
        return Err(Error::InvalidAsset {
            detail: "thresholds.json margin_threshold is not a finite number".to_string(),
        });
    }
    Ok(thresholds.margin_threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_revision_is_a_full_commit_hash() {
        assert_eq!(DEFAULT_MODEL_REVISION.len(), 40);
        assert!(
            DEFAULT_MODEL_REVISION
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
    }

    #[test]
    fn builder_overrides_are_independent() {
        let config = InjectionGuardConfig::default()
            .with_revision("deadbeef")
            .with_cache_dir("/tmp/x")
            .with_execution_provider(ExecutionProvider::WebGpu);
        assert_eq!(config.revision(), "deadbeef");
        assert_eq!(config.cache_dir().unwrap().to_string_lossy(), "/tmp/x");
        assert_eq!(config.execution_provider(), ExecutionProvider::WebGpu);
    }

    #[test]
    fn margin_threshold_ignores_extra_fields() {
        let json = r#"{"probability_threshold": 0.98, "margin_threshold": 3.9, "rule": "x"}"#;
        assert!((margin_threshold_from_json(json).unwrap() - 3.9).abs() < f32::EPSILON);
    }

    #[test]
    fn margin_threshold_rejects_missing_field() {
        assert!(margin_threshold_from_json(r#"{"probability_threshold": 0.98}"#).is_err());
    }
}
