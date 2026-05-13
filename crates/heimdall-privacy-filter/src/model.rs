use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, Result};

/// Hugging Face model repository for OpenAI privacy-filter.
pub const MODEL_REPOSITORY: &str = "openai/privacy-filter";

/// Pinned model revision used by default setup/runtime configuration.
pub const DEFAULT_MODEL_REVISION: &str = "7ffa9a043d54d1be65afb281eddf0ffbe629385b";

const CONFIG_FILE: &str = "config.json";
const TOKENIZER_FILE: &str = "tokenizer.json";
const TOKENIZER_CONFIG_FILE: &str = "tokenizer_config.json";
const VITERBI_FILE: &str = "viterbi_calibration.json";

/// ONNX model precision/quantization variant to use.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivacyFilterVariant {
    /// Q4 variant selected for the initial setup default.
    #[default]
    Q4,
    /// Q4F16 variant.
    Q4F16,
    /// Quantized variant published by the model repository.
    Quantized,
    /// FP16 variant.
    Fp16,
    /// Full precision model variant.
    Full,
}

impl PrivacyFilterVariant {
    /// Return the ONNX file path in the Hugging Face repository.
    #[must_use]
    pub const fn onnx_file(self) -> &'static str {
        match self {
            Self::Q4 => "onnx/model_q4.onnx",
            Self::Q4F16 => "onnx/model_q4f16.onnx",
            Self::Quantized => "onnx/model_quantized.onnx",
            Self::Fp16 => "onnx/model_fp16.onnx",
            Self::Full => "onnx/model.onnx",
        }
    }

    /// Return external-data sidecar paths that must remain beside the ONNX file.
    #[must_use]
    pub const fn sidecar_files(self) -> &'static [&'static str] {
        match self {
            Self::Q4 => &["onnx/model_q4.onnx_data"],
            Self::Q4F16 => &["onnx/model_q4f16.onnx_data"],
            Self::Quantized => &["onnx/model_quantized.onnx_data"],
            Self::Fp16 => &["onnx/model_fp16.onnx_data", "onnx/model_fp16.onnx_data_1"],
            Self::Full => &[
                "onnx/model.onnx_data",
                "onnx/model.onnx_data_1",
                "onnx/model.onnx_data_2",
            ],
        }
    }

    /// Return all repository files required for setup of this variant.
    #[must_use]
    pub fn required_files(self) -> Vec<&'static str> {
        let mut files = vec![
            CONFIG_FILE,
            TOKENIZER_FILE,
            TOKENIZER_CONFIG_FILE,
            VITERBI_FILE,
            self.onnx_file(),
        ];
        files.extend_from_slice(self.sidecar_files());
        files
    }
}

/// ONNX Runtime execution provider selection for privacy-filter inference.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivacyExecutionProvider {
    /// CPU execution provider. This is the default and most portable path.
    #[default]
    Cpu,
    /// WebGPU execution provider. Must be explicitly selected.
    WebGpu,
}

/// User-facing runtime/setup configuration for privacy filtering.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyFilterConfig {
    enabled: bool,
    variant: PrivacyFilterVariant,
    revision: String,
    cache_dir: Option<PathBuf>,
    execution_provider: PrivacyExecutionProvider,
}

impl PrivacyFilterConfig {
    /// Create disabled privacy-filter configuration.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            variant: PrivacyFilterVariant::default(),
            revision: DEFAULT_MODEL_REVISION.to_string(),
            cache_dir: None,
            execution_provider: PrivacyExecutionProvider::default(),
        }
    }

    /// Create enabled privacy-filter configuration with safe defaults.
    #[must_use]
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Self::disabled()
        }
    }

    /// Return whether privacy filtering is enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return the selected model variant.
    #[must_use]
    pub const fn variant(&self) -> PrivacyFilterVariant {
        self.variant
    }

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
    pub const fn execution_provider(&self) -> PrivacyExecutionProvider {
        self.execution_provider
    }

    /// Return a copy with the selected model variant.
    #[must_use]
    pub const fn with_variant(mut self, variant: PrivacyFilterVariant) -> Self {
        self.variant = variant;
        self
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
    pub const fn with_execution_provider(mut self, provider: PrivacyExecutionProvider) -> Self {
        self.execution_provider = provider;
        self
    }
}

impl Default for PrivacyFilterConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Absolute paths to local model assets required by the runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelAssetPaths {
    /// Model config path.
    pub config: PathBuf,
    /// Tokenizer JSON path.
    pub tokenizer: PathBuf,
    /// Tokenizer config JSON path.
    pub tokenizer_config: PathBuf,
    /// Viterbi calibration JSON path.
    pub viterbi: PathBuf,
    /// ONNX model path.
    pub onnx: PathBuf,
    /// ONNX external-data sidecar paths.
    pub sidecars: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct TokenizerMetadata {
    model_max_length: Option<Value>,
}

/// Parse and validate the usable token limit from cached tokenizer metadata.
pub(crate) fn usable_token_limit_from_tokenizer_config_json(json: &str) -> Result<usize> {
    let metadata = serde_json::from_str::<TokenizerMetadata>(json)?;
    let Some(value) = metadata.model_max_length else {
        return Err(Error::InvalidAsset {
            detail: "tokenizer_config.json is missing model_max_length".to_string(),
        });
    };
    let limit = match value {
        Value::Number(number) => number.as_u64(),
        Value::String(raw) => raw.parse::<u64>().ok(),
        _ => None,
    }
    .ok_or_else(|| Error::InvalidAsset {
        detail: "tokenizer_config.json model_max_length is not a positive integer".to_string(),
    })?;
    let limit = usize::try_from(limit).map_err(|error| Error::InvalidAsset {
        detail: format!("tokenizer_config.json model_max_length is too large: {error}"),
    })?;
    if limit < 3 {
        return Err(Error::InvalidAsset {
            detail: format!(
                "tokenizer_config.json model_max_length {limit} is too small for overlapping windows"
            ),
        });
    }
    Ok(limit)
}

impl ModelAssetPaths {
    /// Build asset paths from the Hugging Face snapshot root for the selected variant.
    #[must_use]
    pub fn from_snapshot(snapshot: impl AsRef<Path>, variant: PrivacyFilterVariant) -> Self {
        let snapshot = snapshot.as_ref();
        Self {
            config: snapshot.join(CONFIG_FILE),
            tokenizer: snapshot.join(TOKENIZER_FILE),
            tokenizer_config: snapshot.join(TOKENIZER_CONFIG_FILE),
            viterbi: snapshot.join(VITERBI_FILE),
            onnx: snapshot.join(variant.onnx_file()),
            sidecars: variant
                .sidecar_files()
                .iter()
                .map(|path| snapshot.join(path))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_maps_to_a_different_onnx_file() {
        let files: std::collections::HashSet<&'static str> = [
            PrivacyFilterVariant::Q4.onnx_file(),
            PrivacyFilterVariant::Q4F16.onnx_file(),
            PrivacyFilterVariant::Quantized.onnx_file(),
            PrivacyFilterVariant::Fp16.onnx_file(),
            PrivacyFilterVariant::Full.onnx_file(),
        ]
        .into();
        assert_eq!(files.len(), 5, "each variant must have a unique onnx file");
    }

    #[test]
    fn required_files_dedupe_onnx_and_sidecar_overlap() {
        for variant in [
            PrivacyFilterVariant::Q4,
            PrivacyFilterVariant::Q4F16,
            PrivacyFilterVariant::Quantized,
            PrivacyFilterVariant::Fp16,
            PrivacyFilterVariant::Full,
        ] {
            let files = variant.required_files();
            assert!(files.contains(&variant.onnx_file()));
            assert!(
                files.contains(&CONFIG_FILE),
                "config.json missing for {variant:?}"
            );
            // onnx_file must appear exactly once.
            let count = files.iter().filter(|&&f| f == variant.onnx_file()).count();
            assert_eq!(
                count, 1,
                "onnx_file duplicated in required_files for {variant:?}"
            );
        }
    }

    #[test]
    fn from_snapshot_paths_are_under_root() {
        let paths = ModelAssetPaths::from_snapshot("/base", PrivacyFilterVariant::Q4);
        assert!(paths.config.starts_with("/base"));
        assert!(paths.tokenizer.starts_with("/base"));
        assert!(paths.onnx.starts_with("/base"));
        assert!(paths.sidecars.iter().all(|s| s.starts_with("/base")));
    }

    #[test]
    fn config_enabled_disabled_are_opposite() {
        assert!(PrivacyFilterConfig::enabled().is_enabled());
        assert!(!PrivacyFilterConfig::disabled().is_enabled());
        assert!(!PrivacyFilterConfig::default().is_enabled());
    }

    #[test]
    fn builder_overrides_are_independent() {
        let c = PrivacyFilterConfig::enabled()
            .with_variant(PrivacyFilterVariant::Fp16)
            .with_revision("deadbeef")
            .with_cache_dir("/tmp/x")
            .with_execution_provider(PrivacyExecutionProvider::WebGpu);
        assert_eq!(c.variant(), PrivacyFilterVariant::Fp16);
        assert_eq!(c.revision(), "deadbeef");
        assert_eq!(c.cache_dir().unwrap().to_string_lossy(), "/tmp/x");
        assert_eq!(c.execution_provider(), PrivacyExecutionProvider::WebGpu);
    }

    #[test]
    fn serde_roundtrips_every_variant() {
        for v in [
            PrivacyFilterVariant::Q4,
            PrivacyFilterVariant::Q4F16,
            PrivacyFilterVariant::Quantized,
            PrivacyFilterVariant::Fp16,
            PrivacyFilterVariant::Full,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: PrivacyFilterVariant = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn serde_rejects_unknown_config_field() {
        let json = r#"{"enabled":true,"variant":"q4","revision":"abc","cache_dir":null,"execution_provider":"cpu","EVIL":true}"#;
        assert!(serde_json::from_str::<PrivacyFilterConfig>(json).is_err());
    }

    #[test]
    fn revision_constant_is_40_hex_chars() {
        assert_eq!(DEFAULT_MODEL_REVISION.len(), 40);
        assert!(
            DEFAULT_MODEL_REVISION
                .chars()
                .all(|c: char| c.is_ascii_hexdigit())
        );
    }

    // --- real model tests ---

    #[test]
    fn usable_token_limit_reads_numeric_metadata() {
        let json = r#"{"model_max_length": 128000}"#;
        assert_eq!(
            usable_token_limit_from_tokenizer_config_json(json).unwrap(),
            128000
        );
    }

    #[test]
    fn usable_token_limit_reads_string_metadata() {
        let json = r#"{"model_max_length": "128000"}"#;
        assert_eq!(
            usable_token_limit_from_tokenizer_config_json(json).unwrap(),
            128000
        );
    }

    #[test]
    fn usable_token_limit_rejects_missing_metadata() {
        assert!(usable_token_limit_from_tokenizer_config_json(r#"{}"#).is_err());
    }

    #[test]
    fn usable_token_limit_rejects_unusable_metadata() {
        assert!(
            usable_token_limit_from_tokenizer_config_json(r#"{"model_max_length": 1}"#).is_err()
        );
        assert!(
            usable_token_limit_from_tokenizer_config_json(r#"{"model_max_length": 2}"#).is_err()
        );
    }

    #[test]
    fn setup_caches_all_files_for_q4() {
        let f = crate::testutil::fixture();
        assert!(f.assets.config.exists());
        assert!(f.assets.tokenizer.exists());
        assert!(f.assets.tokenizer_config.exists());
        assert!(f.assets.viterbi.exists());
        assert!(f.assets.onnx.exists());
        for sidecar in &f.assets.sidecars {
            assert!(sidecar.exists(), "missing sidecar {}", sidecar.display());
        }
    }

    #[test]
    fn real_tokenizer_metadata_has_usable_limit() {
        let f = crate::testutil::fixture();
        assert!(f.usable_token_limit > 1);
    }
}
