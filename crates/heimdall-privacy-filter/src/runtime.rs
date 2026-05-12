use std::path::{Path, PathBuf};

use hf_hub::{Cache, Repo, RepoType};
use tokenizers::Tokenizer;

use crate::input::{EncodedPrivacyInput, PrivacyTextInput};
use crate::model::{MODEL_REPOSITORY, ModelAssetPaths, PrivacyFilterConfig};
use crate::output::{PrivacyLabels, PrivacySpanOutput, ViterbiCalibration, decode_logits};
use crate::session::PrivacyOnnxSession;
use crate::{Error, Result};

/// Cache-backed privacy-filter runtime used by redaction commands/tool integrations.
pub struct PrivacyFilterRuntime {
    tokenizer: Tokenizer,
    labels: PrivacyLabels,
    calibration: ViterbiCalibration,
    session: PrivacyOnnxSession,
}

impl PrivacyFilterRuntime {
    /// Load the privacy-filter runtime from the local Hugging Face cache only.
    pub fn load(config: PrivacyFilterConfig) -> Result<Self> {
        if !config.is_enabled() {
            return Err(Error::Disabled);
        }

        let assets = cached_asset_paths(&config)?;
        let config_json = std::fs::read_to_string(&assets.config)?;
        let labels = PrivacyLabels::from_config_json(&config_json)?;
        let calibration =
            ViterbiCalibration::from_json(&std::fs::read_to_string(&assets.viterbi)?)?;
        let tokenizer = Tokenizer::from_file(&assets.tokenizer)?;
        let session = PrivacyOnnxSession::load(&assets.onnx, &config)?;

        Ok(Self {
            tokenizer,
            labels,
            calibration,
            session,
        })
    }

    /// Detect sensitive spans in one text input.
    pub fn detect_spans(&mut self, text: &str) -> Result<PrivacySpanOutput> {
        self.detect_batch(PrivacyTextInput::single(text.to_owned())?)
    }

    /// Detect sensitive spans in one or more text inputs.
    pub fn detect_batch(&mut self, input: PrivacyTextInput) -> Result<PrivacySpanOutput> {
        let encoded =
            EncodedPrivacyInput::encode(input, &self.tokenizer, self.labels.pad_token_id())?;
        let context = encoded.context.clone();
        let logits = self.session.run(&encoded)?;
        decode_logits(logits, context, &self.labels, self.calibration)
    }
}

fn cached_asset_paths(config: &PrivacyFilterConfig) -> Result<ModelAssetPaths> {
    let cache = match config.cache_dir() {
        Some(cache_dir) => Cache::new(cache_dir.to_path_buf()),
        None => Cache::from_env(),
    };
    let repo = Repo::with_revision(
        MODEL_REPOSITORY.to_string(),
        RepoType::Model,
        config.revision().to_string(),
    );
    let repo = cache.repo(repo);
    let config_path = repo
        .get("config.json")
        .ok_or_else(|| missing_cache_error(config, "config.json"))?;
    let snapshot_root = snapshot_root_for(&config_path, "config.json")?;
    Ok(ModelAssetPaths::from_snapshot(
        snapshot_root,
        config.variant(),
    ))
}

fn missing_cache_error(config: &PrivacyFilterConfig, file: &str) -> Error {
    Error::NotReady {
        asset: file.to_string(),
        repository: MODEL_REPOSITORY.to_string(),
        revision: config.revision().to_string(),
    }
}

fn snapshot_root_for(downloaded_file: &Path, repo_relative: &str) -> Result<PathBuf> {
    let mut root = downloaded_file.to_path_buf();
    for _ in Path::new(repo_relative).components() {
        root.pop();
    }
    if root.as_os_str().is_empty() {
        return Err(Error::NotReady {
            asset: downloaded_file.display().to_string(),
            repository: MODEL_REPOSITORY.to_string(),
            revision: String::new(),
        });
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;

    #[test]
    fn load_rejects_disabled_config() {
        assert!(PrivacyFilterRuntime::load(PrivacyFilterConfig::disabled()).is_err());
    }

    #[test]
    fn load_succeeds_with_real_model() {
        let f = testutil::fixture();
        PrivacyFilterRuntime::load(f.config.clone()).unwrap();
    }

    #[test]
    fn detect_spans_finds_email() {
        let f = testutil::fixture();
        let mut runtime = PrivacyFilterRuntime::load(f.config.clone()).unwrap();
        let output = runtime.detect_spans("alice@example.com").unwrap();
        assert!(!output.spans.is_empty());
        assert!(output.spans.iter().any(|s| s.label().contains("email")));
    }

    #[test]
    fn detect_batch_two_windows() {
        let f = testutil::fixture();
        let mut runtime = PrivacyFilterRuntime::load(f.config.clone()).unwrap();
        let input = PrivacyTextInput::new(vec![
            "alice@example.com".to_string(),
            "415-555-1234".to_string(),
        ])
        .unwrap();
        let output = runtime.detect_batch(input).unwrap();
        assert!(!output.spans.is_empty());
    }

    #[test]
    fn detect_spans_plain_text_does_not_error() {
        let f = testutil::fixture();
        let mut runtime = PrivacyFilterRuntime::load(f.config.clone()).unwrap();
        let _ = runtime.detect_spans("just some words").unwrap();
    }
}
