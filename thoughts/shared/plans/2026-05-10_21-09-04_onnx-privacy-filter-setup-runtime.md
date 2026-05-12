---
date: 2026-05-10T21:09:04-0700
author: Ivan Porto Carrero
commit: d9d522e
branch: onnx-privacy
repository: heimdall-sandbox
topic: "ONNX privacy-filter setup and runtime integration"
tags: [plan, rust, onnx, privacy-filter, setup, cli, redaction]
status: ready
parent: thoughts/shared/designs/2026-05-09_15-45-19_onnx-privacy-filter-setup-runtime.md
last_updated: 2026-05-10T21:09:04-0700
last_updated_by: Ivan Porto Carrero
---

# ONNX Privacy-Filter Setup and Runtime Integration — Implementation Plan

## Overview

Implement the design at `thoughts/shared/designs/2026-05-09_15-45-19_onnx-privacy-filter-setup-runtime.md`: a new `heimdall-privacy-filter` crate that integrates OpenAI `openai/privacy-filter` with direct `ort` + `tokenizers`, exposed through `heimdall-sandbox setup` (model download) and `heimdall-sandbox privacy-filter redact` (full captured-text redaction for LLM-facing output).

The product boundary is **capture first, redact before LLM context**: raw output shown to the trusted user/UI; redacted output sent to the model. No exec stdio mutation, no streaming redaction, no policy JSON changes.

## Desired End State

```sh
heimdall-sandbox setup                                    # downloads q4 model to HF cache
heimdall-sandbox privacy-filter redact --text 'email alice@example.com'
# → email [REDACTED:EMAIL]

printf 'email alice@example.com' | heimdall-sandbox privacy-filter redact --stdin
# → email [REDACTED:EMAIL]
```

- `mise format` passes.
- `mise run --force test` passes.
- No `#[allow(...)]`, `#[ignore]`, or test weakening.
- No exec/executor/stdio/policy behavioral changes.
- CLI refactored into command modules with no behavioral regression.

## What We're NOT Doing

- Automatic model download during redaction/runtime use.
- Bundled model assets in release artifacts.
- `exec` integration, child stdout/stderr interception, forced pipes, or output-forwarding changes.
- Policy JSON privacy execution behavior.
- Streaming writer/window redaction API.
- Ready-manifest or cache-validation/preflight gate.
- CoreML/CUDA/DirectML/OpenVINO/XNNPACK execution providers.
- ORP/gline-rs/fastembed-rs as dependencies (references only).

---

## Phase 1: Privacy Crate Foundation

### Overview

Create the full `heimdall-privacy-filter` crate with all runtime modules and register it in the workspace. This phase produces a self-contained crate that compiles independently — no CLI wiring yet.

**Parallel with Phase 2** (separate crates, no cross-dependency).

### Changes Required

#### 1. Workspace registration
**File**: `Cargo.toml`
**Changes**: Add `heimdall-privacy-filter` to workspace members and workspace dependencies (`hf-hub`, `ndarray`, `ort`, `tokenizers`).

```toml
[workspace]
members = [
    "crates/heimdall-core",
    "crates/heimdall-linux-sandbox",
    "crates/heimdall-macos-sandbox",
    "crates/heimdall-privacy-filter",
    "crates/heimdall-process-hardening",
    "crates/heimdall-sandbox",
    "crates/heimdall-sandbox-policy",
]
resolver = "3"

[workspace.package]
edition = "2024"
homepage = "https://github.com/casualjim/heimdall-sandbox"
license = "MIT"
readme = "README.md"
repository = "https://github.com/casualjim/heimdall-sandbox"
version = "0.1.10"

[workspace.dependencies]
clap = { version = "4.5.51", features = ["derive"] }
heimdall-core = { version = "0.1.10", path = "crates/heimdall-core" }
heimdall-linux-sandbox = { version = "0.1.10", path = "crates/heimdall-linux-sandbox" }
heimdall-macos-sandbox = { version = "0.1.10", path = "crates/heimdall-macos-sandbox" }
heimdall-privacy-filter = { version = "0.1.10", path = "crates/heimdall-privacy-filter" }
heimdall-process-hardening = { version = "0.1.10", path = "crates/heimdall-process-hardening" }
heimdall-sandbox-policy = { version = "0.1.10", path = "crates/heimdall-sandbox-policy" }
hf-hub = { version = "0.5.0", default-features = false, features = ["ureq", "rustls-tls"] }
ignore = "0.4.25"
libc = "0.2.177"
ndarray = "0.17.1"
ort = { version = "=2.0.0-rc.12", features = ["download-binaries", "ndarray", "webgpu"] }
schemars = { version = "1.0", features = ["derive"] }
serde = { version = "1.0.228", features = ["derive"] }
serde_json = "1.0.145"
shellexpand = "3.1.1"
signal-hook = "0.3.18"
thiserror = "2.0.17"
tokenizers = { version = "0.23.1", default-features = false }

# The profile that 'dist' will build with
[profile.dist]
inherits = "release"
lto = "thin"
```

#### 2. Privacy crate manifest
**File**: `crates/heimdall-privacy-filter/Cargo.toml`
**Changes**: New file — crate manifest with `hf-hub`, `ndarray`, `ort`, `serde`, `serde_json`, `thiserror`, `tokenizers` dependencies.

```toml
[package]
description = "OpenAI privacy-filter setup, ONNX Runtime inference, and text redaction for Heimdall."
edition.workspace = true
homepage.workspace = true
license.workspace = true
name = "heimdall-privacy-filter"
readme.workspace = true
repository.workspace = true
version.workspace = true

[dependencies]
hf-hub.workspace = true
ndarray.workspace = true
ort.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokenizers.workspace = true
```

#### 3. Crate root
**File**: `crates/heimdall-privacy-filter/src/lib.rs`
**Changes**: New file — module declarations, error enum, `Result<T>` alias, public re-exports of all API types.

```rust
//! OpenAI privacy-filter setup and local ONNX inference support.
//
//! The crate owns model asset metadata, direct `ort` session execution, token
//! offset mapping, BIOES/Viterbi decoding, and full-text redaction
//! primitives. It intentionally depends on `ort` directly rather than through a
//! thin ONNX wrapper crate so Heimdall can adopt `ort` fixes without waiting on
//! another crate's release cadence.

mod input;
mod model;
mod output;
mod session;

pub mod redaction;
pub mod runtime;
pub mod setup;

use thiserror::Error as ThisError;

pub use input::{EncodedPrivacyInput, PrivacyContext, PrivacyTextInput};
pub use model::{
    DEFAULT_MODEL_REVISION, MODEL_REPOSITORY, ModelAssetPaths, PrivacyExecutionProvider,
    PrivacyFilterConfig, PrivacyFilterVariant,
};
pub use output::{DetectedSpan, PrivacyLabels, PrivacySpanOutput, ViterbiCalibration};
pub use redaction::{redact_captured_text, redact_text, CapturedTextRedaction};
pub use session::{LogitsTensor, PrivacyOnnxSession};

/// Result type for privacy-filter operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by privacy-filter setup, loading, inference, and decoding.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Required model asset is missing from the cache or setup output.
    #[error("privacy filter asset missing: {0}")]
    MissingAsset(String),
    /// A model/config/tokenizer file was present but invalid.
    #[error("privacy filter asset invalid: {0}")]
    InvalidAsset(String),
    /// Hugging Face cache/download operation failed during explicit setup.
    #[error("privacy filter setup failed: {0}")]
    Setup(String),
    /// Runtime cache-only loading failed.
    #[error("privacy filter runtime is not ready: {0}; run `heimdall-sandbox setup`")]
    NotReady(String),
    /// Tokenizer loading or encoding failed.
    #[error("privacy filter tokenizer failed: {0}")]
    Tokenizer(String),
    /// ONNX Runtime session loading or inference failed.
    #[error("privacy filter ONNX Runtime failed: {0}")]
    Onnx(String),
    /// ONNX model inputs/outputs are incompatible with the OpenAI privacy-filter contract.
    #[error("privacy filter model schema mismatch: {0}")]
    Schema(String),
    /// Logit output or label metadata could not be decoded.
    #[error("privacy filter decode failed: {0}")]
    Decode(String),
    /// I/O failed while reading setup assets or writing redacted output.
    #[error("privacy filter I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parsing or serialization failed.
    #[error("privacy filter JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<ort::Error> for Error {
    fn from(error: ort::Error) -> Self {
        Self::Onnx(error.to_string())
    }
}

impl From<tokenizers::Error> for Error {
    fn from(error: tokenizers::Error) -> Self {
        Self::Tokenizer(error.to_string())
    }
}
```

#### 4. Model metadata
**File**: `crates/heimdall-privacy-filter/src/model.rs`
**Changes**: New file — `MODEL_REPOSITORY`, `DEFAULT_MODEL_REVISION`, `PrivacyFilterVariant`, `PrivacyExecutionProvider`, `PrivacyFilterConfig`, `ModelAssetPaths`.

```rust
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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
        let mut files = vec![CONFIG_FILE, TOKENIZER_FILE, TOKENIZER_CONFIG_FILE, VITERBI_FILE, self.onnx_file()];
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
```

#### 5. Input encoding
**File**: `crates/heimdall-privacy-filter/src/input.rs`
**Changes**: New file — `PrivacyTextInput`, `PrivacyContext`, `EncodedPrivacyInput` with tokenizer offset handling and tensor construction.

```rust
use ndarray::{Array, Array2, ArrayView};
use tokenizers::Tokenizer;

use crate::{Error, Result};

/// Raw text input for privacy-filter detection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyTextInput {
    texts: Vec<String>,
}

impl PrivacyTextInput {
    /// Create text input from one or more text windows.
    pub fn new(texts: Vec<String>) -> Result<Self> {
        if texts.is_empty() {
            return Err(Error::InvalidAsset("privacy filter input cannot be empty".to_string()));
        }
        Ok(Self { texts })
    }

    /// Create text input for a single text window.
    pub fn single(text: impl Into<String>) -> Result<Self> {
        Self::new(vec![text.into()])
    }

    /// Return the raw text windows.
    #[must_use]
    pub fn texts(&self) -> &[String] {
        &self.texts
    }
}

/// Token context preserved from preprocessing through output decoding.
#[derive(Clone, Debug)]
pub struct PrivacyContext {
    texts: Vec<String>,
    token_offsets: Vec<Vec<(usize, usize)>>,
}

impl PrivacyContext {
    /// Return the original text windows.
    #[must_use]
    pub fn texts(&self) -> &[String] {
        &self.texts
    }

    /// Return token byte offsets per text window.
    #[must_use]
    pub fn token_offsets(&self) -> &[Vec<(usize, usize)>] {
        &self.token_offsets
    }

    /// Resolve a token span into byte offsets, skipping special-token zero offsets.
    pub fn byte_span(&self, sequence: usize, start_token: usize, end_token: usize) -> Result<Option<(usize, usize)>> {
        let offsets = self
            .token_offsets
            .get(sequence)
            .ok_or_else(|| Error::Decode(format!("sequence {sequence} is missing from context")))?;
        let mut start = None;
        let mut end = None;
        for index in start_token..=end_token {
            let (token_start, token_end) = *offsets
                .get(index)
                .ok_or_else(|| Error::Decode(format!("token {index} is missing from context")))?;
            if token_start == token_end {
                continue;
            }
            start.get_or_insert(token_start);
            end = Some(token_end);
        }
        Ok(start.zip(end))
    }
}

/// Encoded tensors for ONNX Runtime inference plus decoding context.
#[derive(Clone, Debug)]
pub struct EncodedPrivacyInput {
    /// Input IDs tensor with shape `[B, T]`.
    pub input_ids: Array2<i64>,
    /// Attention mask tensor with shape `[B, T]`.
    pub attention_mask: Array2<i64>,
    /// Context needed to convert token predictions back to text spans.
    pub context: PrivacyContext,
}

impl EncodedPrivacyInput {
    /// Encode privacy-filter input using the local tokenizer.
    pub fn encode(input: PrivacyTextInput, tokenizer: &Tokenizer, pad_token_id: i64) -> Result<Self> {
        let mut rows = Vec::with_capacity(input.texts.len());
        let mut masks = Vec::with_capacity(input.texts.len());
        let mut token_offsets = Vec::with_capacity(input.texts.len());
        let mut max_len = 0;

        for text in input.texts() {
            let encoding = tokenizer.encode(text.as_str(), true)?;
            let ids = encoding
                .get_ids()
                .iter()
                .map(|id| i64::from(*id))
                .collect::<Vec<_>>();
            let attention = encoding
                .get_attention_mask()
                .iter()
                .map(|value| i64::from(*value))
                .collect::<Vec<_>>();
            max_len = max_len.max(ids.len());
            rows.push(ids);
            masks.push(attention);
            token_offsets.push(encoding.get_offsets().to_vec());
        }

        let mut input_ids = Array::zeros((0, max_len));
        let mut attention_mask = Array::zeros((0, max_len));
        for (mut ids, mut mask) in rows.into_iter().zip(masks) {
            ids.resize(max_len, pad_token_id);
            mask.resize(max_len, 0);
            input_ids.push_row(ArrayView::from(&ids))?;
            attention_mask.push_row(ArrayView::from(&mask))?;
        }

        Ok(Self {
            input_ids,
            attention_mask,
            context: PrivacyContext {
                texts: input.texts,
                token_offsets,
            },
        })
    }
}
```

#### 6. Output decoding
**File**: `crates/heimdall-privacy-filter/src/output.rs`
**Changes**: New file — `DetectedSpan`, `PrivacySpanOutput`, `PrivacyLabels`, `ViterbiCalibration`, `decode_logits` with BIOES/Viterbi path decoding.

```rust
use std::collections::BTreeMap;

use ndarray::{ArrayD, Ix2, Ix3};
use serde::Deserialize;

use crate::input::PrivacyContext;
use crate::{Error, Result};

/// One detected sensitive span in the original text.
#[derive(Clone, Debug, PartialEq)]
pub struct DetectedSpan {
    /// Input window index.
    pub sequence: usize,
    /// Start byte offset in the input window.
    pub start: usize,
    /// End byte offset in the input window.
    pub end: usize,
    /// Privacy category without BIOES prefix.
    pub label: String,
    /// Approximate confidence score for this span.
    pub score: f32,
}

/// Privacy-filter detection output for a batch of text windows.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PrivacySpanOutput {
    /// Detected sensitive spans.
    pub spans: Vec<DetectedSpan>,
}

#[derive(Clone, Debug, Deserialize)]
struct ModelConfig {
    id2label: BTreeMap<String, String>,
    pad_token_id: Option<i64>,
}

/// Parsed model labels and tokenizer settings from `config.json`.
#[derive(Clone, Debug)]
pub struct PrivacyLabels {
    labels: Vec<Label>,
    pad_token_id: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Label {
    prefix: LabelPrefix,
    category: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LabelPrefix {
    Outside,
    Begin,
    Inside,
    End,
    Singleton,
}

impl PrivacyLabels {
    /// Parse and validate OpenAI privacy-filter labels from `config.json`.
    pub fn from_config_json(json: &str) -> Result<Self> {
        let config = serde_json::from_str::<ModelConfig>(json)?;
        let mut labels = Vec::with_capacity(config.id2label.len());
        for expected in 0..config.id2label.len() {
            let raw = config
                .id2label
                .get(&expected.to_string())
                .ok_or_else(|| Error::InvalidAsset(format!("missing id2label entry {expected}")))?;
            labels.push(Label::parse(raw)?);
        }
        if labels.len() != 33 {
            return Err(Error::InvalidAsset(format!(
                "expected 33 labels, found {}",
                labels.len()
            )));
        }
        if labels.first().is_none_or(|label| label.prefix != LabelPrefix::Outside) {
            return Err(Error::InvalidAsset("label 0 must be O".to_string()));
        }
        Ok(Self {
            labels,
            pad_token_id: config.pad_token_id.unwrap_or(199_999),
        })
    }

    /// Return label count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Return tokenizer pad token ID from model config.
    #[must_use]
    pub const fn pad_token_id(&self) -> i64 {
        self.pad_token_id
    }

    fn get(&self, index: usize) -> Result<&Label> {
        self.labels
            .get(index)
            .ok_or_else(|| Error::Decode(format!("label index {index} is out of range")))
    }
}

impl Label {
    fn parse(raw: &str) -> Result<Self> {
        if raw == "O" {
            return Ok(Self {
                prefix: LabelPrefix::Outside,
                category: None,
            });
        }
        let Some((prefix, category)) = raw.split_once('-') else {
            return Err(Error::InvalidAsset(format!("invalid label {raw}")));
        };
        let prefix = match prefix {
            "B" => LabelPrefix::Begin,
            "I" => LabelPrefix::Inside,
            "E" => LabelPrefix::End,
            "S" => LabelPrefix::Singleton,
            other => return Err(Error::InvalidAsset(format!("invalid BIOES prefix {other}"))),
        };
        Ok(Self {
            prefix,
            category: Some(category.to_string()),
        })
    }

    fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ViterbiFile {
    operating_points: BTreeMap<String, OperatingPoint>,
}

#[derive(Clone, Debug, Deserialize)]
struct OperatingPoint {
    biases: ViterbiCalibration,
}

/// Viterbi transition calibration values.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
pub struct ViterbiCalibration {
    /// Bias for staying in background.
    pub transition_bias_background_stay: f32,
    /// Bias for background to begin/singleton.
    pub transition_bias_background_to_start: f32,
    /// Bias for end/singleton to background.
    pub transition_bias_end_to_background: f32,
    /// Bias for end/singleton to begin/singleton.
    pub transition_bias_end_to_start: f32,
    /// Bias for inside continuation.
    pub transition_bias_inside_to_continue: f32,
    /// Bias for inside to end.
    pub transition_bias_inside_to_end: f32,
}

impl ViterbiCalibration {
    /// Parse the default operating point from `viterbi_calibration.json`.
    pub fn from_json(json: &str) -> Result<Self> {
        let file = serde_json::from_str::<ViterbiFile>(json)?;
        file.operating_points
            .get("default")
            .map(|point| point.biases)
            .ok_or_else(|| Error::InvalidAsset("viterbi default operating point is missing".to_string()))
    }
}

/// Decode model logits to text spans using constrained BIOES Viterbi decoding.
pub fn decode_logits(
    logits: ArrayD<f32>,
    context: PrivacyContext,
    labels: &PrivacyLabels,
    calibration: ViterbiCalibration,
) -> Result<PrivacySpanOutput> {
    let dimensions = logits.shape().to_vec();
    match dimensions.as_slice() {
        [tokens, classes] => {
            if *classes != labels.len() {
                return Err(Error::Decode(format!("expected {} classes, found {classes}", labels.len())));
            }
            let logits = logits
                .into_dimensionality::<Ix2>()
                .map_err(|error| Error::Decode(error.to_string()))?;
            decode_sequence(0, logits.view(), &context, labels, calibration)
        }
        [batch, _tokens, classes] => {
            if *classes != labels.len() {
                return Err(Error::Decode(format!("expected {} classes, found {classes}", labels.len())));
            }
            let logits = logits
                .into_dimensionality::<Ix3>()
                .map_err(|error| Error::Decode(error.to_string()))?;
            let mut spans = Vec::new();
            for sequence in 0..*batch {
                let output = decode_sequence(
                    sequence,
                    logits.index_axis(ndarray::Axis(0), sequence),
                    &context,
                    labels,
                    calibration,
                )?;
                spans.extend(output.spans);
            }
            Ok(PrivacySpanOutput { spans })
        }
        _ => Err(Error::Decode(format!(
            "expected logits shape [T, C] or [B, T, C], found {dimensions:?}"
        ))),
    }
}

fn decode_sequence(
    sequence: usize,
    logits: ndarray::ArrayView2<'_, f32>,
    context: &PrivacyContext,
    labels: &PrivacyLabels,
    calibration: ViterbiCalibration,
) -> Result<PrivacySpanOutput> {
    let path = viterbi_path(logits, labels, calibration)?;
    let mut spans = Vec::new();
    let mut open: Option<(usize, String, f32)> = None;

    for (token, label_index) in path.into_iter().enumerate() {
        let label = labels.get(label_index)?;
        match label.prefix {
            LabelPrefix::Outside => open = None,
            LabelPrefix::Begin => {
                if let Some(category) = label.category() {
                    open = Some((token, category.to_string(), score_at(logits, token, label_index)));
                }
            }
            LabelPrefix::Inside => {}
            LabelPrefix::End => {
                if let (Some((start, category, start_score)), Some(end_category)) = (open.take(), label.category())
                    && category == end_category
                    && let Some((start_byte, end_byte)) = context.byte_span(sequence, start, token)?
                {
                    spans.push(DetectedSpan {
                        sequence,
                        start: start_byte,
                        end: end_byte,
                        label: category,
                        score: start_score.min(score_at(logits, token, label_index)),
                    });
                }
            }
            LabelPrefix::Singleton => {
                open = None;
                if let Some(category) = label.category()
                    && let Some((start, end)) = context.byte_span(sequence, token, token)?
                {
                    spans.push(DetectedSpan {
                        sequence,
                        start,
                        end,
                        label: category.to_string(),
                        score: score_at(logits, token, label_index),
                    });
                }
            }
        }
    }

    Ok(PrivacySpanOutput { spans })
}

fn viterbi_path(
    logits: ndarray::ArrayView2<'_, f32>,
    labels: &PrivacyLabels,
    calibration: ViterbiCalibration,
) -> Result<Vec<usize>> {
    let (tokens, classes) = logits.dim();
    if classes != labels.len() {
        return Err(Error::Decode(format!("expected {} classes, found {classes}", labels.len())));
    }
    if tokens == 0 {
        return Ok(Vec::new());
    }

    let mut scores = vec![vec![f32::NEG_INFINITY; classes]; tokens];
    let mut back = vec![vec![0_usize; classes]; tokens];
    for class in 0..classes {
        let label = labels.get(class)?;
        if matches!(label.prefix, LabelPrefix::Outside | LabelPrefix::Begin | LabelPrefix::Singleton) {
            scores[0][class] = logits[[0, class]];
        }
    }

    for token in 1..tokens {
        for class in 0..classes {
            let current = labels.get(class)?;
            for previous in 0..classes {
                let previous_label = labels.get(previous)?;
                let Some(transition) = transition_score(previous_label, current, calibration) else {
                    continue;
                };
                let candidate = scores[token - 1][previous] + transition + logits[[token, class]];
                if candidate > scores[token][class] {
                    scores[token][class] = candidate;
                    back[token][class] = previous;
                }
            }
        }
    }

    let mut best = (0..classes)
        .max_by(|left, right| scores[tokens - 1][*left].total_cmp(&scores[tokens - 1][*right]))
        .unwrap_or(0);
    let mut path = vec![0_usize; tokens];
    for token in (0..tokens).rev() {
        path[token] = best;
        best = back[token][best];
    }
    Ok(path)
}

fn transition_score(previous: &Label, current: &Label, calibration: ViterbiCalibration) -> Option<f32> {
    match (previous.prefix, current.prefix) {
        (LabelPrefix::Outside, LabelPrefix::Outside) => Some(calibration.transition_bias_background_stay),
        (LabelPrefix::Outside, LabelPrefix::Begin | LabelPrefix::Singleton) => {
            Some(calibration.transition_bias_background_to_start)
        }
        (LabelPrefix::Begin | LabelPrefix::Inside, LabelPrefix::Inside) if previous.category == current.category => {
            Some(calibration.transition_bias_inside_to_continue)
        }
        (LabelPrefix::Begin | LabelPrefix::Inside, LabelPrefix::End) if previous.category == current.category => {
            Some(calibration.transition_bias_inside_to_end)
        }
        (LabelPrefix::End | LabelPrefix::Singleton, LabelPrefix::Outside) => {
            Some(calibration.transition_bias_end_to_background)
        }
        (LabelPrefix::End | LabelPrefix::Singleton, LabelPrefix::Begin | LabelPrefix::Singleton) => {
            Some(calibration.transition_bias_end_to_start)
        }
        _ => None,
    }
}

fn score_at(logits: ndarray::ArrayView2<'_, f32>, token: usize, label: usize) -> f32 {
    sigmoid(logits[[token, label]])
}

fn sigmoid(value: f32) -> f32 {
    1.0 / (1.0 + (-value).exp())
}
```

#### 7. ONNX session
**File**: `crates/heimdall-privacy-filter/src/session.rs`
**Changes**: New file — `PrivacyOnnxSession` with `load`, `validate_schema`, `run` using direct `ort`.

```rust
use ndarray::ArrayD;
use ort::execution_providers::{CPUExecutionProvider, WebGPUExecutionProvider};
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::value::TensorRef;

use crate::input::EncodedPrivacyInput;
use crate::model::{PrivacyExecutionProvider, PrivacyFilterConfig};
use crate::{Error, Result};

/// Owned logits tensor returned from ONNX Runtime.
pub type LogitsTensor = ArrayD<f32>;

/// Thin direct wrapper around an ONNX Runtime session for OpenAI privacy-filter.
pub struct PrivacyOnnxSession {
    session: Session,
}

impl PrivacyOnnxSession {
    /// Load a privacy-filter ONNX session from a local file and check its schema.
    pub fn load(model_path: impl AsRef<std::path::Path>, config: &PrivacyFilterConfig) -> Result<Self> {
        let mut builder = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .with_intra_threads(4)?;

        builder = match config.execution_provider() {
            PrivacyExecutionProvider::Cpu => builder.with_execution_providers([CPUExecutionProvider::default().build()])?,
            PrivacyExecutionProvider::WebGpu => builder.with_execution_providers([WebGPUExecutionProvider::default().build()])?,
        };

        let session = builder.commit_from_file(model_path)?;
        let this = Self { session };
        this.validate_schema()?;
        Ok(this)
    }

    /// Validate model input/output names before inference.
    pub fn validate_schema(&self) -> Result<()> {
        let inputs = self
            .session
            .inputs()
            .iter()
            .map(|input| input.name.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let expected_inputs = ["attention_mask", "input_ids"]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        if inputs != expected_inputs {
            return Err(Error::Schema(format!(
                "expected inputs {expected_inputs:?}, found {inputs:?}"
            )));
        }

        let outputs = self
            .session
            .outputs()
            .iter()
            .map(|output| output.name.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if !outputs.contains("logits") && outputs.len() != 1 {
            return Err(Error::Schema(format!(
                "expected output `logits` or a single output tensor, found {outputs:?}"
            )));
        }
        Ok(())
    }

    /// Run inference and return owned logits.
    pub fn run(&mut self, input: &EncodedPrivacyInput) -> Result<LogitsTensor> {
        let input_ids = TensorRef::from_array_view(&input.input_ids)?;
        let attention_mask = TensorRef::from_array_view(&input.attention_mask)?;
        let outputs = self.session.run(ort::inputs![
            "input_ids" => input_ids,
            "attention_mask" => attention_mask,
        ]?)?;

        let logits = outputs
            .get("logits")
            .or_else(|| outputs.iter().next().map(|(_, value)| value))
            .ok_or_else(|| Error::Decode("model returned no outputs".to_string()))?;
        let logits = logits.try_extract_array::<f32>()?;
        Ok(logits.to_owned())
    }
}
```

#### 8. Setup download
**File**: `crates/heimdall-privacy-filter/src/setup.rs`
**Changes**: New file — `SetupRequest`, `SetupReport`, `setup_privacy_filter` using `hf-hub` sync API.

```rust
use std::path::{Path, PathBuf};

use hf_hub::api::sync::ApiBuilder;
use hf_hub::{Repo, RepoType};

use crate::model::{PrivacyFilterConfig, MODEL_REPOSITORY};
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
        .map_err(|error| Error::Setup(format!("failed to download {file}: {error}")))?;
        downloaded_files.push(path);
    }

    let config_path = downloaded_files
        .iter()
        .find(|path| path.file_name().is_some_and(|name| name == "config.json"))
        .ok_or_else(|| Error::Setup("config.json was not downloaded".to_string()))?;
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
    builder
        .build()
        .map_err(|error| Error::Setup(format!("failed to initialize Hugging Face API: {error}")))
}

fn snapshot_root_for(downloaded_file: &Path, repo_relative: &str) -> Result<PathBuf> {
    let mut root = downloaded_file.to_path_buf();
    for _ in Path::new(repo_relative).components() {
        root.pop();
    }
    if root.as_os_str().is_empty() {
        return Err(Error::Setup(format!(
            "failed to derive snapshot root from {}",
            downloaded_file.display()
        )));
    }
    Ok(root)
}
```

#### 9. Cache-backed runtime
**File**: `crates/heimdall-privacy-filter/src/runtime.rs`
**Changes**: New file — `PrivacyFilterRuntime` with `load` (cache-only), `detect_spans`, `detect_batch`.

```rust
use std::path::{Path, PathBuf};

use hf_hub::{Cache, Repo, RepoType};
use tokenizers::Tokenizer;

use crate::input::{EncodedPrivacyInput, PrivacyTextInput};
use crate::model::{ModelAssetPaths, PrivacyFilterConfig, MODEL_REPOSITORY};
use crate::output::{decode_logits, PrivacyLabels, PrivacySpanOutput, ViterbiCalibration};
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
            return Err(Error::NotReady("privacy filter is disabled".to_string()));
        }

        let assets = cached_asset_paths(&config)?;
        let config_json = std::fs::read_to_string(&assets.config)?;
        let labels = PrivacyLabels::from_config_json(&config_json)?;
        let calibration = ViterbiCalibration::from_json(&std::fs::read_to_string(&assets.viterbi)?)?;
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
    pub fn detect_spans(&mut self, text: impl Into<String>) -> Result<PrivacySpanOutput> {
        self.detect_batch(PrivacyTextInput::single(text.into())?)
    }

    /// Detect sensitive spans in one or more text inputs.
    pub fn detect_batch(&mut self, input: PrivacyTextInput) -> Result<PrivacySpanOutput> {
        let encoded = EncodedPrivacyInput::encode(input, &self.tokenizer, self.labels.pad_token_id())?;
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
    let config_path = repo.get("config.json").ok_or_else(|| missing_cache_error(config, "config.json"))?;
    let snapshot_root = snapshot_root_for(&config_path, "config.json")?;
    Ok(ModelAssetPaths::from_snapshot(snapshot_root, config.variant()))
}

fn missing_cache_error(config: &PrivacyFilterConfig, file: &str) -> Error {
    Error::NotReady(format!(
        "{file} for {} revision {} is not present in the Hugging Face cache",
        MODEL_REPOSITORY,
        config.revision()
    ))
}

fn snapshot_root_for(downloaded_file: &Path, repo_relative: &str) -> Result<PathBuf> {
    let mut root = downloaded_file.to_path_buf();
    for _ in Path::new(repo_relative).components() {
        root.pop();
    }
    if root.as_os_str().is_empty() {
        return Err(Error::NotReady(format!(
            "failed to derive snapshot root from {}",
            downloaded_file.display()
        )));
    }
    Ok(root)
}
```

#### 10. Full-text redaction
**File**: `crates/heimdall-privacy-filter/src/redaction.rs`
**Changes**: New file — `CapturedTextRedaction`, `redact_text`, `redact_captured_text`, `apply_spans`.

```rust
use crate::runtime::PrivacyFilterRuntime;
use crate::{DetectedSpan, Result};

/// Raw local output plus redacted model-facing output for a captured text value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedTextRedaction {
    /// Unmodified captured text that may be shown to the trusted local user/UI.
    pub raw_for_user: String,
    /// Redacted text that may be sent to the LLM/model context.
    pub redacted_for_llm: String,
}

/// Redact one captured text value while preserving the raw local copy.
pub fn redact_captured_text(
    runtime: &mut PrivacyFilterRuntime,
    raw_for_user: impl Into<String>,
) -> Result<CapturedTextRedaction> {
    let raw_for_user = raw_for_user.into();
    let redacted_for_llm = redact_text(runtime, &raw_for_user)?;
    Ok(CapturedTextRedaction {
        raw_for_user,
        redacted_for_llm,
    })
}

/// Redact one captured text value for model-facing use.
pub fn redact_text(runtime: &mut PrivacyFilterRuntime, text: &str) -> Result<String> {
    let output = runtime.detect_spans(text.to_string())?;
    Ok(apply_spans(text, output.spans))
}

fn apply_spans(text: &str, mut spans: Vec<DetectedSpan>) -> String {
    spans.sort_by_key(|span| (span.start, span.end));
    let mut redacted = String::with_capacity(text.len());
    let mut cursor = 0;

    for span in spans {
        if span.end <= cursor || span.start >= span.end || span.end > text.len() {
            continue;
        }
        if !text.is_char_boundary(span.start) || !text.is_char_boundary(span.end) {
            continue;
        }
        redacted.push_str(&text[cursor..span.start]);
        redacted.push_str("[REDACTED:");
        redacted.push_str(&span.label);
        redacted.push(']');
        cursor = span.end;
    }

    redacted.push_str(&text[cursor..]);
    redacted
}
```

### Success Criteria

#### Automated Verification
- [x] Workspace compiles: `cargo check -p heimdall-privacy-filter`
- [x] Format passes: `mise format`
- [x] No `#[allow(...)]` or `#[ignore]` introduced
- [x] No ORP/gline-rs/fastembed-rs in `crates/heimdall-privacy-filter/Cargo.toml`
- [x] `ort` features include `download-binaries`, `ndarray`, `webgpu`: `grep 'download-binaries' crates/heimdall-privacy-filter/Cargo.toml` returns 0 matches (resolved from workspace)
- [x] No `ApiRepo::download` or network-capable HF paths in `runtime.rs`

#### Manual Verification
- [x] `PrivacyFilterConfig::enabled()` produces CPU-default config with q4 variant
- [x] `redact_text` function signature accepts `&mut PrivacyFilterRuntime` and `&str`
- [x] `CapturedTextRedaction` has `raw_for_user` and `redacted_for_llm` fields

---

## Phase 2: CLI Module Refactoring

### Overview

Split monolithic `crates/heimdall-sandbox/src/lib.rs` into focused command modules. This is a pure structural refactor — no behavioral change to existing `exec`, `policy`, or `inner-exec` commands. All existing tests must continue passing.

**Parallel with Phase 1** (separate crates, no cross-dependency).

### Changes Required

#### 1. Command module root
**File**: `crates/heimdall-sandbox/src/commands/mod.rs`
**Changes**: New file — re-exports of command submodules.

#### 2. Exec command extraction
**File**: `crates/heimdall-sandbox/src/commands/exec.rs`
**Changes**: New file — `ExecArgs`, conversion to `ExecRequest`, extracted from current `lib.rs`.

#### 3. Policy command extraction
**File**: `crates/heimdall-sandbox/src/commands/policy.rs`
**Changes**: New file — `PolicyArgs`, `PolicyCommands`, schema/validate dispatch, extracted from current `lib.rs`.

#### 4. Inner-exec command extraction
**File**: `crates/heimdall-sandbox/src/commands/inner_exec.rs`
**Changes**: New file — `InnerExecArgs`, conversion, extracted from current `lib.rs`.

#### 5. Policy schema extraction
**File**: `crates/heimdall-sandbox/src/policy.rs`
**Changes**: New file — `PolicyDocument`, `SandboxConfig`, `PolicyFilesystem`, `PolicyEnvironment`, validation helpers, extracted from current `lib.rs`.

#### 6. Thinned lib.rs
**File**: `crates/heimdall-sandbox/src/lib.rs`
**Changes**: Retain `Cli`, `Commands` enum, `CliStdioPolicy`, `run()`, `run_from()`, `run_cli()`, and inline tests. Import and delegate to command modules.

### Success Criteria

#### Automated Verification
- [x] `mise format` passes
- [x] `mise run --force test` passes — all existing tests unchanged
- [x] No new `#[allow(...)]` or `#[ignore]`
- [x] `cargo check -p heimdall-sandbox` succeeds
- [x] No `heimdall-privacy-filter` dependency added yet in `heimdall-sandbox/Cargo.toml`

#### Manual Verification
- [x] `heimdall-sandbox exec --cwd . -- printf hello` still works
- [x] `heimdall-sandbox policy schema` still prints JSON schema
- [x] No behavioral difference in any existing command

---

## Phase 3: Setup and Redaction CLI Commands

### Overview

Wire `heimdall-sandbox setup` and `heimdall-sandbox privacy-filter redact` into the refactored CLI. Add `heimdall-privacy-filter` dependency to `heimdall-sandbox` and register the new commands in `Commands` enum and dispatch.

**Depends on Phase 1 and Phase 2.**

### Changes Required

#### 1. Add privacy-filter dependency
**File**: `crates/heimdall-sandbox/Cargo.toml`
**Changes**: Add `heimdall-privacy-filter.workspace = true` to dependencies.

#### 2. Setup command
**File**: `crates/heimdall-sandbox/src/commands/setup.rs`
**Changes**: New file — `SetupArgs` with `--force`, `--cache-dir`, `--variant`, `--revision` flags; `run_setup_command` calling `setup_privacy_filter`.

#### 3. Privacy-filter redact command
**File**: `crates/heimdall-sandbox/src/commands/privacy_filter.rs`
**Changes**: New file — `PrivacyFilterArgs`, `PrivacyFilterCommands::Redact`, `RedactArgs` with `--text`, `--stdin`, `--cache-dir`, `--variant`, `--revision`, `--execution-provider`; `run_redact_command` calling `PrivacyFilterRuntime::load` + `redact_text`.

#### 4. Register commands
**File**: `crates/heimdall-sandbox/src/commands/mod.rs`
**Changes**: Add `pub mod setup;` and `pub mod privacy_filter;` re-exports.

#### 5. Update Commands enum and dispatch
**File**: `crates/heimdall-sandbox/src/lib.rs`
**Changes**: Add `Setup(SetupArgs)` and `PrivacyFilter(PrivacyFilterArgs)` variants to `Commands`. Update `run_cli` to dispatch setup and redact before exec path. Add `CliPrivacyVariant`, `CliExecutionProvider`, `privacy_config`, `redact_input` helpers.

### Success Criteria

#### Automated Verification
- [x] `mise format` passes
- [x] `mise run --force test` passes — all existing + new tests
- [x] `cargo check -p heimdall-sandbox` succeeds
- [x] No `ApiRepo::download` or `Tokenizer::from_pretrained` in `privacy_filter.rs`

#### Manual Verification
- [x] `heimdall-sandbox setup --help` shows flags: `--force`, `--cache-dir`, `--variant`, `--revision`
- [x] `heimdall-sandbox privacy-filter redact --help` shows flags: `--text`, `--stdin`, `--cache-dir`, `--variant`, `--revision`, `--execution-provider`
- [x] `heimdall-sandbox setup` without prior cache returns a meaningful error (no network call expected in CI)
- [x] No exec/executor/stdio/policy behavioral changes

---

## Phase 4: Integration Tests

### Overview

Add integration tests for command shape, setup defaults, and redact input validation. These tests verify CLI parsing and command wiring without requiring actual model downloads.

**Depends on Phase 3.**

### Changes Required

#### 1. Privacy-filter integration tests
**File**: `crates/heimdall-sandbox/tests/privacy_filter.rs`
**Changes**: New file — tests for:
- `privacy-filter redact --text '...'` parses correctly
- `privacy-filter redact --stdin` parses correctly
- `redact --text` and `--stdin` are mutually exclusive
- `redact` without `--text` or `--stdin` is rejected
- `setup` defaults to q4 variant
- `setup --variant fp16` parses correctly
- `setup --force` parses correctly

### Success Criteria

#### Automated Verification
- [x] `mise run --force test` passes — all existing + new integration tests
- [x] No `#[allow(...)]` or `#[ignore]`

#### Manual Verification
- [x] Test output shows new tests passing alongside existing tests
- [x] No test requires network access or real Hugging Face downloads

---

## Testing Strategy

### Automated
- `mise format` — format + lint
- `mise run --force test` — all tests via nextest
- `cargo check -p heimdall-privacy-filter` — privacy crate compiles
- `cargo check -p heimdall-sandbox` — CLI crate compiles

### Manual Testing Steps
1. Run `heimdall-sandbox setup --help` and verify flags match design
2. Run `heimdall-sandbox privacy-filter redact --help` and verify flags match design
3. Run `heimdall-sandbox exec --cwd . -- printf hello` and verify no behavioral regression
4. Run `heimdall-sandbox policy schema` and verify no behavioral regression
5. After running `heimdall-sandbox setup`, run `heimdall-sandbox privacy-filter redact --text 'email alice@example.com'` and verify redacted output
6. Verify `grep -r "orp\|gline\|fastembed" crates/heimdall-privacy-filter/Cargo.toml` returns empty

## Performance Considerations

- Setup can download nearly a gigabyte for q4; progress output should make the long-running operation visible.
- Redaction command startup loads tokenizer, ONNX Runtime session, model config, and Viterbi calibration before inference.
- Optional WebGPU can improve inference latency on supported systems, but selected provider failures should surface as normal runtime/session errors.
- Full-text redaction is intentionally scoped to one captured blurb for this design; streaming stdout/stderr redaction is deferred/rejected for this boundary.
- `Session::run()` requires mutable session access; the standalone command can keep a single mutable runtime instance for one request.

## Migration Notes

No persisted project/user schema migration is required. Setup stores model assets in the Hugging Face cache. Existing policies remain unchanged because this design does not add policy JSON privacy fields.

## References

- Design: `thoughts/shared/designs/2026-05-09_15-45-19_onnx-privacy-filter-setup-runtime.md`
- Research: `thoughts/shared/research/2026-05-09_00-05-56_rust-onnx-privacy-filter-runtime.md`
- `ort` session docs: <https://docs.rs/ort/latest/ort/session/struct.Session.html>
- `hf-hub` sync API: <https://docs.rs/hf-hub/latest/hf_hub/api/sync/struct.ApiRepo.html>
- `hf-hub` cache: <https://docs.rs/hf-hub/latest/hf_hub/struct.CacheRepo.html>
- `tokenizers::Tokenizer`: <https://docs.rs/tokenizers/latest/tokenizers/tokenizer/struct.Tokenizer.html>
