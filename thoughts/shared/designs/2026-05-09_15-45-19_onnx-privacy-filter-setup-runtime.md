---
date: 2026-05-09T15:45:19-0700
author: Ivan Porto Carrero
commit: d9d522e
branch: onnx-privacy
repository: heimdall-sandbox
topic: "ONNX privacy-filter setup and runtime integration"
tags: [design, rust, onnx, privacy-filter, setup, cli]
status: in-progress
parent: thoughts/shared/research/2026-05-09_00-05-56_rust-onnx-privacy-filter-runtime.md
last_updated: 2026-05-09T23:17:31-0700
last_updated_by: Ivan Porto Carrero
last_updated_note: "Clarified capture-first redaction boundary: raw output to user, redacted output to LLM"
---

# Design: ONNX Privacy-Filter Setup and Runtime Integration

## Summary
Build a `heimdall-privacy-filter` crate that integrates OpenAI `openai/privacy-filter` directly with `ort` and `tokenizers`, then expose it through an explicit setup flow and a full-text redaction primitive.

The intended product boundary is **capture first, redact before LLM context**:

1. Tools/commands capture full output normally.
2. The trusted local UI/user can see the raw, unredacted output.
3. Before any captured text is sent to an LLM model, Heimdall runs that captured text through the privacy-filter runtime and sends only the redacted text to the model.

This design does **not** stream-redact stdout/stderr. It does **not** mutate child process stdio, intercept terminal output, or try to redact bytes while a command is running. It also does not add a separate model/cache validation gate: setup downloads assets, and runtime use simply attempts to load from the local Hugging Face cache. If the model, tokenizer, sidecars, or ONNX Runtime session are missing/invalid, that load/inference error is the failure.

The runtime owns the OpenAI-specific inference contract: tokenizer offsets, `input_ids`/`attention_mask` tensor construction, `ort` session construction, logits extraction, BIOES/Viterbi span decoding, and pure full-text redaction. ORP/gline-rs and fastembed-rs are reference implementations only; Heimdall does not depend on ORP/gline-rs.

## Requirements
- Add an explicit `heimdall-sandbox setup` command for first-run model download.
- Do not download model assets automatically during redaction/runtime use.
- Download privacy-filter assets through the Hugging Face Rust crate into the Hugging Face cache.
- Default setup model variant is `q4`.
- Use direct `ort` + `tokenizers` integration for the OpenAI privacy-filter runtime; ORP/gline-rs and fastembed-rs are references only, not dependencies.
- Add a standalone command/API that receives a blurb of text and returns redacted text.
- Treat redaction as a full captured-text transformation, not a streaming stdout/stderr filter.
- Preserve raw captured output for trusted local display while providing redacted output for LLM/model context.
- Runtime loading should naturally error when cached assets are missing or invalid; do not add an extra ready-manifest/preflight validation gate.
- Do not add `exec` stdout/stderr filtering in this design.
- Do not add policy JSON privacy execution behavior in this design.
- Keep model/runtime mechanics out of CLI parsing and policy validation.
- Support optional WebGPU execution provider selection while keeping CPU as the default provider.
- Do not package model assets with main release artifacts in this change.

## Current State Analysis
Heimdall currently has a compact CLI and core execution pipeline with no model/runtime crate. `ExecRequest` carries cwd, argv, environment, stdio, network, filesystem, and proc settings, while `Executor` configures stdio and forwards piped child output with raw `std::io::copy()`. The CLI owns policy parsing/schema generation, rejects unknown top-level policy fields manually, and directly converts CLI/policy input into `ExecRequest`.

### Key Discoveries
- `Cargo.toml:2-8` lists workspace crates; there is no privacy-filter or ONNX runtime crate.
- `Cargo.toml:28-42` contains workspace dependencies; no `ort`, `tokenizers`, `hf-hub`, or `ndarray` dependency exists.
- `crates/heimdall-core/src/request.rs:29-38` defines `ExecRequest` fields and has no privacy config.
- `crates/heimdall-core/src/request.rs:48-70` defaults `StdioPolicy::Inherit`, host networking, empty filesystem policy, and default proc mode.
- `crates/heimdall-core/src/executor.rs:173-185` treats stdio as bundled: inherit all streams or null stdin and pipe stdout/stderr.
- `crates/heimdall-core/src/executor.rs:196-218` starts forwarding only for `StdioPolicy::Piped`.
- `crates/heimdall-core/src/executor.rs:220-227` discards output-forwarding thread errors.
- `crates/heimdall-core/src/executor.rs:230-232` is the raw copy seam for child forwarding; this design intentionally does not change it because redaction happens after tool output is captured for LLM context.
- `crates/heimdall-core/src/error.rs:6` and `crates/heimdall-core/src/error.rs:75-87` map runtime misconfiguration failures to exit code 2.
- `crates/heimdall-sandbox/src/lib.rs:22-35` defines visible `exec`, `policy`, and hidden inner Linux re-entry commands; `setup` belongs here as another top-level command.
- `crates/heimdall-sandbox/src/lib.rs:39-56` shows nested command shape for `policy`; `setup all` can follow the same top-level command dispatch pattern without nested subcommands.
- `crates/heimdall-sandbox/src/lib.rs:131-147` owns JSON policy schema structs; this design intentionally does not add privacy policy fields yet.
- `crates/heimdall-sandbox/src/lib.rs:287-318` manually rejects unknown policy fields; this design leaves the policy allowlist unchanged.
- `crates/heimdall-sandbox/src/lib.rs:418-436` special-cases policy commands before process hardening/execution; setup should be handled before `into_exec_request()` as well.
- `crates/heimdall-linux-sandbox/src/plan.rs:281-300` passes the original stdio policy through hidden inner re-entry; this design leaves Linux inner re-entry unchanged.
- `crates/heimdall-macos-sandbox/src/lib.rs:202-204` allows fd 1/2 and `/dev/tty`; fd filtering cannot stop explicit `/dev/tty` writes and this remains a known bypass vector.
- `crates/heimdall-process-hardening/src/lib.rs:146-155` strips loader environment variables, so this design avoids relying on `LD_LIBRARY_PATH`/`DYLD_LIBRARY_PATH` by choosing `ort/download-binaries`.
- The OpenAI model card documents Transformers.js with `device: "webgpu"`, and `ort` exposes a `webgpu` Cargo feature, but native Rust `ort` WebGPU EP compatibility is only proven when the redaction runtime successfully loads and runs.
- Research artifact lines 32-39 list required ONNX variants/sidecars and warn external data names must remain beside the `.onnx` file.
- Research artifact lines 71-79 require local tokenizer loading, input/output metadata validation, 33-label logits, and offset-preserving post-processing.
- Research artifact lines 92-94 and 183-186 identify q4/q4f16/quantized compatibility and quality risks; q4 is still selected as the developer-approved setup default.
- Research artifact line 120 states ONNX redaction is token-window post-processing, not byte-by-byte streaming.
- `/Users/ivan/github/fbilhaut/orp/src/model.rs` shows a useful reference for session construction, execution-provider configuration, schema checks, and inference, but ORP is not a dependency in this design.
- `/Users/ivan/github/fbilhaut/orp/src/pipeline.rs` shows a useful reference for separating model-specific pre/postprocessing from session execution.
- `/Users/ivan/github/fbilhaut/gline-rs/src/model/pipeline/span.rs` and `token.rs` show model-specific tensor contracts as reference implementations.
- `/Users/ivan/github/fbilhaut/gline-rs/src/model/input/tensors/span.rs` and `token.rs` confirm GLiNER requires `words_mask`/`text_lengths` and sometimes `span_idx`/`span_mask`, so `gline-rs` cannot run OpenAI privacy-filter directly.
- OpenAI `config.json` declares `OpenAIPrivacyFilterForTokenClassification` with 33 BIOES labels, and `tokenizer_config.json` declares only `input_ids` and `attention_mask`; Heimdall will implement that direct contract with `ort` + `tokenizers`.

## Scope
### Building
- New `heimdall-privacy-filter` crate with a crate-root `Error` and `Result<T>` alias.
- OpenAI privacy-filter runtime modules: input/context, tensor builder, session construction, logits/BIOES/Viterbi decoder, normalized span output.
- Privacy model metadata (`PrivacyFilterVariant`, built-in q4 default, model repo/revision, required files).
- `setup` command that downloads q4 model/config/tokenizer/Viterbi/ONNX sidecars through `hf-hub`.
- Cache-backed runtime loader used by the standalone redaction command/API; it does not download and does not require a ready manifest.
- Pure full-text redaction API that consumes one captured text string and returns one redacted string.
- CLI command for ad-hoc redaction of a supplied text blurb.
- Refactor monolithic `crates/heimdall-sandbox/src/lib.rs` into focused command modules with no behavioral change to existing commands.
- Design hook for tool integrations: keep raw captured output for local UI, send redacted captured output to LLM context.
- Unit/integration tests using fakes/fixtures, not real Hugging Face downloads or multi-GB ONNX assets.

### Not Building
- Automatic model download during redaction/runtime use.
- Bundled model assets in main cargo-dist/npm artifacts.
- Separate model asset package/archive.
- `exec` integration, child stdout/stderr interception, forced pipes, stdin preservation changes, or output-forwarding thread changes.
- Policy JSON privacy execution behavior.
- Streaming writer/window redaction API.
- Configurable window/overlap knobs.
- Ready-manifest or separate cache-validation/preflight gate.
- CoreML/CUDA/DirectML/OpenVINO/XNNPACK execution providers beyond the optional WebGPU path.
- Full external accuracy benchmark suite for all ONNX variants.
- Guaranteed interception of explicit `/dev/tty` writes.
- A standalone installer/downloader outside `heimdall-sandbox setup`.

## Decisions
### Add a dedicated privacy-filter crate
Simple decision. `Cargo.toml:2-8` has no runtime crate and `Cargo.toml:28-42` has no ORP/ONNX/HF dependencies. Model download metadata, OpenAI privacy-filter direct runtime semantics, full-text redaction, and BIOES/Viterbi decoding belong in `crates/heimdall-privacy-filter` so callers consume a typed runtime API rather than depending on ad hoc model code.

### Use direct `ort` + `tokenizers`, with ORP and fastembed-rs as references only
Ambiguity: depend on ORP/gline-rs, hand-roll the OpenAI privacy-filter contract directly, or hide both behind a local adapter trait.

Explored:
- ORP custom pipeline: feasible, but adds an external dependency for a small single-model integration.
- `gline-rs` direct: not compatible because GLiNER pipelines expect `words_mask`, `text_lengths`, and sometimes `span_idx`/`span_mask`, while OpenAI privacy-filter only declares `input_ids` and `attention_mask`.
- Direct `ort` + `tokenizers`: keeps Heimdall's dependency graph explicit while using ORP/gline-rs and fastembed-rs as implementation references for session setup, schema validation, and named-output handling.

Decision: implement OpenAI privacy-filter directly with `ort` + `tokenizers`. ORP/gline-rs and fastembed-rs are references only and must not be added as runtime dependencies. This keeps Heimdall free to adopt `ort` fixes, feature changes, and security updates directly instead of being pinned behind a thin wrapper crate's release cadence.

### Use `heimdall-sandbox setup` for first-run downloads
Ambiguity: automatic first-load download vs explicit setup.

Explored:
- Automatic first-load download: convenient, but violates developer direction and can block or fail during redaction/runtime use.
- Explicit `setup` command: matches the current CLI command model at `crates/heimdall-sandbox/src/lib.rs:22-35`, keeps downloads out of redaction/runtime use, and lets missing assets surface as normal load errors.

Decision: add visible `heimdall-sandbox setup` as a top-level command that performs first-run downloads. It downloads privacy-filter q4 assets into the Hugging Face cache. Runtime redaction never downloads and does not depend on a ready manifest.

### Use Hugging Face cache during setup; cache-only at runtime
Ambiguity: local configured asset directory, packaged asset archive, automatic runtime download, or setup download.

Explored:
- Local configured asset root: original research recommendation, but developer prefers the Hugging Face Rust crate/cache.
- Packaged assets: large release artifacts; research lines 99-106 warn smallest ONNX sidecar is ~809MB and full/fp16 are multi-GB.
- Runtime download: rejected by developer.
- Setup download: downloads through HF crate once, then runtime loads from cache only.

Decision: setup uses `hf-hub` to download required repo files into the HF cache. Runtime uses `CacheRepo::get` to resolve cached paths and refuses network/download behavior.

### Default setup variant is q4
Ambiguity: no default, fp16 baseline, q4f16 smallest, q4, quantized.

Explored:
- No default: safer but developer chose built-in default for setup.
- fp16: better accuracy baseline but ~2.8GB external data.
- q4f16: smallest listed (~809MB) but not developer choice.
- q4: ~917MB and used by the model card's Transformers.js example; if native loading fails, the redaction command surfaces that load/session error.

Decision: `setup` defaults to q4. Setup downloads q4 and does not silently choose another variant; runtime redaction surfaces any q4 load/session incompatibility as an error.

### Use built-in revision pin with optional override
Simple decision. Research line 55 requires pinning the Hugging Face revision. Developer accepted capturing the pin in code if necessary. The crate exposes `DEFAULT_REVISION` and setup/exec config can override it for controlled upgrades.

### Use `ort/download-binaries`
Ambiguity: `ort/load-dynamic`, `ort/download-binaries`, or both.

Explored:
- Dynamic load: clearer deployment error surface, but more user/runtime path setup and loader-env concerns.
- Download binaries: developer choice; simpler setup for this first integration.
- Both: too much packaging/test surface for this design.

Decision: depend on `ort` with `download-binaries`, `ndarray`, and `webgpu` features, plus direct `tokenizers`, `ndarray`, `hf-hub`, and serde dependencies where setup/runtime code needs them. CPU remains the default execution provider. WebGPU is optional and must be explicitly selected; if selected WebGPU session loading fails, the redaction command returns that error rather than silently falling back.

### Support optional WebGPU while keeping CPU default
Ambiguity: CPU-only, optional WebGPU, or WebGPU default.

Explored:
- CPU-only: lowest risk, but ignores the model card's documented WebGPU usage path.
- Optional WebGPU: lets users use WebGPU where native `ort` supports it while keeping CPU as the safe default.
- WebGPU default: too risky because Transformers.js WebGPU compatibility is not proof of native Rust `ort` WebGPU EP compatibility.

Decision: include optional WebGPU execution provider support in v1. CPU remains default; selecting WebGPU makes runtime load the WebGPU execution provider and return any provider/session error with no silent fallback.

### Refactor CLI into command modules
Simple decision. `crates/heimdall-sandbox/src/lib.rs` currently holds all command definitions, arg structs, policy JSON schemas, conversion logic, dispatch, and inline tests in one ~520-line file. Adding `setup` and `privacy-filter redact` without restructuring would make it worse.

Decision: split the monolithic `lib.rs` into focused command modules while keeping `lib.rs` as the thin public API surface (`Cli`, `Commands` enum, `run()`, `run_from()`). Each command gets its own module owning its arg structs, conversion, and dispatch logic. This is a pure structural refactor with no behavioral change to existing `exec`/`policy`/`inner-exec` commands.

### Capture first; redact before LLM context
Ambiguity: stream-redact child stdout/stderr, reject raw output, or redact captured tool output before model context.

Explored:
- Streaming stdout/stderr redaction: wrong boundary for this product use; the user/tool UI should still show full output, and ONNX privacy-filter is token-window/full-text post-processing rather than byte-by-byte filtering.
- Process-level egress filtering: changes stdio/TTY semantics and is unnecessary for the initial use case.
- Capture-first sanitization: preserves raw output for trusted local display and produces a separate redacted representation for the LLM.

Decision: redact captured text before it enters LLM context. The primitive is `input text -> redacted text`; tool integrations can store/display raw output separately from the redacted model-facing output.

### Do not add a ready-manifest validation gate
Simple decision. The developer clarified: do not validate model/cache separately; if the model is not there, it will error. Setup downloads assets into the Hugging Face cache. Runtime redaction resolves cache paths and loads tokenizer/config/ONNX session directly. Missing or invalid assets surface as normal load/inference errors.

### Defer exec and policy integration
Simple decision. `exec` stdout/stderr filtering, `OutputForwarding::join()` changes, stdin preservation logic, and policy JSON privacy fields are outside this design. They may be revisited later once the capture-first raw-vs-redacted tool-output boundary is implemented.

## Architecture
### Cargo.toml — MODIFY
Workspace membership and dependency additions.

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

### crates/heimdall-privacy-filter/Cargo.toml — NEW
Privacy runtime crate manifest.

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

### crates/heimdall-privacy-filter/src/lib.rs — NEW
Crate-root module exports, error boundary, setup/runtime API exports.

```rust
//! OpenAI privacy-filter setup and local ONNX inference support.
//!
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

### crates/heimdall-privacy-filter/src/model.rs — NEW
Model constants, variants, required files, and local asset paths.

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

### crates/heimdall-privacy-filter/src/input.rs — NEW
Privacy text input, tokenized context, tokenizer offset handling, and tensor input construction helpers.

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

### crates/heimdall-privacy-filter/src/output.rs — NEW
Normalized detected spans, logits decoding, BIOES/Viterbi output handling.

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

### crates/heimdall-privacy-filter/src/session.rs — NEW
ONNX Runtime session construction, metadata checks, and tensor input/output execution helpers.

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

### crates/heimdall-privacy-filter/src/setup.rs — NEW
Setup request/report and HF-cache download flow.

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

### crates/heimdall-privacy-filter/src/runtime.rs — NEW
Cache-only runtime loader, tokenizer/session/config/Viterbi construction, inference contract.

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

### crates/heimdall-privacy-filter/src/redaction.rs — NEW
Pure full-text redaction from detected spans.

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

### crates/heimdall-sandbox/Cargo.toml — MODIFY
CLI dependency on privacy-filter crate for setup and standalone redaction commands.

```toml
[dependencies]
clap.workspace = true
heimdall-core.workspace = true
heimdall-privacy-filter.workspace = true
heimdall-process-hardening.workspace = true
schemars.workspace = true
serde.workspace = true
serde_json.workspace = true
shellexpand.workspace = true
```

### crates/heimdall-sandbox/src/lib.rs — MODIFY
Thin public surface: `Cli`, `Commands` enum, `run()`, `run_from()`. Extract all command implementations into `src/commands/` modules.

### crates/heimdall-sandbox/src/commands/mod.rs — NEW
Command module re-exports.

### crates/heimdall-sandbox/src/commands/exec.rs — NEW
Exec arg structs, conversion, dispatch (extracted from current `lib.rs`).

### crates/heimdall-sandbox/src/commands/policy.rs — NEW
Policy arg structs, schema command, validate command (extracted from current `lib.rs`).

### crates/heimdall-sandbox/src/commands/inner_exec.rs — NEW
Hidden Linux inner-exec arg structs and conversion (extracted from current `lib.rs`).

### crates/heimdall-sandbox/src/commands/setup.rs — NEW
Setup arg structs and download dispatch.

### crates/heimdall-sandbox/src/commands/privacy_filter.rs — NEW
Privacy-filter redact arg structs and dispatch.

### crates/heimdall-sandbox/src/policy.rs — NEW
Policy JSON schema structs and validation (extracted from current `lib.rs`).

```rust
use heimdall_privacy_filter::{
    redact_text, setup_privacy_filter, PrivacyExecutionProvider, PrivacyFilterConfig,
    PrivacyFilterRuntime, PrivacyFilterVariant, SetupRequest,
};

#[derive(Debug, Subcommand)]
enum Commands {
    /// Execute a command in the minimal sandbox runtime.
    Exec(ExecArgs),
    /// Download first-run assets used by Heimdall commands.
    Setup(SetupArgs),
    /// Run privacy-filter utilities over captured text.
    #[command(name = "privacy-filter")]
    PrivacyFilter(PrivacyFilterArgs),
    /// Work with JSON policy documents.
    Policy(PolicyArgs),
    /// Internal re-entry point used inside a Linux bubblewrap namespace.
    #[command(name = "__heimdall-inner-exec", hide = true)]
    InnerExec(InnerExecArgs),
}

#[derive(Debug, Parser)]
struct SetupArgs {
    /// Redownload assets even if they are already present in the Hugging Face cache.
    #[arg(long)]
    force: bool,

    /// Hugging Face cache directory override.
    #[arg(long = "cache-dir")]
    cache_dir: Option<PathBuf>,

    /// Privacy-filter ONNX variant to download.
    #[arg(long, value_enum, default_value_t = CliPrivacyVariant::Q4)]
    variant: CliPrivacyVariant,

    /// Hugging Face revision to download.
    #[arg(long)]
    revision: Option<String>,
}

#[derive(Debug, Parser)]
struct PrivacyFilterArgs {
    #[command(subcommand)]
    command: PrivacyFilterCommands,
}

#[derive(Debug, Subcommand)]
enum PrivacyFilterCommands {
    /// Redact one captured text value and print model-facing text.
    Redact(RedactArgs),
}

#[derive(Debug, Parser)]
struct RedactArgs {
    /// Text blurb to redact.
    #[arg(long, conflicts_with = "stdin")]
    text: Option<String>,

    /// Read the text blurb from stdin.
    #[arg(long)]
    stdin: bool,

    /// Hugging Face cache directory override.
    #[arg(long = "cache-dir")]
    cache_dir: Option<PathBuf>,

    /// Privacy-filter ONNX variant to load.
    #[arg(long, value_enum, default_value_t = CliPrivacyVariant::Q4)]
    variant: CliPrivacyVariant,

    /// Hugging Face revision to load.
    #[arg(long)]
    revision: Option<String>,

    /// ONNX Runtime execution provider to use.
    #[arg(long = "execution-provider", value_enum, default_value_t = CliExecutionProvider::Cpu)]
    execution_provider: CliExecutionProvider,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliPrivacyVariant {
    Q4,
    Q4F16,
    Quantized,
    Fp16,
    Full,
}

impl From<CliPrivacyVariant> for PrivacyFilterVariant {
    fn from(value: CliPrivacyVariant) -> Self {
        match value {
            CliPrivacyVariant::Q4 => Self::Q4,
            CliPrivacyVariant::Q4F16 => Self::Q4F16,
            CliPrivacyVariant::Quantized => Self::Quantized,
            CliPrivacyVariant::Fp16 => Self::Fp16,
            CliPrivacyVariant::Full => Self::Full,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliExecutionProvider {
    Cpu,
    WebGpu,
}

impl From<CliExecutionProvider> for PrivacyExecutionProvider {
    fn from(value: CliExecutionProvider) -> Self {
        match value {
            CliExecutionProvider::Cpu => Self::Cpu,
            CliExecutionProvider::WebGpu => Self::WebGpu,
        }
    }
}

fn run_cli(cli: Cli) -> i32 {
    let Cli { command } = cli;
    match command {
        Commands::Setup(args) => return run_setup_command(args),
        Commands::PrivacyFilter(args) => return run_privacy_filter_command(args),
        Commands::Policy(args) => {
            return match run_policy_command(args) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("{error}");
                    SANDBOX_MISCONFIGURATION_EXIT_CODE
                }
            };
        }
        command => run_exec_command(command),
    }
}

fn run_setup_command(args: SetupArgs) -> i32 {
    let config = privacy_config(args.variant, args.revision, args.cache_dir, CliExecutionProvider::Cpu);
    match setup_privacy_filter(SetupRequest::new(config).with_force(args.force)) {
        Ok(report) => {
            eprintln!("privacy-filter assets downloaded to {}", report.snapshot_root.display());
            0
        }
        Err(error) => {
            eprintln!("{error}");
            SANDBOX_MISCONFIGURATION_EXIT_CODE
        }
    }
}

fn run_privacy_filter_command(args: PrivacyFilterArgs) -> i32 {
    match args.command {
        PrivacyFilterCommands::Redact(args) => run_redact_command(args),
    }
}

fn run_redact_command(args: RedactArgs) -> i32 {
    let input = match redact_input(args.text, args.stdin) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("{error}");
            return SANDBOX_MISCONFIGURATION_EXIT_CODE;
        }
    };
    let config = privacy_config(args.variant, args.revision, args.cache_dir, args.execution_provider);
    match PrivacyFilterRuntime::load(config).and_then(|mut runtime| redact_text(&mut runtime, &input)) {
        Ok(redacted) => {
            println!("{redacted}");
            0
        }
        Err(error) => {
            eprintln!("{error}");
            SANDBOX_MISCONFIGURATION_EXIT_CODE
        }
    }
}

fn redact_input(text: Option<String>, stdin: bool) -> std::result::Result<String, String> {
    if let Some(text) = text {
        return Ok(text);
    }
    if stdin {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .map_err(|error| format!("failed to read stdin: {error}"))?;
        return Ok(input);
    }
    Err("redact requires --text or --stdin".to_string())
}

fn privacy_config(
    variant: CliPrivacyVariant,
    revision: Option<String>,
    cache_dir: Option<PathBuf>,
    execution_provider: CliExecutionProvider,
) -> PrivacyFilterConfig {
    let mut config = PrivacyFilterConfig::enabled()
        .with_variant(variant.into())
        .with_execution_provider(execution_provider.into());
    if let Some(revision) = revision {
        config = config.with_revision(revision);
    }
    if let Some(cache_dir) = cache_dir {
        config = config.with_cache_dir(cache_dir);
    }
    config
}
```

### crates/heimdall-sandbox/tests/privacy_filter.rs — NEW
Integration tests for command shape, missing-cache error propagation, and redacted text output with a fake runtime boundary.

```rust
#[test]
fn parses_privacy_filter_redact_text_command() {
    let cli = Cli::try_parse_from([
        "heimdall-sandbox",
        "privacy-filter",
        "redact",
        "--text",
        "email alice@example.com",
    ])
    .expect("privacy-filter redact parses");

    assert!(matches!(cli.command, Commands::PrivacyFilter(_)));
}

#[test]
fn redact_requires_text_or_stdin() {
    let error = redact_input(None, false).expect_err("missing input is rejected");

    assert_eq!(error, "redact requires --text or --stdin");
}

#[test]
fn setup_command_defaults_to_q4() {
    let cli = Cli::try_parse_from(["heimdall-sandbox", "setup"])
        .expect("setup command parses");

    let Commands::Setup(args) = cli.command else {
        panic!("expected setup command");
    };
    assert_eq!(args.variant, CliPrivacyVariant::Q4);
}
```

## Desired End State
```sh
# First-run setup. Downloads q4 privacy-filter assets through hf-hub.
heimdall-sandbox setup

# Ad-hoc redaction primitive. Loads from local HF cache; if assets are absent,
# the load/session error is returned. No child process is spawned.
heimdall-sandbox privacy-filter redact --text 'email alice@example.com'

# Optional stdin form for larger captured blurbs.
printf 'email alice@example.com
' | heimdall-sandbox privacy-filter redact --stdin
```

```text
email [REDACTED:EMAIL]
```

```rust
use heimdall_privacy_filter::{redact_text, PrivacyFilterConfig, PrivacyFilterRuntime};

let config = PrivacyFilterConfig::enabled();
let mut runtime = PrivacyFilterRuntime::load(config)?;

// Tool integration boundary:
let raw_for_user = "email alice@example.com".to_string();
let redacted_for_llm = redact_text(&mut runtime, &raw_for_user)?;

// UI/trusted side may show raw_for_user.
// LLM/model context receives redacted_for_llm only.
assert_eq!(redacted_for_llm, "email [REDACTED:EMAIL]");
```

## File Map
```text
Cargo.toml  # MODIFY — workspace member/dependency registration
crates/heimdall-privacy-filter/Cargo.toml  # NEW — privacy runtime crate manifest
crates/heimdall-privacy-filter/src/lib.rs  # NEW — crate-root error/result/API exports
crates/heimdall-privacy-filter/src/model.rs  # NEW — model variants, required files, cache paths
crates/heimdall-privacy-filter/src/input.rs  # NEW — text input/tokenizer-offset context and tensor input builder
crates/heimdall-privacy-filter/src/output.rs  # NEW — normalized detected span output and BIOES/Viterbi decoder
crates/heimdall-privacy-filter/src/session.rs  # NEW — ONNX Runtime session checks/execution helpers
crates/heimdall-privacy-filter/src/setup.rs  # NEW — setup download flow
crates/heimdall-privacy-filter/src/runtime.rs  # NEW — cache-backed tokenizer/session/config/Viterbi loader
crates/heimdall-privacy-filter/src/redaction.rs  # NEW — full-text redaction using detected spans
crates/heimdall-sandbox/Cargo.toml  # MODIFY — add heimdall-privacy-filter dependency
crates/heimdall-sandbox/src/lib.rs  # MODIFY — thin public surface: Cli, Commands, run(), run_from()
crates/heimdall-sandbox/src/commands/mod.rs  # NEW — command module re-exports
crates/heimdall-sandbox/src/commands/exec.rs  # NEW — exec arg structs, conversion, dispatch (extracted from lib.rs)
crates/heimdall-sandbox/src/commands/policy.rs  # NEW — policy arg structs, schema, validation (extracted from lib.rs)
crates/heimdall-sandbox/src/commands/inner_exec.rs  # NEW — hidden Linux inner-exec (extracted from lib.rs)
crates/heimdall-sandbox/src/commands/setup.rs  # NEW — setup arg structs and download dispatch
crates/heimdall-sandbox/src/commands/privacy_filter.rs  # NEW — privacy-filter redact arg structs and dispatch
crates/heimdall-sandbox/src/policy.rs  # NEW — policy JSON schema structs and validation (extracted from lib.rs)
crates/heimdall-sandbox/tests/privacy_filter.rs  # NEW — integration tests for setup/redact command shape
```

## Ordering Constraints
1. Privacy crate foundation, input/output decoder, and session helper types must exist before setup/runtime/CLI can compile.
2. Setup command can be wired once the privacy crate exposes setup request/report types.
3. Runtime cache-backed loader must exist before standalone redaction can call inference.
4. Pure redaction API must exist before the CLI command can print redacted text.
5. CLI module refactoring should land before or alongside new command additions to keep the diff clean.
6. CLI integration and integration tests should land after public privacy crate surfaces are finalized.

## Verification Notes
- `mise format` must pass.
- `mise run --force test` must pass after Rust source implementation.
- Verify no `#[allow(...)]`, `#![allow(...)]`, `#[ignore]`, or test weakening is introduced.
- Verify `heimdall-sandbox setup` is handled in `run_cli()` before `into_exec_request()` and does not execute a child command.
- Verify the redaction command accepts a text blurb and prints redacted text without spawning a sandbox child process.
- Verify the redaction command does not call `ApiRepo::download`, `ApiRepo::get`, `Tokenizer::from_pretrained`, or any network-capable HF path.
- Verify missing cached assets surface as command errors instead of triggering download or producing unredacted model-facing output.
- Verify setup downloads exactly `config.json`, `tokenizer.json`, `tokenizer_config.json`, `viterbi_calibration.json`, `onnx/model_q4.onnx`, and `onnx/model_q4.onnx_data` for the default q4 variant.
- Verify ONNX sidecar filenames are not renamed and the `.onnx` path passed to ORT remains in the same snapshot directory as sidecars.
- Verify inference expects inputs `input_ids` and `attention_mask`, output `logits`, logits last dimension 33, and 33 labels from config.
- Verify ORP/gline-rs are not added as dependencies; they are references only. Direct `ort::Session::builder()` and `Session::run()` calls should be isolated inside `crates/heimdall-privacy-filter/src/session.rs`.
- Verify q4 setup failure does not silently fall back to another model variant.
- Verify optional WebGPU selection uses the native `ort` WebGPU execution provider when selected; CPU remains the default when WebGPU is not selected.
- Verify no `exec` request, executor, stdio, output-forwarding, or policy JSON behavior changes are introduced by this scoped design.
- Verify release packaging docs/tests do not imply model assets are bundled with cargo-dist/npm artifacts.

## Performance Considerations
- Setup can download nearly a gigabyte for q4; progress output should make the long-running operation visible.
- Redaction command startup loads tokenizer, ONNX Runtime session, model config, and Viterbi calibration before inference.
- Optional WebGPU can improve inference latency on supported systems, but selected provider failures should surface as normal runtime/session errors.
- Full-text redaction is intentionally scoped to one captured blurb for this design; streaming stdout/stderr redaction is deferred/rejected for this boundary.
- `Session::run()` requires mutable session access; the standalone command can keep a single mutable runtime instance for one request.

## Migration Notes
No persisted project/user schema migration is required. Setup stores model assets in the Hugging Face cache. Existing policies remain unchanged because this design does not add policy JSON privacy fields.

## Pattern References
- `crates/heimdall-core/src/request.rs:29-162` — builder/accessor pattern for typed `ExecRequest` options.
- `crates/heimdall-sandbox/src/lib.rs:22-56` — top-level and nested CLI command patterns.
- `crates/heimdall-sandbox/src/lib.rs:418-436` — command dispatch, process hardening, and execution call site.
- `/Users/ivan/github/fbilhaut/orp/src/model.rs` — reference for ONNX Runtime session construction, schema checks, and inference boundaries.
- `/Users/ivan/github/fbilhaut/orp/src/pipeline.rs` — reference for separating pre/postprocessing from session execution.
- `/Users/ivan/github/fbilhaut/gline-rs/src/model/pipeline/span.rs` — reference for model-specific expected input/output declarations.
- `/Users/ivan/github/fbilhaut/gline-rs/src/model/pipeline/token.rs` — reference for token-mode decoding and why GLiNER direct use does not match OpenAI input tensors.
- External `fastembed-rs` — reference for `ort` 2.x setup and named-output error handling.

## Developer Context
**Q (conversation correction): How will this be used first?**
A: As a standalone command that receives a blurb of text and returns redacted text. Do not wire it into `exec` stdout/stderr filtering yet.

**Q (conversation): Should this be streaming?**
A: Probably not for the initial use. Capture the output first, then redact the captured text before sending it to the LLM.

**Q (conversation): What sees raw versus redacted output?**
A: The tool/UI shows full raw output to the user; the LLM model receives redacted output only.

**Q (conversation): What is the actual focus?**
A: Technical research for integrating ONNX Runtime in Rust, not product framing or already-solved guard behavior.

**Q: Model assets are huge (`tokenizer.json` ~28MB; ONNX external data ~809MB–5.6GB), and current packaging only ships the CLI crate. Which asset strategy should this design use?**
A: We will download from Hugging Face to the Hugging Face cache on first load.

**Correction:** Automatic first-load download is not desired. There should be a `heimdall-sandbox setup` subcommand that downloads models and performs first-run tasks.

**Q (`crates/heimdall-sandbox/src/lib.rs:22-35`, `39-56`): Which setup command shape should the design lock in?**
A: `setup all` — implemented as `heimdall-sandbox setup` performing all first-run tasks.

**Q: Earlier we chose no default model variant, but `setup all` now performs first-run tasks. How should setup know which privacy-filter model to download?**
A: Built-in default.

**Q (research lines 92-94, 183-186): Which default should `setup all` use?**
A: q4.

**Q (`crates/heimdall-sandbox/src/lib.rs:74-101`): Which user-facing surface should this corrected design include?**
A: CLI setup plus standalone redaction command. Policy JSON privacy behavior is deferred.

**Q (`thoughts/shared/research/2026-05-09_00-05-56_rust-onnx-privacy-filter-runtime.md:55`): How should the design source the revision pin?**
A: Use the Hugging Face Rust crate and do not make this difficult; if needed, capture the pin in code.

**Q (`crates/heimdall-process-hardening/src/lib.rs:146-155`): Which ONNX Runtime linking strategy should the design use?**
A: Download binaries.

**Q (conversation): Should redaction be streaming/windowed for this first design?**
A: No. Capture output first, then redact the full captured blurb before sending it to the LLM.

**Design correction:** The prior exec egress-filtering/redactor direction was rejected. The design now scopes to setup plus full captured-text redaction for LLM-facing output.
A: Use a separate command that receives a blurb of text and returns redacted text. If the model/cache is missing, let loading error naturally; do not add extra model/cache validation gates.

**Slice 1 checkpoint correction:** Developer asked why ORP/gline-rs cannot be used directly and clarified the goal is to avoid low-level ONNX code. Local inspection showed `gline-rs` cannot run OpenAI privacy-filter directly because GLiNER tensor contracts differ, while ORP could run it through a custom pipeline.

**Final model decision:** Use OpenAI privacy-filter for this design.

**Dependency correction:** Do not depend on ORP/gline-rs. Implement the OpenAI runtime directly with `ort` + `tokenizers`, using ORP/gline-rs and fastembed-rs as reference implementations only.

**Rationale:** Avoid being held hostage from `ort` fixes by a thin wrapper crate's version pin or release cadence.

**Q (model card + `ort` features): Should this design include WebGPU support in v1?**
A: Optional WebGPU. CPU remains default; explicit WebGPU selection uses native `ort` EP/session loading and surfaces any provider/session failure as a normal runtime error.

## Design History
- Slice 1: Privacy crate foundation — rethink: replaced low-level ONNX wrapper with custom ORP pipeline architecture for OpenAI privacy-filter
- Slice 1: ORP pipeline foundation — rethink: removed ORP dependency; ORP/gline-rs and fastembed-rs are references only
- Slice 1: Direct ort runtime foundation — approved as generated: direct ort/tokenizers foundation with optional WebGPU and no ORP/gline dependency
- Slice 2: Setup command and HF cache setup — approved as generated
- Slice 3: Cache-only direct ort runtime loader — approved as generated
- Slice 4: Streaming redactor/writer — rejected as wrong approach
- Slice 4: Pure full-text redaction API — revised for capture-first raw-vs-redacted boundary
- Slice 5: Standalone CLI redaction command + CLI module refactoring — pending
- Slice 6: Tests and cleanup — pending

## References
- Research artifact: `thoughts/shared/research/2026-05-09_00-05-56_rust-onnx-privacy-filter-runtime.md`
- Hugging Face model tree API: <https://huggingface.co/api/models/openai/privacy-filter/tree/main?recursive=true>
- OpenAI Privacy Filter README/model card: <https://raw.githubusercontent.com/openai/privacy-filter/main/README.md>
- `orp` local source references: `/Users/ivan/github/fbilhaut/orp/src/model.rs`, `/Users/ivan/github/fbilhaut/orp/src/pipeline.rs`
- `gline-rs` local source references: `/Users/ivan/github/fbilhaut/gline-rs/src/model/pipeline/span.rs`, `/Users/ivan/github/fbilhaut/gline-rs/src/model/pipeline/token.rs`
- `hf-hub` 0.5 sync API docs: <https://docs.rs/hf-hub/latest/hf_hub/api/sync/struct.ApiRepo.html>
- `hf-hub` cache docs: <https://docs.rs/hf-hub/latest/hf_hub/struct.CacheRepo.html>
- `ort` session builder docs: <https://docs.rs/ort/latest/ort/session/builder/struct.SessionBuilder.html>
- `ort` session docs: <https://docs.rs/ort/latest/ort/session/struct.Session.html>
- `ort` values docs: <https://ort.pyke.io/fundamentals/value>
- `tokenizers::Tokenizer` docs: <https://docs.rs/tokenizers/latest/tokenizers/tokenizer/struct.Tokenizer.html>
- ONNX Runtime large model/external data docs: <https://onnxruntime.ai/docs/tutorials/web/large-models.html>
