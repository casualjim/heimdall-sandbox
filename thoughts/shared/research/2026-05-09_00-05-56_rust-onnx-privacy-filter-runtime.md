---
date: 2026-05-09T00:05:56-0700
author: Ivan Porto Carrero
commit: d9d522e
branch: onnx-privacy
repository: heimdall-sandbox
topic: "Rust ONNX runtime integration for openai/privacy-filter"
tags: [research, rust, onnx, onnx-runtime, tokenizers, privacy-filter]
status: complete
last_updated: 2026-05-09T11:54:52-0700
last_updated_by: Ivan Porto Carrero
last_updated_note: "Added external Rust ort integration survey"
---

# Research: Rust ONNX runtime integration for `openai/privacy-filter`

## Research Question
How should this Rust project integrate a local/offline ONNX runtime for Hugging Face `openai/privacy-filter`, including model artifact packaging/loading, tokenizer compatibility, ONNX Runtime APIs, output interpretation, platform packaging, and fail-closed behavior?

## Summary
`openai/privacy-filter` ships native ONNX assets plus tokenizer/config/Viterbi metadata, but the ONNX graphs use external data files that must remain beside the `.onnx` file with their original names. A Rust implementation should use a local asset root, `tokenizers::Tokenizer::from_file("tokenizer.json")`, and `ort` sessions loaded from the selected ONNX file; it should validate required files, input/output metadata, and label shape at startup before executing or forwarding any text. CPU-only ONNX Runtime is the lowest-complexity cross-platform path for macOS/Linux; accelerated execution providers add dynamic-library and fallback semantics that must be made explicit.

## Detailed Findings

### Available model artifacts
Hugging Face tree API currently lists these relevant files for `openai/privacy-filter`:

- `config.json` — 3,039 bytes; contains `id2label`, `label2id`, model metadata, `default_n_ctx: 128000`, `max_position_embeddings: 131072`, `model_type: openai_privacy_filter`.
- `tokenizer.json` — 27,868,174 bytes; required for Rust tokenizer execution.
- `tokenizer_config.json` — declares backend `tokenizers`, inputs `input_ids` and `attention_mask`, `model_max_length: 128000`, pad/eos token `<|endoftext|>`.
- `viterbi_calibration.json` — currently one `default` operating point with six transition biases, all `0.0`.
- ONNX variants:
  - `onnx/model.onnx` + `model.onnx_data`, `model.onnx_data_1`, `model.onnx_data_2` (~5.6 GB external data total).
  - `onnx/model_fp16.onnx` + `model_fp16.onnx_data`, `model_fp16.onnx_data_1` (~2.8 GB external data total).
  - `onnx/model_q4.onnx` + `model_q4.onnx_data` (~917 MB external data).
  - `onnx/model_q4f16.onnx` + `model_q4f16.onnx_data` (~809 MB external data).
  - `onnx/model_quantized.onnx` + `model_quantized.onnx_data` (~1.6 GB external data).

Implementation consequence: package a selected variant directory intact. Do not rename `*.onnx_data*`; ONNX stores external weight locations in the model protobuf and native ONNX Runtime expects those files on disk relative to the model.

### Required local asset layout
Recommended offline bundle shape:

```text
privacy-filter/
  config.json
  tokenizer.json
  tokenizer_config.json
  viterbi_calibration.json
  onnx/
    model_q4.onnx
    model_q4.onnx_data
```

Use a configured asset root or install-time resolved data directory. Do not call Hugging Face at runtime. Pin the Hugging Face revision used to produce the bundle and record hashes/sizes for every asset in packaging metadata.

### Rust runtime crates

#### `ort`
`ort` is the Rust binding for ONNX Runtime. Relevant APIs and constraints:

- `ort::init()` or `ort::init_from(path)?.commit()` must happen before sessions are created when using runtime dynamic loading.
- `Session::builder()?.commit_from_file("model.onnx")?` loads a graph from disk.
- `Session::inputs()` / `Session::outputs()` should be used at startup to validate metadata.
- `Session::run()` runs inference.
- `load-dynamic` is useful for CLI packaging because a missing `libonnxruntime.so`/`.dylib` becomes a normal startup error instead of an executable load failure.

CPU EP first is the least surprising macOS/Linux path. If adding CoreML/CUDA/WebGPU/etc., configure EP failures explicitly: `ort` documents that failed EP registration can silently fall back to CPU unless `.error_on_failure()` is applied.

#### `tokenizers`
The Hugging Face `tokenizers` crate is Rust-native and can load the serialized tokenizer locally. Use local deserialization (`Tokenizer::from_file("tokenizer.json")`), not `Tokenizer::from_pretrained`, because the latter requires the optional HTTP feature and creates a runtime download path. Encoding offsets are required to convert token predictions back to original text spans.

### ONNX model contract to validate
From the model config/card/tokenizer config:

- Inputs: `input_ids`, `attention_mask`.
- Output: logits, to verify by inspecting `Session::outputs()`; expected shape is `[T, 33]` or `[B, T, 33]`.
- Labels: 33 classes: `O` plus BIOES (`B/I/E/S`) for eight categories: `account_number`, `private_address`, `private_date`, `private_email`, `private_person`, `private_phone`, `private_url`, `secret`.
- Post-processing: constrained Viterbi BIOES decoding, not independent argmax. Bundle and parse `viterbi_calibration.json` even though current default biases are all zero.

Startup checks should fail closed if:

- any required file is missing;
- external ONNX data files are missing/misnamed;
- ONNX Runtime dylib cannot be loaded;
- tokenizer fails to load;
- session inputs are not exactly compatible with `input_ids` / `attention_mask`;
- output logits do not have 33 classes;
- `config.json` label count/order does not match logits last dimension;
- selected quantized variant uses operators unsupported by the chosen native CPU runtime.

### Quantized variant risk
The repository includes `q4`, `q4f16`, and `model_quantized` ONNX files. The model card’s Transformers.js example uses `{ device: "webgpu", dtype: "q4" }`, and `config.json` has `transformers.js_config.use_external_data_format`. That proves the assets are intended to work in Transformers.js, but does not by itself prove native ONNX Runtime CPU compatibility for every quantized variant. Before choosing `model_q4.onnx` as the default Rust asset, inspect and load it with native ONNX Runtime CPU in CI or an asset validation tool. If q4 fails, fall back at packaging/design time to `model_quantized` or `fp16`; do not fallback silently at runtime.

### Binary/package impact
Do not embed these assets into the Rust binary with `include_bytes!`:

- tokenizer alone is ~28 MB;
- smallest listed ONNX external data variant is ~809 MB;
- full/fp16 variants are multi-GB.

Treat the model as install data or an optional package artifact selected at install/build time. For npm/Homebrew/cargo distribution, this likely means one of:

1. a separate model-assets package/archive downloaded by installer/release tooling, not runtime code;
2. a configured local asset directory required by policy/config;
3. package variants (`heimdall-sandbox` vs `heimdall-sandbox-privacy-filter-assets`) if distributing huge assets through npm/casks is acceptable.

The runtime must not auto-download missing assets. Missing assets are configuration errors.

### Execution integration constraint in this repo
Current `heimdall-core` forwards child output only in piped mode:

- `StdioPolicy::Inherit` gives child stdout/stderr directly to the parent (`crates/heimdall-core/src/executor.rs:173-179`).
- `StdioPolicy::Piped` captures stdout/stderr (`crates/heimdall-core/src/executor.rs:180-185`).
- `OutputForwarding::start()` forwards owned pipes (`crates/heimdall-core/src/executor.rs:196-218`).
- `copy_stream()` is currently raw `std::io::copy()` (`crates/heimdall-core/src/executor.rs:230-232`).

If ONNX redaction is applied to command output, inherited stdout/stderr cannot be redacted. Developer checkpoint resolved: when privacy filtering is enabled, preserve stdin behavior but force stdout/stderr through filtered pipes internally.

Important ONNX-specific caveat: this model is token-classification over text windows, not byte-stream redaction. A streaming output redactor must buffer text windows, preserve tokenizer offsets, hold back enough overlap to avoid leaking spans across chunk boundaries, run model inference on windows, then write redacted text. It cannot be a simple byte-by-byte transform.

### Failure handling
Load the runtime/model/tokenizer before spawning the child process whenever filtering is required. If setup fails, do not execute the command and do not forward unredacted output. This matches current fail-closed project rules and avoids runtime fallback from model filtering to raw `copy_stream()`.

For stream-time inference failures, the current `OutputForwarding::join()` discards thread results (`crates/heimdall-core/src/executor.rs:220-227`); a real implementation must propagate forwarding/redaction errors back to `Executor.execute()` so the CLI can print the error and return its error code.

## Code References
- `Cargo.toml:2-8` — current workspace members; no ONNX/runtime crate exists.
- `Cargo.toml:28-42` — workspace deps; no `ort`, `tokenizers`, `hf-hub`, or model runtime deps.
- `crates/heimdall-core/src/executor.rs:173-185` — inherited vs piped stdio; redaction only possible on owned streams.
- `crates/heimdall-core/src/executor.rs:196-233` — current output forwarding and raw copy seam.
- `crates/heimdall-core/src/error.rs:6` — existing sandbox misconfiguration exit code.
- `crates/heimdall-sandbox/src/lib.rs:287-302` — policy loading/parsing precedent for explicit file input.
- `crates/heimdall-sandbox/src/lib.rs:305-318` — unknown policy fields are rejected, so privacy config must be schema-owned.

## Architecture Insights
- Keep model runtime concerns separate from CLI config parsing. CLI/policy should carry typed paths/options; ONNX/session/tokenizer objects should be runtime internals.
- Use `ort` + `tokenizers` with local files only. Avoid `hf-hub` and `Tokenizer::from_pretrained` in runtime paths unless explicitly building an offline installer/downloader tool.
- Validate model metadata at startup rather than trusting filenames.
- Keep regex/allowlist-style secret blocking separate from ONNX span detection; they have different failure modes and inputs.
- For this repo’s streaming stdout/stderr path, filtering requires an output-windowing abstraction, not direct `std::io::copy()`.

## Precedents & Lessons
- `4d0c26f` — minimal runtime added inherited/piped output forwarding; lesson: preserve faithful stdout/stderr semantics when interposing on output.
- `733f2e7` — Linux bubblewrap policy/schema path; lesson: add fields through parser/schema/validation and fail closed on missing capabilities.
- `216dcd2` — macOS Seatbelt/shared policy extraction; lesson: keep platform-neutral policy intent separate from platform/runtime mechanics.
- `3fd8ac4` plus follow-up release fixes — adding crates/assets affects publish ordering and release packaging; plan model assets separately from core crates.

## Developer Context
**Q (`crates/heimdall-core/src/executor.rs:173-185`): When privacy filtering is enabled, should Heimdall force stdout/stderr through filtered pipes or reject inherited stdio?**
A: Force filtered pipes. Preserve stdin behavior, but internally pipe stdout/stderr through the redactor.

**Q (conversation): What is the actual focus?**
A: Technical research for integrating ONNX Runtime in Rust, not product framing or already-solved guard behavior.

## Open Questions
- Which ONNX variant (`q4`, `q4f16`, `model_quantized`, `fp16`, full) successfully loads and runs on native ONNX Runtime CPU across target macOS/Linux platforms?
- What is the exact output name reported by `Session::outputs()` for each chosen ONNX variant?
- Should the model assets be shipped in the main package, a separate asset package, or required as a configured local directory?
- How large should streaming text windows and overlap be for acceptable latency without leaking spans across chunk boundaries?

## Sources
- Hugging Face model tree API: <https://huggingface.co/api/models/openai/privacy-filter/tree/main?recursive=true>
- Model config: <https://huggingface.co/openai/privacy-filter/raw/main/config.json>
- Tokenizer config: <https://huggingface.co/openai/privacy-filter/raw/main/tokenizer_config.json>
- Viterbi calibration: <https://huggingface.co/openai/privacy-filter/raw/main/viterbi_calibration.json>
- OpenAI Privacy Filter README/model card: <https://raw.githubusercontent.com/openai/privacy-filter/main/README.md>
- `ort` crate docs: <https://docs.rs/ort/latest/ort/>
- `ort` dynamic linking docs: <https://ort.pyke.io/setup/linking>
- `ort` execution provider docs: <https://ort.pyke.io/perf/execution-providers>
- `tokenizers` crate docs: <https://docs.rs/tokenizers/latest/tokenizers/>
- ONNX Runtime external data docs: <https://onnxruntime.ai/docs/tutorials/web/large-models.html>

## Follow-up Research 2026-05-09T00:11:00-0700

### GGUF availability
No official or credible GGUF build was found for `openai/privacy-filter`. The official Hugging Face tree has ONNX, safetensors, tokenizer, config, and Viterbi metadata, but no `.gguf` artifact. Hugging Face model API searches for `privacy-filter gguf` and `openai privacy filter gguf` returned no model results.

### Why GGUF is not a drop-in target
`openai/privacy-filter` is a bidirectional token-classification model. It emits 33 logits per token and then requires constrained BIOES/Viterbi span decoding. GGUF/llama.cpp is primarily a runtime/container path for supported GGML architectures, especially causal decoder LLMs. A useful GGUF port would require llama.cpp support for this model architecture, token-classification head, 33-label logits, tokenizer offsets, and Viterbi post-processing. Merely converting tensors to GGUF would not provide the required runtime behavior.

### ONNX accuracy/depth tradeoff
ONNX itself is a graph/runtime format and does not inherently reduce model depth or accuracy. A full-precision ONNX export should preserve the same architecture and be close to the source checkpoint subject to export/runtime numerical differences. Smaller/faster ONNX variants (`q4`, `q4f16`, `model_quantized`, `fp16`) trade numeric precision for size/speed; that can reduce detection quality, especially around boundaries and rare secret/PII formats. Quantization changes precision, not layer count/depth, unless a separate distillation/pruning process is used.

### Practical recommendation
Use full or fp16 ONNX as the accuracy baseline, then evaluate `q4`, `q4f16`, and `model_quantized` against project redaction fixtures before choosing a default. Treat variant choice as a benchmarked packaging decision, not as automatic proof that smaller/faster is good enough.

### Follow-up sources
- Official Hugging Face model tree API: <https://huggingface.co/api/models/openai/privacy-filter/tree/main?recursive=true>
- Hugging Face model search API (`privacy-filter gguf`): <https://huggingface.co/api/models?search=privacy-filter%20gguf&limit=20>
- Hugging Face model search API (`openai privacy filter gguf`): <https://huggingface.co/api/models?search=openai%20privacy%20filter%20gguf&limit=20>
- OpenAI Privacy Filter README/model card: <https://raw.githubusercontent.com/openai/privacy-filter/main/README.md>
- Hugging Face GGUF/llama.cpp docs: <https://huggingface.co/docs/hub/gguf-llamacpp>

## Follow-up Research 2026-05-09T00:20:00-0700

### Breeze ONNX precedent
`~/github/casualjim/breeze` does use ONNX Runtime for local embeddings, and it confirms the hard parts are mostly runtime/linking/assets rather than the `Session::run()` call itself.

Useful patterns to copy:
- `crates/breeze-indexer/Cargo.toml:8,28-30` — gates ONNX behind `local-embeddings`; uses `ort` with `load-dynamic`, `ndarray`, `half`, and `coreml` on macOS.
- `crates/breeze-indexer/src/embeddings/local/ort_bert.rs:134,169-191` and `crates/breeze-indexer/src/embeddings/local/ort_qwen3.rs:50,62-84` — loads tokenizer from local cached file, builds `Session`, applies optimization/thread settings, then `commit_from_file()`.
- `crates/breeze-indexer/src/embeddings/local/ort_bert.rs:214-232` — inspects session inputs/outputs and conditionally supplies `token_type_ids`; privacy-filter should use the same idea but validate exact `input_ids`, `attention_mask`, and a logits output with 33 classes.

Patterns not to copy for Heimdall privacy filtering:
- `crates/breeze-indexer/src/lib.rs:37-61` — global `small_ctor` + `OnceLock` ORT init. Prefer explicit startup/model-load errors for fail-closed privacy behavior.
- `crates/breeze-indexer/src/embeddings/local/ort_bert.rs:72-106` and `crates/breeze-indexer/src/embeddings/local/ort_qwen3.rs:36-46` — runtime `hf_hub::Api` downloads. Privacy-filter should use a local/offline asset root only.
- `crates/breeze-indexer/src/embeddings/local/ort_qwen3.rs:249-252` — CI skips due incomplete model files/disk constraints. Heimdall tests should use committed stubs/fixtures for runtime seams, not skip required privacy behavior.

Packaging precedent:
- `Dockerfile:38,49` — runtime `LD_LIBRARY_PATH` and copying ORT libs into `/opt/onnxruntime/lib`.
- `.github/actions/setup-env/action.yml:62-82` — Linux CI downloads ONNX Runtime and exports `ORT_LIBRARY_PATH`/`LD_LIBRARY_PATH`.
- `.github/workflows/CI.yml:452-474` — release Docker flow downloads ORT libs outside Docker and copies them into dist layout.
- `com.github.casualjim.breeze.server.plist.template:27` — macOS launchd needs `ORT_DYLIB_PATH`.

Takeaway: use Breeze as proof that `ort` + `tokenizers` works in Rust, but do not transplant it wholesale. Copy the session/tokenizer/input-validation mechanics; avoid global ctor init, runtime model downloads, CI skips, and implicit execution-provider/runtime fallback.

## Follow-up Research 2026-05-09T11:54:52-0700

### External Rust `ort` integration survey
Breeze should be treated as a negative/experience precedent, not the implementation model. I checked external Rust `ort` users and found three more useful precedent families.

#### `fastembed-rs` — best `ort` 2.x production precedent
Repo: <https://github.com/Anush008/fastembed-rs> at `c34435d`.

Useful patterns:
- `Cargo.toml:29-52` uses `ort = 2.0.0-rc.12` with `ndarray`, `std`, and feature switches for `ort/download-binaries` vs `ort/load-dynamic`.
- `src/text_embedding/impl.rs:84-100` builds a session with caller-provided execution providers, graph optimization level 3, intra threads, a DirectML-specific memory-pattern/parallel-execution workaround, then `commit_from_file()`.
- `src/text_embedding/impl.rs:116-162` supports BYO model bytes, BYO tokenizer files, and external initializer files, then `commit_from_memory()`.
- `src/text_embedding/init.rs:78-122` models ONNX bytes, tokenizer files, quantization, output key, and external initializer file buffers explicitly.
- `src/text_embedding/impl.rs:180-188` derives whether `token_type_ids` is needed by inspecting session inputs.
- `src/text_embedding/impl.rs:400-420` builds `input_ids`/`attention_mask`, conditionally adds `token_type_ids`, runs the session, and preserves all output names.
- `src/output/embedding_output.rs:30-49` selects model output by explicit precedence and errors with available output names when no suitable output exists.

Avoid for Heimdall privacy-filter:
- Default features include HF Hub and ONNX binary download (`Cargo.toml:43-52`), which is good for a library but not for fail-closed offline privacy filtering.
- Some tests rely on network/cache and large downloads (`tests/text-embeddings.rs:212-268`, `:345-361`); use deterministic fixtures/stubs instead.

#### `orp` + `gline-rs`/`gliclass-rs` — best schema/pipeline precedent
Repos: <https://github.com/fbilhaut/orp>, <https://github.com/fbilhaut/gline-rs>, <https://github.com/fbilhaut/gliclass-rs> at `orp c074d0a`, `gline 6dce27e`, `gliclass 674b501`.

Useful patterns:
- `orp/src/model.rs:20-24` and `:32-36` centralize session creation from file or bytes with threads, execution providers, graph optimization, and `commit_from_file()` / `commit_from_memory()`.
- `orp/src/model.rs:80-93` validates actual ONNX session inputs/outputs against pipeline-declared expectations before inference.
- `orp/src/error.rs:10-20` reports mismatched input/output tensor sets explicitly.
- `gline-rs/src/model/pipeline/token.rs:46-64` declares expected inputs and expected outputs from the concrete token-classification pipeline.
- `gline-rs/src/model/input/tensors/token.rs:7-45` names exact token-mode ONNX inputs and converts encoded text into `SessionInputs`.
- `gline-rs/src/model/output/decoded/token.rs:12-50` requires `logits`, checks output shape, and extracts `f32` tensor data.
- `gline-rs/src/model/output/decoded/token.rs:130-132` enforces expected logits shape for token-mode NER before decoding.
- `gliclass-rs/src/input/tensors.rs:7-25` shows a simpler classification pipeline with exact `input_ids`/`attention_mask` inputs.
- `gliclass-rs/src/output/classes.rs:7-20` requires `logits` and extracts the tensor before post-processing.

Heimdall privacy-filter should copy this shape more than Breeze: a small model wrapper with a declared contract (`input_ids`, `attention_mask`, `logits`, last dim 33), explicit schema validation before inference, and post-processing as a separate Rust stage.

#### `rust-bert` ONNX support — useful but old API / heavier stack
Repo: <https://github.com/guillaume-be/rust-bert> at `6db859e`.

Useful patterns:
- `Cargo.toml:54-73` gates ONNX behind an `onnx` feature and depends on `ort`, `ndarray`, and optional tokenizer support.
- `Cargo.toml:110` uses `ort` with `load-dynamic` in dev dependencies.
- `src/pipelines/onnx/config.rs:8-19` centralizes conventional ONNX NLP input/output names (`input_ids`, `attention_mask`, `token_type_ids`, `logits`, etc.).
- `src/pipelines/onnx/config.rs:60-91` maps a runtime config into session-builder options: optimization, threads, parallel execution, memory pattern, allocator, memory type.
- `src/pipelines/onnx/common.rs:11-38` records model input/output names from session metadata.
- `src/pipelines/onnx/encoder.rs:124-153` builds inputs by matching the session's expected input names and fails if a required input is missing.
- `src/pipelines/onnx/encoder.rs:160-177` extracts optional named outputs such as `last_hidden_state`, `logits`, `start_logits`, and `end_logits`.
- `examples/onnx-token-classification.rs:9-24` demonstrates an ONNX token-classification pipeline using ONNX model/config/vocab resources.

Caveat: `rust-bert` uses older `ort` 1.16 APIs and a large `tch`-oriented stack. Use it for design ideas, not direct implementation code.

### Revised Heimdall recommendation from survey
- Use `ort` 2.x APIs like `fastembed-rs`, not Breeze's older trial-and-error shape.
- Make runtime loading explicit: choose either `download-binaries` for build-time convenience or `load-dynamic` for controlled deployment errors. For Heimdall, `load-dynamic` plus explicit dylib path/config is safer.
- Do not use runtime HF downloads; make an asset-root contract and validate required files.
- Add a privacy-filter wrapper with a declared model contract and schema validation before first inference, borrowing the `orp` pattern.
- Build a post-processing layer separate from ONNX session execution: token offsets + logits -> BIOES/Viterbi spans -> redacted text.
- Preserve named-output errors like `fastembed-rs`: if `logits` is missing or shape is wrong, fail closed with available outputs and do not redact by passthrough.
