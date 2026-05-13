## Context

`heimdall-privacy-filter` currently tokenizes each submitted text into one sequence in `EncodedPrivacyInput::encode`, pads batch rows to the longest sequence, and sends that tensor to one ONNX session run from `PrivacyFilterRuntime::detect_batch`. The pinned OpenAI privacy-filter assets advertise a large but finite tokenizer/model context (`model_max_length` near 128k tokens, model positions near 131k). Inputs can still exceed that limit when users redact whole files, logs, or redirected streams.

Privacy redaction has a stricter safety requirement than normal inference: overflow cannot silently truncate and cannot ask the caller to choose a weaker mode. Every byte of the original input must be represented in at least one model window, and decoded spans must map back to the original byte offsets before redaction is applied.

## Goals / Non-Goals

**Goals:**

- Automatically process overflow inputs with overlapping tokenizer-aligned windows.
- Preserve original byte offsets across windowing so redaction applies to the original input exactly once.
- Keep the current single-window path for inputs within the usable context limit.
- Derive the usable model limit from cached tokenizer/model metadata when loading assets.
- Add tests that prove overflow is covered, overlaps dedupe, and no truncation occurs.

**Non-Goals:**

- Do not add a user-facing truncate/reject/window mode; windowing is mandatory on overflow.
- Do not introduce `text-splitter` as the correctness mechanism.
- Do not change WebGPU/provider selection behavior.
- Do not redesign redaction labels, Viterbi decoding, or model asset setup beyond metadata needed for limits.

## Decisions

### Token windows are the correctness primitive

Use tokenizer encodings and their offset mappings to build windows. Paragraph, sentence, or semantic splitters can miss model-specific token boundaries and do not directly express the ONNX context limit. Token windows let the runtime prove that all encoded tokens, and therefore all offset-bearing byte ranges, are covered.

Alternative considered: add `text-splitter` and split by text size. That is useful for readability-oriented chunking, but it does not guarantee model-token budget compliance without a second tokenizer pass. For privacy redaction the tokenizer is the source of truth.

### Window only when the encoded sequence exceeds the usable limit

For a text whose encoded length fits the usable limit, keep the existing single sequence behavior. For longer text, create windows of at most the usable limit with a fixed overlap. The overlap must be smaller than the limit and large enough to catch entities near boundaries.

A conceptual shape:

```text
tokens:  0 ........................................ 127999 128000 ...
window0 [0 ........................................ 127999]
window1                          [127744 ......................]
                                  overlap protects boundary spans
```

Implementation should define the overlap as an internal constant first; it can be tuned later with benchmarks and fixtures. The runtime should fail during initialization if metadata produces an unusable limit or if overlap configuration would prevent forward progress.

### Preserve original offsets in each window

Each window context should carry token offsets that still refer to the original input text, not a substring-local coordinate space. Decoding can then reuse the existing byte-span concept and produce spans in original byte coordinates. Redaction should continue to operate on the original text once after all windows finish.

This avoids stitching substring-local spans and avoids accidental off-by-one behavior around UTF-8 boundaries.

### Merge spans after all windows decode

Overlapping windows can produce duplicate or partially overlapping spans. The runtime should collect spans from every window, sort them by byte range, and deduplicate/merge before redaction. The merge policy should preserve privacy: if two same-category spans overlap or touch, prefer a single covering span. If categories differ and spans overlap, keep deterministic existing redaction precedence by sorting and applying the first covering span rather than exposing raw text.

### Keep batching optional to the internal design

The simplest implementation can run each window sequentially through the existing session path. A later optimization can batch windows because `EncodedPrivacyInput` already represents `[B, T]`, but correctness should not depend on batching. If batching is used, padding remains internal and mask-driven.

## Risks / Trade-offs

- **Window overlap misses very long cross-boundary entities** → Use a conservative overlap and add boundary tests; very large entities still appear across multiple windows but the model may only tag visible portions.
- **More inference calls for huge input** → This is required to avoid truncation; sequential windowing can be optimized later with batching.
- **Metadata is missing or inconsistent** → Treat this as an initialization error rather than guessing an unsafe hardcoded limit.
- **Duplicate spans create noisy output** → Centralize span merging before redaction and test exact-overlap and partial-overlap cases.
- **Large inputs allocate large encoded vectors** → Full tokenization is needed to plan windows; avoid extra copies where possible and only materialize window tensors needed for inference.
