## Why

Privacy-filter currently encodes each input as a single tokenizer sequence before ONNX inference. Inputs longer than the model/tokenizer context must not be truncated or rejected because privacy redaction must cover the full user-provided text.

## What Changes

- Add long-input handling that automatically splits overflow input into overlapping tokenizer windows.
- Preserve original byte offsets for every window so decoded sensitive spans redact the original text correctly.
- Merge and deduplicate spans found across overlapping windows before applying redaction.
- Derive the usable token limit from cached model/tokenizer metadata instead of hardcoding a CLI-only limit.
- Keep overflow behavior non-configurable: overflow always windows; no truncate/reject mode.

## Capabilities

### New Capabilities
- `privacy-filter-windowing`: Privacy-filter runtime behavior for covering long text inputs with tokenizer-aligned overlapping model windows.

### Modified Capabilities

## Impact

- Affects `heimdall-privacy-filter` input encoding, runtime orchestration, span decoding context, and tests.
- Affects `heimdall-sandbox privacy-filter redact` behavior for very large positional/file/stdin inputs through the shared runtime.
- Does not add a `text-splitter` dependency; tokenizer offsets are the correctness boundary.
- Does not change WebGPU execution-provider behavior.
