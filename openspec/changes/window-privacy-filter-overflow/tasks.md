## 1. Metadata and Window Planning

- [x] 1.1 Load and validate the usable token limit from cached privacy-filter tokenizer/model metadata during runtime setup.
- [x] 1.2 Add an internal token-window planner that keeps single-window input unchanged and splits overflow into overlapping token ranges.
- [x] 1.3 Add planner tests proving full token coverage, forward progress, overlap behavior, and metadata failure behavior.

## 2. Encoding and Offset Preservation

- [x] 2.1 Extend encoded privacy input/context structures so each generated window carries original byte offsets.
- [x] 2.2 Update tokenizer encoding to produce model-ready tensors for one or more windows without truncating overflow text.
- [x] 2.3 Add tests for original byte offsets in overflow windows, including UTF-8 text around window boundaries.

## 3. Runtime and Span Merging

- [x] 3.1 Update privacy-filter runtime detection to run all planned windows and collect spans from each window.
- [x] 3.2 Add deterministic span merge/deduplication before redaction is applied to the original text.
- [x] 3.3 Add tests for duplicate overlap detections and partially overlapping detections.

## 4. End-to-End Validation

- [x] 4.1 Add long-input redaction tests that place sensitive text after the first window and verify it is redacted.
- [x] 4.2 Add CLI-level coverage showing file/stdin overflow input is processed without length truncation.
- [x] 4.3 Run `mise format` and `mise run --force test`.
