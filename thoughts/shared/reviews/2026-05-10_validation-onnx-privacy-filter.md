---
date: 2026-05-10
author: validate skill
branch: onnx-privacy
commit: d9d522e (HEAD)
plan: thoughts/shared/plans/2026-05-10_21-09-04_onnx-privacy-filter-setup-runtime.md
status: partial
---

# Validation Report: ONNX Privacy-Filter Setup and Runtime Integration

## Implementation Status

| Phase | Name | Status |
|---|---|---|
| Phase 1 | Privacy Crate Foundation | ✅ Fully implemented (uncommitted) |
| Phase 2 | CLI Module Refactoring | ❌ Not started |
| Phase 3 | Setup and Redaction CLI Commands | ❌ Not started |
| Phase 4 | Integration Tests | ❌ Not started |

## Automated Verification Results

| Check | Result |
|---|---|
| `mise format` (cargo-check, clippy, rustfmt, cargo-sort, etc.) | ✅ PASS — all hooks green |
| `mise run --force test` | ✅ PASS — 95/95 tests, 0 skipped |
| `cargo check -p heimdall-privacy-filter` | ✅ PASS — compiles cleanly |
| No `#[allow(...)]` / `#[ignore]` in privacy crate | ✅ PASS |
| No orp/gline-rs/fastembed-rs dependencies | ✅ PASS |
| `ort` workspace features include `download-binaries`, `ndarray`, `webgpu` | ✅ PASS |
| `runtime.rs` cache-only (no network-capable HF paths) | ✅ PASS |
| No `println!` or `dbg!` in privacy crate | ✅ PASS |
| No bare `.unwrap()` or `.expect()` in production paths | ✅ PASS |

## Phase 1 Detailed Review

### Matches Plan

| File | Verdict |
|---|---|
| `heimdall-privacy-filter/Cargo.toml` | ✅ MATCH — all 7 workspace deps |
| `src/lib.rs` | ✅ MATCH — 10 Error variants, Result<T>, re-exports |
| `src/model.rs` | ✅ MATCH — constants, enums, config, asset paths |
| `src/setup.rs` | ✅ MATCH — SetupRequest, SetupReport, hf-hub sync download |
| `src/runtime.rs` | ✅ MATCH — cache-only loading, detect_spans, detect_batch |
| `src/redaction.rs` | ✅ MATCH — CapturedTextRedaction, apply_spans |

### Documented Deviations (All Acceptable)

| File | Deviation | Assessment |
|---|---|---|
| `src/input.rs` | Added `impl From<ndarray::ShapeError> for Error` | ✅ Required — plan code would not compile without it (`push_row` returns `ShapeError`) |
| `src/output.rs` | Added `is_empty()` on `PrivacyLabels` | ✅ Required — clippy warns when `len()` exists without `is_empty()` |
| `src/output.rs` | `_tokens` prefix on unused match arm | ✅ Required — clippy unused-binding warning |
| `src/session.rs` | `input.name()` method vs `input.name` field | ✅ Required — adapts to actual `ort` 2.0.0-rc.12 API surface |
| `src/session.rs` | Explicit `.map_err(onnx_error)?` helper | ✅ Neutral — more defensive, same runtime behavior |
| Workspace `Cargo.toml` | `tokenizers` adds `features = ["onig", "esaxx_fast"]` | ✅ Required — BPE tokenization needs these for the OpenAI model |

### Minor Finding (Non-blocking)

| File | Issue | Risk |
|---|---|---|
| `src/session.rs` `run()` | Removed `or_else(\|\| outputs.iter().next())` fallback for unnamed outputs | **Low** — `validate_schema` accepts single-output models, but `run()` only accepts explicitly named `"logits"`. Logical inconsistency. Safe for openai/privacy-filter (always names output "logits"). Could surprise if reused with a model that has a single unnamed output. |

### Codebase Pattern Compliance

| Check | Status |
|---|---|
| Error handling (thiserror + crate-root Result) | ✅ MATCH |
| Cargo.toml workspace refs | ✅ MATCH |
| Module organization (private mods + pub use) | ✅ MATCH |
| Public API doc comments | ✅ MATCH — all public items documented |
| Builder pattern (consuming `with_*` methods) | ✅ MATCH |
| `#[must_use]` on accessors | ✅ MATCH |

## Phases 2–4: Not Started

- **Phase 2** (CLI Module Refactoring): No `crates/heimdall-sandbox/src/commands/` directory exists. `lib.rs` is still monolithic.
- **Phase 3** (Setup and Redaction CLI Commands): No `heimdall-privacy-filter` dependency in `heimdall-sandbox/Cargo.toml`. No `Setup` or `PrivacyFilter` variants in `Commands` enum.
- **Phase 4** (Integration Tests): No `privacy_filter.rs` test file in `crates/heimdall-sandbox/tests/`.

## Summary

**Phase 1: COMPLETE and VALIDATED.** Implementation matches plan with documented, necessary deviations. All automated checks pass. No regressions, no banned patterns, no missing validations.

**Phases 2–4: NOT STARTED.** Remaining work:
1. Refactor `heimdall-sandbox` CLI into command modules
2. Wire `setup` and `privacy-filter redact` commands
3. Add integration tests for CLI parsing and command wiring

## Recommendations

1. **Phase 1 commit** — Ready to commit. Clean, validated, all checks pass.
2. **session.rs logits fallback** — Consider restoring the `or_else(|| outputs.iter().next())` fallback for robustness if the crate is ever reused with models that don't name their output "logits". Low priority.
3. **Proceed to Phase 2** — CLI module refactoring is independent of the privacy crate and can proceed next.

---

**Next step:** `/skill:commit` — commit Phase 1 changes, then continue with Phase 2 implementation.
