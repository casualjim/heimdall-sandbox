---
date: 2026-05-11T14:45:00-0700
branch: onnx-privacy
commit: d9d522e
plan: thoughts/shared/plans/2026-05-10_21-09-04_onnx-privacy-filter-setup-runtime.md
status: complete
---

# Validation Report: ONNX Privacy-Filter Setup and Runtime

## Implementation Status

- ✅ Phase 1: Privacy Crate Foundation — Fully implemented
- ✅ Phase 2: CLI Module Refactoring — Fully implemented
- ✅ Phase 3: Setup and Redaction CLI Commands — Fully implemented
- ✅ Phase 4: Integration Tests — Fully implemented (10 tests, plan specified 7)

## Automated Verification Results

| Check | Status |
|---|---|
| `cargo check -p heimdall-privacy-filter` | ✅ PASS |
| `cargo check -p heimdall-sandbox` | ✅ PASS |
| `mise format` | ✅ PASS (shellcheck, cargo-sort, check-toml, rustfmt, trailing-whitespace, etc.) |
| `mise run --force test` | ✅ 105/105 tests pass, 0 skipped, 0 failed |
| No `#[allow(...)]` in privacy crate | ✅ NONE FOUND |
| No `#[ignore]` in privacy crate | ✅ NONE FOUND |
| No ORP/gline-rs/fastembed-rs deps | ✅ NONE FOUND |
| No `ApiRepo::download` / `Tokenizer::from_pretrained` in runtime + CLI | ✅ NONE FOUND |
| No `.unwrap()` / `.expect()` in production paths | ✅ NONE FOUND |
| No `println!` / `dbg!` in production paths | ✅ NONE FOUND |
| `ort` features: `download-binaries`, `ndarray`, `webgpu` | ✅ VERIFIED |
| All public items have doc comments | ✅ VERIFIED (22 public items checked) |

## Code Review Findings

### Matches Plan

- All 10 source files in `heimdall-privacy-filter` match plan specs
- All 6 command module files in `heimdall-sandbox` match plan specs
- Integration test file covers all 7 planned test cases + 3 extra
- Workspace Cargo.toml updated with all required workspace deps
- Error handling follows codebase pattern: single Error enum, single Result alias at crate root
- CLI command modules follow existing clap derive patterns
- `PrivacyFilterConfig::enabled()` → CPU default, q4 variant ✅
- `redact_text` accepts `&mut PrivacyFilterRuntime` + `&str` ✅
- `CapturedTextRedaction` has `raw_for_user` + `redacted_for_llm` fields ✅

### Deviations from Plan (All Benign)

| # | Location | Deviation | Severity |
|---|---|---|---|
| 1 | `Cargo.toml` (workspace) | `tokenizers` adds `features = ["onig", "esaxx_fast"]` for regex backend | Benign — needed for model |
| 2 | `input.rs` | Adds `From<ndarray::ShapeError> for Error` | Benign — proper error handling |
| 3 | `output.rs` | Adds `is_empty()` to `PrivacyLabels` | Benign — clippy requirement |
| 4 | `session.rs` | Uses `onnx_error()` helper instead of `From<ort::Error>` + `?` | Benign — different conversion strategy |
| 5 | `setup.rs` + `privacy_filter.rs` | `CliPrivacyVariant` duplicated in both files | Low — minor duplication |
| 6 | `tests/privacy_filter.rs` | 10 tests instead of 7 in plan | Positive — extra coverage |

### Potential Issues

| # | Location | Issue | Severity |
|---|---|---|---|
| 1 | `lib.rs:67` | `From<ort::Error> for Error` is dead code — `session.rs` uses its own `onnx_error()` helper | Low — cleanup |
| 2 | `session.rs:run()` | Only fetches output named "logits"; `validate_schema()` accepts single unnamed outputs too. Inconsistency won't affect OpenAI model but could confuse future variants | Low |

## Manual Testing Required

1. **CLI help output**:
   - [ ] `heimdall-sandbox setup --help` shows `--force`, `--cache-dir`, `--variant`, `--revision`
   - [ ] `heimdall-sandbox privacy-filter redact --help` shows `--text`, `--stdin`, `--cache-dir`, `--variant`, `--revision`, `--execution-provider`

2. **Functional verification** (requires model download):
   - [ ] `heimdall-sandbox setup` downloads q4 model to HF cache
   - [ ] `heimdall-sandbox privacy-filter redact --text 'email alice@example.com'` → `email [REDACTED:EMAIL]`
   - [ ] `printf 'email alice@example.com' | heimdall-sandbox privacy-filter redact --stdin` → `email [REDACTED:EMAIL]`

3. **Regression verification**:
   - [ ] `heimdall-sandbox exec --cwd . -- printf hello` works unchanged
   - [ ] `heimdall-sandbox policy schema` works unchanged

## Recommendations

1. **Remove dead code**: `From<ort::Error> for Error` in `lib.rs` is unused since `session.rs` uses `onnx_error()`. Either use the trait impl consistently or remove it.
2. **Consider deduplicating `CliPrivacyVariant` / `CliExecutionProvider`** into a shared CLI types module if more commands use them.
3. **Align `run()` with `validate_schema()`**: If `validate_schema` accepts single unnamed outputs, `run()` should also handle that case for consistency.

## Validation Checklist

- [x] All phases marked complete are actually done
- [x] Automated tests pass (105/105)
- [x] Code follows existing patterns (error handling, clap derive, crate structure)
- [x] No regressions introduced (all existing tests pass)
- [x] Error handling is robust (no unwrap/expect in production)
- [x] No debug `println!` or `dbg!` statements
- [x] No `#[allow(...)]` or `#[ignore]`
- [x] All public items have doc comments
- [x] No hardcoded credentials
- [x] Dependency check: no undocumented horizontal deps

---

**Status**: ✅ **COMPLETE** — Implementation matches plan. Two low-severity cleanups identified (dead code, minor duplication) but no blockers.

💬 **Next step**: `/skill:commit` — the implementation is already committed at `d9d522e`. For the two low-severity findings, fix in-place and re-validate, or accept as-is.
