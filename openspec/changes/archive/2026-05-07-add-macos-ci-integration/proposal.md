## Why

macOS Seatbelt sandbox support now exists, but CI still validates only on Linux and release automation still specifies Linux-only cargo-dist artifacts. This leaves macOS-specific sandbox behavior and macOS release publishing unverified after each change.

## What Changes

- Add macOS GitHub Actions CI validation for pull requests, pushes to `main`, and manual workflow dispatch.
- Ensure macOS CI uses the same project validation boundary as Linux: `mise format` and `mise run --force test`.
- Update release automation to publish Apple Silicon macOS cargo-dist artifacts in addition to existing Linux artifacts.
- Validate the cargo-dist release plan so `aarch64-apple-darwin` artifacts are present before relying on tag-triggered publishing.
- No breaking changes.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `release-automation`: extend CI and release artifact requirements from Linux-only validation/publishing to include macOS validation and macOS release artifacts.

## Impact

- `.github/workflows/ci.yml` gains a macOS validation job.
- Cargo-dist release configuration and/or generated release workflow are updated so Apple Silicon macOS artifacts are planned, built, and uploaded.
- `openspec/specs/release-automation/spec.md` is updated to describe macOS CI and Apple Silicon release publishing behavior.
- Release validation may require checking cargo-dist plan output for `aarch64-apple-darwin`.
