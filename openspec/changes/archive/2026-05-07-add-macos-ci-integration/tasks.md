## 1. CI Workflow

- [x] 1.1 Update `.github/workflows/ci.yml` to keep the existing Linux CI job and add a separate macOS CI job on a GitHub-hosted macOS runner.
- [x] 1.2 Configure the macOS CI job to check out the repository, install the mise toolchain with caching, install Rust `rustfmt` and `clippy`, run `mise format`, and run `mise run --force test`.
- [x] 1.3 Confirm macOS Seatbelt integration tests run through the normal test command when `/usr/bin/sandbox-exec` is available, without adding new ignore flags, feature gates, or CI-specific skips.

## 2. Release Artifact Configuration

- [x] 2.1 Inspect current cargo-dist configuration and generated release workflow to identify the existing Linux artifact targets.
- [x] 2.2 Update cargo-dist configuration so release planning includes `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, and `aarch64-apple-darwin`, while continuing to exclude Windows and `x86_64-apple-darwin` artifacts.
- [x] 2.3 Regenerate or update cargo-dist generated workflow files using the cargo-dist-supported process if target configuration changes require workflow updates.
- [x] 2.4 Confirm the release workflow still creates a GitHub Release and uploads generated Linux and Apple Silicon macOS artifacts.
- [x] 2.5 Confirm Homebrew publishing remains after release hosting and does not add secret preflight checks or silent skips.

## 3. Spec and Documentation Sync

- [x] 3.1 Ensure `openspec/specs/release-automation/spec.md` is updated from this change's delta spec during archive/sync.
- [x] 3.2 Update any release or CI documentation that explicitly states releases are Linux-only or CI is Linux-only, if such documentation exists outside the spec.

## 4. Validation

- [x] 4.1 Run `mise format` and confirm it is clean with no warnings or formatting changes.
- [x] 4.2 Run `mise run --force test` and confirm all tests pass cleanly.
- [x] 4.3 Run cargo-dist release planning and confirm the output includes `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, and `aarch64-apple-darwin`, and does not include `x86_64-apple-darwin`.
- [x] 4.4 Confirm `openspec validate --specs --strict` passes after spec updates.
