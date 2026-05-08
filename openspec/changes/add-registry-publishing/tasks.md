## 1. Cargo package readiness

- [x] 1.1 Update workspace/package metadata so every publishable Heimdall crate has crates.io-required metadata, including description, license, repository, homepage/readme where appropriate.
- [x] 1.2 Correct crate repository/homepage metadata to point at `https://github.com/casualjim/heimdall-sandbox` where registry metadata should reference this release repository.
- [x] 1.3 Add registry version requirements to internal workspace dependencies while preserving local path dependencies for workspace development.
- [x] 1.4 Configure release/versioning metadata so internal dependency versions remain in lockstep with `workspace.package.version` during release cuts.
- [x] 1.5 Validate Cargo packaging with dry-run packaging for all crates that must publish to crates.io.

## 2. crates.io publishing automation

- [x] 2.1 Add a retry-tolerant Cargo registry publish script or workflow step that checks whether each release version is already published before attempting upload.
- [x] 2.2 Publish crates in dependency order: `heimdall-process-hardening`, `heimdall-sandbox-policy`, `heimdall-linux-sandbox`, `heimdall-macos-sandbox`, `heimdall-core`, then `heimdall-sandbox`.
- [x] 2.3 Wire Cargo registry publishing into release automation using `CARGO_REGISTRY_TOKEN` without preflighting, printing, or inspecting the secret value.
- [x] 2.4 Ensure Cargo registry publishing fails visibly when the token is missing, under-scoped, or a crate version mismatch is detected.

## 3. npm package generation

- [x] 3.1 Add npm package metadata/templates or generation scripts for the main `@casualjim/heimdall-sandbox` package.
- [x] 3.2 Add platform package metadata/templates or generation scripts for `@casualjim/heimdall-sandbox-linux-x64`, `@casualjim/heimdall-sandbox-linux-arm64`, and `@casualjim/heimdall-sandbox-darwin-arm64`.
- [x] 3.3 Implement platform package assembly that copies the cargo-dist-built binary for each supported target into the matching npm platform package.
- [x] 3.4 Implement the main package CLI shim so `heimdall-sandbox` executes the matching optional platform package binary and fails with an actionable error when missing.
- [x] 3.5 Ensure the main npm package declares optional dependencies on the platform packages at the release version.
- [x] 3.6 Validate npm package contents with `npm pack --dry-run` or equivalent for the main package and every platform package.

## 4. cargo-dist release integration

- [x] 4.1 Add cargo-dist custom publish job configuration for npm registry package assembly and publishing instead of relying on cargo-dist's built-in npm installer download model.
- [x] 4.2 Add cargo-dist custom publish job configuration for crates.io publishing, or otherwise wire the Cargo publish lane into the tag-triggered release workflow without hand-editing generated workflow output.
- [x] 4.3 Configure npm publishing job permissions for trusted publishing and provenance, including `id-token: write`, without adding `NPM_TOKEN` usage.
- [x] 4.4 Preserve existing cargo-dist GitHub release, shell installer, Homebrew, custom runner, and attestation configuration.
- [x] 4.5 Regenerate or check the cargo-dist generated release workflow so `.github/workflows/release.yml` matches `dist-workspace.toml` and custom job configuration.

## 5. Registry publishing behavior

- [x] 5.1 Publish npm platform packages before publishing the main `@casualjim/heimdall-sandbox` package.
- [x] 5.2 Ensure npm publishing skips already-published package versions only when the existing version exactly matches the release version.
- [x] 5.3 Ensure `npm publish` uses trusted publishing/provenance and fails rather than falling back to token-based authentication.
- [x] 5.4 Ensure npm installation does not download Heimdall binaries from GitHub release assets during install or first run.

## 6. Documentation and validation

- [x] 6.1 Update README installation instructions to include `npm install -g @casualjim/heimdall-sandbox` once npm publishing is backed by release automation.
- [x] 6.2 Document required external registry setup: the Cargo registry token secret and npm trusted publisher configuration for all four npm package names.
- [x] 6.3 Validate cargo-dist planning includes the existing supported targets and the registry publish jobs.
- [x] 6.4 Run `mise format`.
- [x] 6.5 Run `mise run --force test`.
