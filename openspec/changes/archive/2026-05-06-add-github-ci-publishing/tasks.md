## 1. Release Configuration

- [x] 1.1 Add workspace cargo-release metadata so Heimdall releases in lockstep, does not sign release commits/tags, allows `main`, and does not publish crates to crates.io.
- [x] 1.2 Add cargo-dist workspace configuration for GitHub hosting, Linux-only targets, shell and Homebrew installers, Homebrew tap publishing, and native ARM Linux runner selection.
- [x] 1.3 Add git-cliff configuration compatible with Conventional Commits and initialize `CHANGELOG.md`.
- [x] 1.4 Ensure local tool configuration includes release tooling needed for maintainers, including `cargo-dist` and `git-cliff` where not already present.
- [x] 1.5 Verify `AGENTS.md` requires Conventional Commits and gives examples aligned with the release/changelog workflow.

## 2. GitHub CI Workflow

- [x] 2.1 Add `.github/workflows/ci.yml` for pull requests, pushes to `main`, and manual dispatch.
- [x] 2.2 Configure CI to install the mise-pinned toolchain and run `mise format`.
- [x] 2.3 Configure CI to run `mise run --force test` on Linux.
- [x] 2.4 Prevent CI from relying on macOS or Windows runners while Heimdall remains Linux-only.

## 3. Release Cutting Workflow

- [x] 3.1 Add `.github/workflows/release-cut.yml` triggered by successful CI on `main` and by manual dispatch.
- [x] 3.2 Implement bump-token detection from associated pull request text or fallback commit message, with `bump:major`, `bump:minor`, `bump:patch`, and default patch behavior.
- [x] 3.3 Compute the next version from root `Cargo.toml` at `workspace.package.version`.
- [x] 3.4 Generate `CHANGELOG.md` for `vX.Y.Z` with `git-cliff` and commit changelog changes when present.
- [x] 3.5 Run `cargo release <version> --no-confirm --no-publish --no-push --execute` to update workspace release metadata and create the release commit/tag locally.
- [x] 3.6 Push the release commit with the workflow token and push the release tag with `RELEASE_TOKEN`.
- [x] 3.7 Ensure bot-triggered release commits do not recursively cut another release.

## 4. Release Publishing Workflow

- [x] 4.1 Generate or add cargo-dist `.github/workflows/release.yml` from `dist-workspace.toml`.
- [x] 4.2 Configure the workflow to build only `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` artifacts.
- [x] 4.3 Configure cargo-dist hosting to create the GitHub Release and upload generated artifacts.
- [x] 4.4 Configure Homebrew formula publishing to `casualjim/homebrew-taps` using `HOMEBREW_TAP_TOKEN`.
- [x] 4.5 Confirm no macOS or Windows artifacts are published by the release workflow.

## 5. Validation

- [x] 5.1 Run `openspec validate add-github-ci-publishing --strict`.
- [x] 5.2 Run `mise format`.
- [x] 5.3 Run `mise run --force test`.
- [x] 5.4 Review generated workflows for required secrets: `RELEASE_TOKEN` and `HOMEBREW_TAP_TOKEN`.
