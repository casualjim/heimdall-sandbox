## Why

Heimdall needs repository CI before the next development batch moves to macOS, so pushes and pull requests can validate the Linux-only sandbox on GitHub-hosted Linux runners. The project also needs the same release automation pattern used by sibling CLI repos (`zage`, `umber`, and `remark`) so tagged releases produce GitHub artifacts and Homebrew publishing without manual packaging.

## What Changes

- Add GitHub Actions CI for pull requests, pushes to `main`, and manual dispatch.
- Add an automated release-cut workflow triggered by successful CI on `main` and by manual dispatch.
- Use `bump:major`, `bump:minor`, and `bump:patch` tokens from the merged PR or commit message to determine the next version, defaulting to patch.
- Adapt release cutting to Heimdall's workspace-level version in `workspace.package.version`.
- Generate a conventional-commit changelog with `git-cliff`.
- Use `cargo-release` to update the workspace version, commit the release, and tag `vX.Y.Z` without publishing crates to crates.io.
- Add a cargo-dist GitHub release workflow for Linux-only release artifacts.
- Publish Homebrew formula updates to `casualjim/homebrew-taps` after successful releases.
- Align repository agent guidance with Conventional Commits.

## Capabilities

### New Capabilities
- `release-automation`: CI, release cutting, GitHub release artifact generation, and Homebrew publishing for the Linux-only Heimdall CLI.

### Modified Capabilities

## Impact

- Adds `.github/workflows/ci.yml`, `.github/workflows/release-cut.yml`, and `.github/workflows/release.yml`.
- Adds cargo-dist configuration, git-cliff configuration, and changelog files.
- Updates Cargo workspace release metadata so releases are versioned in lockstep and are not published to crates.io.
- Requires repository secrets matching sibling repos: `RELEASE_TOKEN` for tag pushes and `HOMEBREW_TAP_TOKEN` for Homebrew tap publishing.
- Keeps release targets Linux-only for now: `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`.
- Updates `AGENTS.md` commit-message guidance to require Conventional Commits.
