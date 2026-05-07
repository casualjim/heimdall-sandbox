## Context

Heimdall currently has no GitHub Actions workflows, no cargo-dist configuration, no changelog configuration, and no release automation. The workspace version lives at `workspace.package.version`, and all crates inherit that version. The runtime is intentionally Linux-only right now because sandboxing is built around Linux/bubblewrap behavior, but development may happen from macOS machines; CI needs to be the Linux validation boundary.

Sibling projects (`zage`, `umber`, and `remark`) use a two-stage release model: successful CI on `main` cuts a version/tag, and the tag triggers cargo-dist to build GitHub release artifacts plus Homebrew publishing. Heimdall should reuse that shape while adapting it to a workspace package version and Linux-only targets.

## Goals / Non-Goals

**Goals:**
- Validate pushes and pull requests on Linux through GitHub Actions.
- Use the repository's mise tasks for CI validation of formatting, linting, builds, and tests.
- Cut releases automatically after successful CI on `main`, with manual dispatch available.
- Determine SemVer bumps from Conventional Commit-adjacent bump tokens: `bump:major`, `bump:minor`, and `bump:patch`.
- Keep all Heimdall crates versioned in lockstep through `workspace.package.version`.
- Build and publish Linux-only release artifacts through cargo-dist.
- Publish Homebrew formula updates to `casualjim/homebrew-taps`.
- Keep crates unpublished to crates.io for this change.

**Non-Goals:**
- macOS or Windows release artifacts.
- crates.io publishing.
- Changing sandbox runtime behavior.
- Introducing release channels beyond stable `vX.Y.Z` tags.
- Replacing cargo-dist with a custom packaging system.

## Decisions

### Use the sibling two-workflow release model

Adopt the same separation used by `zage`, `umber`, and `remark`:

```text
CI success on main
  │
  ▼
release-cut.yml
  ├─ compute next workspace version
  ├─ update CHANGELOG.md
  ├─ cargo release --no-publish --no-push --execute
  └─ push vX.Y.Z tag
        │
        ▼
release.yml
  ├─ cargo-dist plan/build/host
  ├─ create GitHub Release
  └─ publish Homebrew formula
```

This keeps version mutation separate from artifact publishing and lets the pushed tag be the single release boundary. The alternative was a single workflow that bumps, builds, and publishes in one run; that couples mutation and artifact creation more tightly and diverges from the known sibling pattern.

### Read versions from `workspace.package.version`

The sibling release-cut scripts read `package.version`, but Heimdall has no root package. The release-cut workflow must parse `Cargo.toml` at `workspace.package.version`, compute the next SemVer version, and pass that exact version to cargo-release. Cargo-release dry-runs already show it can bump the workspace version and all inheriting crates together.

The alternative was adding a root package solely to match the sibling scripts. That would add fake package structure for CI convenience and is not worth it.

### Keep release targets Linux-only

Configure cargo-dist for:

```toml
targets = ["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"]
```

Use `ubuntu-24.04-arm` for native ARM Linux builds where available, matching `zage`'s runner choice. Do not include macOS or Windows artifacts until the runtime has an intentional non-Linux behavior story.

The alternative was publishing macOS artifacts so macOS development machines can install the CLI. That is misleading while the sandbox depends on Linux isolation semantics.

### Use mise for CI validation, but cargo-dist for generated release builds

CI should install the mise-pinned toolchain and run the project tasks, especially `mise format` and `mise run --force test`. Release publishing should use cargo-dist's generated workflow because cargo-dist owns its build matrix, artifact manifest, installer generation, GitHub release upload, and Homebrew formula generation.

The alternative was hand-writing release artifact builds with mise tasks. That would duplicate cargo-dist logic and make Homebrew publishing harder.

### Use Conventional Commits for changelog generation

Heimdall should align `AGENTS.md` with Conventional Commits and use a `git-cliff` configuration equivalent to the sibling repos. This makes changelog generation predictable and matches the requested release style.

The alternative was adapting git-cliff to plain-English commits, but that conflicts with the intended convention and sibling process.

### Avoid crates.io publishing

Configure cargo-release with `publish = false` and run release cutting with `--no-publish`. Heimdall artifacts are CLI binaries and installers published through GitHub/Homebrew for this change.

The alternative was preparing all crates for crates.io, which would require metadata, dependency, and API review unrelated to the immediate CI/release need.

## Risks / Trade-offs

- `RELEASE_TOKEN` missing or under-scoped → release commits may push but tags may not trigger the publishing workflow. Mitigation: document the required secret and use the same token pattern as sibling repos.
- `HOMEBREW_TAP_TOKEN` missing or under-scoped → GitHub releases succeed but Homebrew publishing fails. Mitigation: keep Homebrew as a separate downstream job and document the required secret.
- `ubuntu-24.04-arm` runner availability changes → ARM Linux builds may queue or fail. Mitigation: use the known sibling configuration first; if runner availability becomes a problem, switch cargo-dist to cross-build or temporarily drop ARM.
- cargo-dist generated workflow drift → manual edits to `release.yml` may be overwritten. Mitigation: treat `dist-workspace.toml` as the source of truth and regenerate release workflow from cargo-dist during implementation.
- Conventional Commit discipline is required → changelog quality depends on commit messages. Mitigation: update `AGENTS.md` now and keep `git-cliff` conventional parsing enabled.
