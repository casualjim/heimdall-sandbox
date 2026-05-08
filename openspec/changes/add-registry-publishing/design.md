## Context

Heimdall currently uses cargo-dist for release artifact generation, GitHub release hosting, shell installers, GitHub attestations, and Homebrew publishing. The generated `.github/workflows/release.yml` is owned by cargo-dist and should be regenerated from `dist-workspace.toml` rather than edited directly.

The README already advertises `cargo install heimdall-sandbox`, but the workspace release metadata disables Cargo publishing and the release-cut workflow runs `cargo release` with `--no-publish`. The workspace crates also use internal workspace path dependencies that must be publishable on crates.io before the top-level CLI crate can be installed from the registry.

The npm package should be `@casualjim/heimdall-sandbox`. The desired npm model is registry-hosted platform packages, not an install-time GitHub download. cargo-dist's built-in npm installer publishes an npm package that fetches hosted archives during install, so this change uses cargo-dist orchestration and generated workflow integration while providing a custom cargo-dist publish job for npm packages that fully embed the binaries.

## Goals / Non-Goals

**Goals:**

- Make `cargo install heimdall-sandbox` work by publishing all required crates to crates.io.
- Make `npm install -g @casualjim/heimdall-sandbox` work without depending on GitHub release asset availability during installation.
- Keep cargo-dist as the owner of release workflow generation; do not manually maintain generated release workflow edits.
- Publish npm packages using trusted publishing and provenance instead of `NPM_TOKEN`.
- Preserve current release targets: Linux x64, Linux arm64, and Apple Silicon macOS.

**Non-Goals:**

- Add unsupported npm packages for Intel macOS, Windows, or musl Linux before cargo-dist builds those targets.
- Replace existing GitHub release, shell installer, Homebrew, or attestation behavior.
- Move release versioning away from the workspace version in `workspace.package.version`.
- Store or inspect registry secrets during implementation.

## Decisions

### Use cargo-dist orchestration, not hand-maintained release workflow edits

Release workflow changes should be expressed through cargo-dist configuration and custom cargo-dist jobs. After changing `dist-workspace.toml` or job files, regenerate or check the generated workflow with cargo-dist.

Alternative considered: directly edit `.github/workflows/release.yml`. This is rejected because the file is generated and future `dist generate` runs would overwrite or diverge from manual edits.

### Use a custom cargo-dist npm publish job for registry-hosted platform packages

The npm install path should use a main package plus platform optional dependency packages:

- `@casualjim/heimdall-sandbox`
- `@casualjim/heimdall-sandbox-linux-x64`
- `@casualjim/heimdall-sandbox-linux-arm64`
- `@casualjim/heimdall-sandbox-darwin-arm64`

Target mapping:

| Cargo target | npm platform package |
| --- | --- |
| `x86_64-unknown-linux-gnu` | `@casualjim/heimdall-sandbox-linux-x64` |
| `aarch64-unknown-linux-gnu` | `@casualjim/heimdall-sandbox-linux-arm64` |
| `aarch64-apple-darwin` | `@casualjim/heimdall-sandbox-darwin-arm64` |

The custom publish job should consume cargo-dist build artifacts after the host/build phases, create npm package directories, copy the matching binary into each platform package, pack/smoke-test the packages, publish platform packages first, and publish the main package last.

Alternative considered: cargo-dist's built-in `installers = ["npm"]` / `publish-jobs = ["npm"]` path. This is rejected for this change because that installer fetches hosted release archives during npm install, which reintroduces the GitHub availability risk this change is intended to avoid.

### Publish npm through trusted publishing

The npm publish job should use GitHub OIDC/trusted publishing with provenance. It should not read `NPM_TOKEN` or require an npm token secret. The generated release workflow/job permissions must include `id-token: write` for the npm publish job and enough read access to download artifacts.

Each npm package name must be configured on npmjs.com for the trusted publisher workflow before the first release that publishes it.

Alternative considered: token-based npm publishing like `breeze-tree-sitter-parsers`. This is rejected for Heimdall because trusted publishing removes token rotation and secret exposure concerns.

### Publish crates.io packages separately from cargo-dist binary publishing

Cargo-dist publishes binary distributions and installers; crates.io publication remains a Cargo/cargo-release responsibility. The release automation should publish crates in dependency order using `CARGO_REGISTRY_TOKEN` after versioning is complete and before the release is considered fully published.

Crate publish order:

1. `heimdall-process-hardening`
2. `heimdall-sandbox-policy`
3. `heimdall-linux-sandbox`
4. `heimdall-macos-sandbox`
5. `heimdall-core`
6. `heimdall-sandbox`

Internal workspace dependencies should include registry versions alongside path dependencies so the workspace remains ergonomic locally and crates.io receives resolvable dependencies.

Alternative considered: publish only `heimdall-sandbox`. This is rejected because crates.io cannot resolve unpublished internal path-only dependencies.

### Keep the workspace version as the single release version

The release-cut workflow should continue to compute and apply the next version through `workspace.package.version`. npm package versions and crates.io package versions should match that workspace version for a given release tag.

Alternative considered: maintain independent npm and Cargo versions. This is rejected because it creates avoidable release coordination and documentation ambiguity for a single CLI product.

## Risks / Trade-offs

- npm trusted publisher setup is missing or misconfigured → the npm publish job fails visibly; configure all package names on npm before enabling release publishing.
- Cargo token is missing or under-scoped → crates.io publishing fails visibly; do not silently skip the Cargo publish lane.
- Main npm package publishes before platform packages → installs may resolve missing optional dependencies; publish platform packages first and main last.
- cargo-dist target list and npm package list diverge → unsupported installs or missing packages; derive package creation from the current target mapping and validate with cargo-dist planning output.
- Partially published crates.io package set → retrying may encounter already-published versions; publish scripts should detect already-published versions and skip them while failing on real mismatches.
- Custom npm publish job increases release complexity → keep it as a cargo-dist custom publish job so release sequencing stays in generated cargo-dist workflow structure.

## Migration Plan

1. Update package metadata so all crates needed by `heimdall-sandbox` are publishable on crates.io.
2. Update internal workspace dependencies to include matching version requirements for crates.io publication.
3. Add crates.io publish automation using `CARGO_REGISTRY_TOKEN`, dependency-order publishing, and already-published detection.
4. Add npm package templates or generation scripts for the main package and platform packages.
5. Add a cargo-dist custom publish job for npm package assembly and trusted publishing.
6. Update `dist-workspace.toml` to register the npm custom publish job while preserving Homebrew publishing.
7. Regenerate/check cargo-dist generated workflow output.
8. Validate release planning, npm packing, and Cargo packaging before enabling the next release.

Rollback strategy: disable the new Cargo/npm publish jobs in cargo-dist/release configuration while leaving existing GitHub release and Homebrew publishing intact. Already-published registry versions cannot be unpublished as a rollback mechanism; fixes should publish a newer version.

## Resolved Implementation Notes

- crates.io metadata should use the release repository URL, `https://github.com/casualjim/heimdall-sandbox`, so registry metadata matches the README and release artifact locations.
- Registry publishing should run from the tag-triggered release workflow after cargo-dist has built the release artifacts. The Cargo lane remains implemented with Cargo/cargo-release commands, but it may be wired into cargo-dist's generated workflow through a custom publish job so the generated workflow remains the orchestration boundary.
- Registry publish scripts should be retry-tolerant: if a package version is already present with the expected version, skip it; if the registry state differs from the release version, fail visibly.
