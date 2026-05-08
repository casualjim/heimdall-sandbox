## Why

The README documents `cargo install heimdall-sandbox`, and the project intends to offer npm installation through `@casualjim/heimdall-sandbox`; those registry install paths must be backed by release automation before the documentation is truthful. The existing release automation publishes GitHub artifacts and Homebrew formulae, but it does not publish crates.io packages or npm packages.

## What Changes

- Publish the crates required for `cargo install heimdall-sandbox` to crates.io as part of release automation using a Cargo registry token secret.
- Extend cargo-dist release orchestration with npm registry publishing for `@casualjim/heimdall-sandbox` using trusted publishing and provenance instead of an npm token.
- Publish npm platform packages for the currently supported cargo-dist targets and publish the main npm package only after the platform packages are available.
- Keep npm installs independent of GitHub release asset availability by packaging platform binaries in npm optional dependency packages rather than downloading from GitHub during install.
- Preserve the existing GitHub release, shell installer, Homebrew, and cargo-dist artifact publishing paths.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `release-automation`: add registry publishing requirements for crates.io and npm packages in addition to existing GitHub release and Homebrew publishing requirements.

## Impact

- Release configuration: `dist-workspace.toml`, cargo-dist generated workflow output, and release-cut/publish workflow behavior.
- Package metadata: workspace crate metadata and dependency declarations needed for crates.io publication.
- npm packaging: package metadata for `@casualjim/heimdall-sandbox` and platform packages matching current release targets.
- Secrets and trust setup: Cargo registry token secret for crates.io and npm trusted publisher configuration for the scoped npm packages.
- Documentation: README installation instructions become backed by actual registry publishing.
