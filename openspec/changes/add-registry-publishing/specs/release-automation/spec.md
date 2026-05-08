## ADDED Requirements

### Requirement: crates.io publishing
The release automation SHALL publish every workspace crate required for `cargo install heimdall-sandbox` to crates.io for each stable release version.

#### Scenario: Release publishes required Cargo crates
- **WHEN** a stable `vX.Y.Z` release is published
- **THEN** the release automation publishes `heimdall-process-hardening` version `X.Y.Z` to crates.io
- **AND** it publishes `heimdall-sandbox-policy` version `X.Y.Z` to crates.io
- **AND** it publishes `heimdall-linux-sandbox` version `X.Y.Z` to crates.io
- **AND** it publishes `heimdall-macos-sandbox` version `X.Y.Z` to crates.io
- **AND** it publishes `heimdall-core` version `X.Y.Z` to crates.io
- **AND** it publishes `heimdall-sandbox` version `X.Y.Z` to crates.io

#### Scenario: Cargo install resolves release version
- **WHEN** crates.io publishing succeeds for release version `X.Y.Z`
- **THEN** `cargo install heimdall-sandbox --version X.Y.Z` can resolve all required Heimdall crates from crates.io

#### Scenario: Missing Cargo token fails visibly
- **WHEN** the Cargo registry token secret is unavailable or under-scoped during crates.io publishing
- **THEN** the crates.io publishing job fails visibly
- **AND** it does not report registry publication as successful

### Requirement: npm trusted publishing
The release automation SHALL publish npm packages for `@casualjim/heimdall-sandbox` using trusted publishing and provenance without an npm token secret.

#### Scenario: Release publishes npm packages through trusted publishing
- **WHEN** a stable `vX.Y.Z` release is published
- **THEN** the release automation publishes `@casualjim/heimdall-sandbox-linux-x64` version `X.Y.Z` to npm
- **AND** it publishes `@casualjim/heimdall-sandbox-linux-arm64` version `X.Y.Z` to npm
- **AND** it publishes `@casualjim/heimdall-sandbox-darwin-arm64` version `X.Y.Z` to npm
- **AND** it publishes `@casualjim/heimdall-sandbox` version `X.Y.Z` to npm
- **AND** every npm publish operation uses provenance
- **AND** no npm publish operation requires `NPM_TOKEN`

#### Scenario: npm package names match supported targets
- **WHEN** the npm publishing job prepares packages for release version `X.Y.Z`
- **THEN** `x86_64-unknown-linux-gnu` maps to `@casualjim/heimdall-sandbox-linux-x64`
- **AND** `aarch64-unknown-linux-gnu` maps to `@casualjim/heimdall-sandbox-linux-arm64`
- **AND** `aarch64-apple-darwin` maps to `@casualjim/heimdall-sandbox-darwin-arm64`
- **AND** it does not publish npm platform packages for unsupported cargo-dist targets

#### Scenario: Trusted publisher setup failure is visible
- **WHEN** npm trusted publishing is not configured for a package being published
- **THEN** the npm publishing job fails visibly
- **AND** it does not fall back to token-based npm authentication

### Requirement: npm registry-hosted CLI installation
The npm packages SHALL install the Heimdall CLI from npm registry package contents instead of downloading release assets from GitHub during package installation.

#### Scenario: Main npm package exposes CLI command
- **WHEN** a user installs `@casualjim/heimdall-sandbox` globally with npm on a supported platform
- **THEN** npm exposes a `heimdall-sandbox` executable command
- **AND** that command executes the platform binary supplied by the matching optional platform package

#### Scenario: npm install does not require GitHub release access
- **WHEN** a user installs `@casualjim/heimdall-sandbox` on a supported platform
- **THEN** package installation does not download Heimdall binaries from GitHub release assets
- **AND** installation succeeds using npm registry package contents for the matching platform package

#### Scenario: Missing platform package fails loudly
- **WHEN** a user installs `@casualjim/heimdall-sandbox` on a supported platform but the matching optional platform package is unavailable
- **THEN** running `heimdall-sandbox` fails with an actionable error identifying the missing platform package
- **AND** it does not silently download a binary from GitHub as a fallback

### Requirement: cargo-dist registry publishing integration
The release automation SHALL integrate registry publishing through cargo-dist configuration or cargo-dist custom jobs rather than manual edits to generated release workflow output.

#### Scenario: Generated release workflow includes registry publishing
- **WHEN** cargo-dist release workflow generation runs after registry publishing is configured
- **THEN** the generated release workflow includes the npm registry publishing job in the cargo-dist publish phase
- **AND** existing GitHub release, shell installer, Homebrew, and attestation behavior remains configured

#### Scenario: Generated workflow stays up to date
- **WHEN** maintainers validate release automation changes
- **THEN** cargo-dist generation or checking confirms the generated release workflow matches the checked-in release configuration

### Requirement: Registry publish validation
The repository SHALL provide validation steps that prove Cargo and npm registry package preparation before release publishing is considered ready.

#### Scenario: Cargo packaging validates
- **WHEN** maintainers validate registry publishing changes
- **THEN** Cargo packaging validation confirms each publishable Heimdall crate has required crates.io metadata
- **AND** internal Heimdall dependencies include registry versions resolvable by crates.io

#### Scenario: npm packaging validates
- **WHEN** maintainers validate registry publishing changes
- **THEN** npm package validation packs the main package and every supported platform package
- **AND** validation confirms the main package references the supported platform packages at the release version
- **AND** validation confirms each platform package contains the matching Heimdall binary
