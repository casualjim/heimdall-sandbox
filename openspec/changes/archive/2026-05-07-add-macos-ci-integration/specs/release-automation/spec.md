## MODIFIED Requirements

### Requirement: GitHub CI validation
The repository SHALL run GitHub Actions CI for pull requests, pushes to `main`, and manual dispatch using the project mise tasks as the validation boundary on both Linux and macOS.

#### Scenario: Pull request validation runs
- **WHEN** a pull request targets the repository
- **THEN** GitHub Actions runs CI on a Linux runner
- **AND** GitHub Actions runs CI on a macOS runner
- **AND** each CI job executes the project formatting/linting task through `mise format`
- **AND** each CI job executes the full Rust test task through `mise run --force test`

#### Scenario: Main branch validation runs
- **WHEN** commits are pushed to `main`
- **THEN** GitHub Actions runs the same Linux and macOS CI validation used for pull requests

#### Scenario: Manual validation runs
- **WHEN** a maintainer dispatches the CI workflow manually
- **THEN** GitHub Actions runs the same Linux and macOS CI validation used for pull requests

#### Scenario: macOS Seatbelt tests run on macOS CI
- **WHEN** the macOS CI job runs on a GitHub-hosted macOS runner with `/usr/bin/sandbox-exec` available
- **THEN** macOS Seatbelt integration tests execute as part of `mise run --force test`
- **AND** failures in those tests fail the macOS CI job

### Requirement: Linux and Apple Silicon macOS GitHub release artifacts
The repository SHALL publish Linux and Apple Silicon macOS release artifacts through cargo-dist when a release tag is pushed.

#### Scenario: Release tag builds Linux artifacts
- **WHEN** a `vX.Y.Z` tag is pushed
- **THEN** the release workflow runs cargo-dist planning and build steps
- **AND** it builds artifacts for `x86_64-unknown-linux-gnu`
- **AND** it builds artifacts for `aarch64-unknown-linux-gnu`

#### Scenario: Release tag builds Apple Silicon macOS artifacts
- **WHEN** a `vX.Y.Z` tag is pushed
- **THEN** the release workflow runs cargo-dist planning and build steps
- **AND** it builds artifacts for `aarch64-apple-darwin`

#### Scenario: Unsupported desktop artifacts are not published
- **WHEN** a `vX.Y.Z` tag is pushed
- **THEN** the release workflow does not build or publish Windows artifacts
- **AND** it does not build or publish Intel macOS artifacts for `x86_64-apple-darwin`

#### Scenario: GitHub release is created
- **WHEN** cargo-dist builds release artifacts successfully for a release tag
- **THEN** the release workflow creates a GitHub Release for that tag
- **AND** uploads the generated Linux and Apple Silicon macOS artifacts and installers to the GitHub Release

### Requirement: Release plan validation
The repository SHALL provide a validation path that proves cargo-dist plans Linux and Apple Silicon macOS artifacts before release publishing is considered ready.

#### Scenario: Dist plan includes Linux targets
- **WHEN** maintainers validate release automation changes
- **THEN** cargo-dist planning output includes `x86_64-unknown-linux-gnu`
- **AND** cargo-dist planning output includes `aarch64-unknown-linux-gnu`

#### Scenario: Dist plan includes Apple Silicon macOS target
- **WHEN** maintainers validate release automation changes
- **THEN** cargo-dist planning output includes `aarch64-apple-darwin`
- **AND** cargo-dist planning output does not include `x86_64-apple-darwin`
