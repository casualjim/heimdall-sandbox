## ADDED Requirements

### Requirement: GitHub CI validation
The repository SHALL run GitHub Actions CI for pull requests, pushes to `main`, and manual dispatch using the project mise tasks as the validation boundary.

#### Scenario: Pull request validation runs
- **WHEN** a pull request targets the repository
- **THEN** GitHub Actions runs CI on a Linux runner
- **AND** CI executes the project formatting/linting task through `mise format`
- **AND** CI executes the full Rust test task through `mise run --force test`

#### Scenario: Main branch validation runs
- **WHEN** commits are pushed to `main`
- **THEN** GitHub Actions runs the same Linux CI validation used for pull requests

#### Scenario: Manual validation runs
- **WHEN** a maintainer dispatches the CI workflow manually
- **THEN** GitHub Actions runs the same Linux CI validation used for pull requests

### Requirement: Automated release cutting
The repository SHALL provide a release-cut workflow that creates a release commit and `vX.Y.Z` tag after successful CI on `main` or manual dispatch.

#### Scenario: Successful main CI cuts release
- **WHEN** the CI workflow completes successfully for `main`
- **THEN** the release-cut workflow computes the next version from the merged PR or commit text
- **AND** the workflow updates release metadata and changelog files
- **AND** the workflow creates a release commit
- **AND** the workflow pushes a `vX.Y.Z` tag

#### Scenario: Failed CI does not cut release
- **WHEN** the CI workflow does not complete successfully for `main`
- **THEN** the release-cut workflow does not create a release commit or tag

#### Scenario: Bot-triggered release commit does not loop
- **WHEN** the GitHub Actions bot creates or pushes the release commit
- **THEN** the release-cut workflow does not recursively create another release

#### Scenario: Manual release cut is available
- **WHEN** a maintainer dispatches the release-cut workflow manually
- **THEN** the workflow performs the same version computation, changelog update, release commit, and tag push steps as an automatic release cut

### Requirement: Workspace version bumping
The release-cut workflow SHALL version the Heimdall workspace in lockstep through `workspace.package.version`.

#### Scenario: Workspace version is incremented
- **WHEN** the release-cut workflow computes a next version
- **THEN** it reads the current version from root `Cargo.toml` at `workspace.package.version`
- **AND** it passes the computed version to `cargo-release`
- **AND** all workspace crates that inherit the workspace version are released with the same version

#### Scenario: Major bump token wins
- **WHEN** release source text contains `bump:major`
- **THEN** the next version increments the major component and resets minor and patch to zero

#### Scenario: Minor bump token wins over patch
- **WHEN** release source text contains `bump:minor` and does not contain `bump:major`
- **THEN** the next version increments the minor component and resets patch to zero

#### Scenario: Patch bump is default
- **WHEN** release source text contains no bump token
- **THEN** the next version increments the patch component

### Requirement: Conventional changelog generation
The repository SHALL generate `CHANGELOG.md` from Conventional Commits using `git-cliff` during release cutting.

#### Scenario: Changelog is regenerated for release tag
- **WHEN** a release-cut workflow computes next version `X.Y.Z`
- **THEN** it runs `git-cliff` for tag `vX.Y.Z`
- **AND** it writes the generated changelog to `CHANGELOG.md`

#### Scenario: Commit guidance requires Conventional Commits
- **WHEN** contributors or agents read repository guidance
- **THEN** `AGENTS.md` requires Conventional Commits for commit messages
- **AND** the guidance includes valid examples using commit types such as `feat`, `fix`, `ci`, and `chore`

### Requirement: Linux-only GitHub release artifacts
The repository SHALL publish Linux-only release artifacts through cargo-dist when a release tag is pushed.

#### Scenario: Release tag builds Linux artifacts
- **WHEN** a `vX.Y.Z` tag is pushed
- **THEN** the release workflow runs cargo-dist planning and build steps
- **AND** it builds artifacts for `x86_64-unknown-linux-gnu`
- **AND** it builds artifacts for `aarch64-unknown-linux-gnu`

#### Scenario: Non-Linux artifacts are not published
- **WHEN** a `vX.Y.Z` tag is pushed
- **THEN** the release workflow does not build or publish macOS artifacts
- **AND** it does not build or publish Windows artifacts

#### Scenario: GitHub release is created
- **WHEN** cargo-dist builds release artifacts successfully for a release tag
- **THEN** the release workflow creates a GitHub Release for that tag
- **AND** uploads the generated artifacts and installers to the GitHub Release

### Requirement: Homebrew publishing
The repository SHALL publish Homebrew formula updates to `casualjim/homebrew-taps` after successful cargo-dist release hosting.

#### Scenario: Homebrew formula is pushed
- **WHEN** a non-prerelease GitHub release is created successfully
- **THEN** the release workflow checks out `casualjim/homebrew-taps`
- **AND** it commits the generated formula file
- **AND** it pushes the formula update using `HOMEBREW_TAP_TOKEN`

#### Scenario: Missing Homebrew token fails publishing visibly
- **WHEN** `HOMEBREW_TAP_TOKEN` is unavailable or under-scoped
- **THEN** the Homebrew publishing job fails visibly instead of silently skipping formula publication

### Requirement: Required release secrets
The release workflows SHALL use explicit repository secrets for privileged publishing operations.

#### Scenario: Release tag uses release token
- **WHEN** the release-cut workflow pushes the `vX.Y.Z` tag
- **THEN** it uses `RELEASE_TOKEN` for the tag push so the tag-triggered release workflow can run

#### Scenario: GitHub token handles release hosting
- **WHEN** the release workflow creates the GitHub Release
- **THEN** it uses the workflow `GITHUB_TOKEN` permissions required for release hosting and artifact upload
