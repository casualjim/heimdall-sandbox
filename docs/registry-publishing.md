# Registry publishing setup

Heimdall release automation publishes both Cargo and npm registry packages during the tag-triggered cargo-dist release workflow.

## crates.io

Configure the repository secret `CARGO_REGISTRY_TOKEN` with permission to publish these crates:

1. `heimdall-process-hardening`
2. `heimdall-sandbox-policy`
3. `heimdall-linux-sandbox`
4. `heimdall-macos-sandbox`
5. `heimdall-core`
6. `heimdall-sandbox`

The workflow passes the token directly to `cargo publish`. Missing, expired, or under-scoped tokens make the publish job fail visibly.

## npm trusted publishing

Configure trusted publishing on npmjs.com for these packages:

- `@casualjim/heimdall-sandbox-linux-x64`
- `@casualjim/heimdall-sandbox-linux-arm64`
- `@casualjim/heimdall-sandbox-darwin-arm64`
- `@casualjim/heimdall-sandbox`

Each trusted publisher entry should point at this GitHub repository and the reusable workflow `.github/workflows/publish-npm.yml`. The npm job uses GitHub OIDC with `id-token: write` and publishes with `npm publish --provenance`; no `NPM_TOKEN` is used.

Platform npm packages publish first. The main package publishes last and depends on the platform packages as optional dependencies at the same release version.

Do not remove `@casualjim/heimdall-sandbox-linux-arm64` only because privacy-filter WebGPU prebuilt binaries are unavailable for Linux arm64. Linux arm64 remains a supported sandbox/package target, but its release binary is built without WebGPU and must not package `libwebgpu_dawn.so`. The limitation is specifically the upstream ONNX Runtime/Dawn WebGPU native artifact availability for privacy-filter acceleration.

## Local validation

Use `scripts/validate-cargo-packages.sh` to validate package file selection and required Cargo metadata for every publishable crate before a first registry release. Full `cargo publish --dry-run` can only verify dependent Heimdall crates after their internal dependencies already exist in the crates.io index; the release publish script handles first-release ordering and waits for each dependency version to become visible before publishing the next crate.

Use `node scripts/prepare-npm-packages.ts --dry-run-placeholders --pack-dry-run` to validate npm metadata, optional dependency wiring, CLI shim packaging, and platform package file layout without cargo-dist release artifacts. The npm package assembly script uses Node 24's built-in TypeScript support and has no third-party dependencies.
