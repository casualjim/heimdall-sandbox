## Why

Heimdall needs a native Phase 1 sandbox runtime before platform-specific Linux and macOS jail/container isolation can be implemented. This first deliverable provides the minimal hardened sandbox runtime: explicit environment isolation, process hardening, direct argv execution, signal behavior, and exit status mapping. The Rust code should be structured as reusable core logic plus a thin CLI, because the JavaScript integration will call the binary now and native bindings may be added later.

## What Changes

- Convert the repository into a Cargo workspace.
- Add a reusable `heimdall-core` library crate for minimal sandbox runtime behavior: request types, environment filtering, process hardening, command execution, signal behavior, and exit status mapping.
- Add a thin `heimdall-sandbox` binary crate that parses command-line arguments and delegates to `heimdall-core`.
- Keep the CLI args-only: no TOML, JSON, or other config file loading in the CLI.
- Add cross-platform process hardening hooks for Linux and macOS.
- Add explicit argument-driven environment variable allowlisting before command execution.
- Add command execution plumbing that inherits stdout/stderr directly, forwards termination signals, and returns the child command's exit status.
- Add structured error/exit handling for sandbox misconfiguration and child exit status propagation.

## Capabilities

### New Capabilities

- `sandbox-core-runtime`: Workspace-based minimal sandbox runtime and args-only CLI behavior, including reusable core APIs, CLI invocation, environment filtering, process hardening, signal handling, stdio inheritance, and exit code propagation.

### Modified Capabilities

None.

## Impact

- Replaces the single-crate layout with a Cargo workspace containing `crates/heimdall-core` and `crates/heimdall-sandbox`.
- Introduces core library modules for environment filtering, hardening, execution, and runtime errors.
- Introduces CLI parsing in the binary crate only.
- Adds dependencies for CLI parsing, error handling, platform-specific libc calls, and signal handling.
- Delivers the Phase 1 minimal hardened sandbox runtime used by future Linux bwrap and macOS Seatbelt jail/container implementations and possible future native bindings.
