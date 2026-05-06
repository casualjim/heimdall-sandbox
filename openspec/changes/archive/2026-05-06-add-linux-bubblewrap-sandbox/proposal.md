## Why

The Phase 1 runtime can harden process execution and filter environment variables, but it still executes commands directly against the host filesystem. Linux needs the planned OS-level filesystem and network isolation so agent commands can operate in a readonly-by-default project view with explicit writable grants and concrete secret masks.

## What Changes

- Add a Linux bubblewrap execution path for `heimdall-sandbox exec` that builds a restricted namespace before running the requested command.
- Introduce `crates/heimdall-linux-sandbox` as the Linux-specific planning/materialization crate so `heimdall-core` keeps reusable runtime orchestration while delegating bubblewrap argv construction and filesystem policy expansion.
- Require Codex-compatible Linux bubblewrap lifecycle behavior: user/process namespace isolation, `--argv0` compatibility probing, process-group signal forwarding for `SIGHUP`/`SIGINT`/`SIGQUIT`/`SIGTERM`, setup signal masking/replay, and `PR_SET_PDEATHSIG`.
- Parse JSON filesystem policy from `filesystem: { deny, writable, virtual }` and produce a JSON Schema for accepted policy documents.
- Interpret `filesystem.deny` and `filesystem.writable` as ordered gitignore-style pattern streams using the `ignore` crate.
- Merge optional cwd-relative `.heimdall-deny` and `.heimdall-write` files after the JSON pattern lists so later project fragments can refine earlier rules.
- Materialize deny pattern matches into concrete bubblewrap masks because bubblewrap accepts paths, not glob patterns.
- Mount the project readable by default and writable only where the writable matcher grants access; deny masks take precedence over writable grants.
- Support readonly virtual files from `filesystem.virtual` via bubblewrap data binds, including synthetic `/etc/passwd` and `/etc/group` supplied by policy or platform defaults.
- Expose only selected real readonly `/etc` support files for DNS/TLS and avoid binding the full host `/etc` directory.
- Support `/proc` mounting with preflight fallback and explicit no-proc execution mode for container compatibility.
- Support Linux network isolation for `network: "none"` by using bubblewrap network namespace isolation.
- Preserve Phase 1 environment filtering, process hardening, stdio behavior, signal forwarding, and exit status propagation.

## Capabilities

### New Capabilities
- `linux-bubblewrap-sandbox`: Linux namespace execution using bubblewrap, readonly-by-default filesystem mounts, ignore-pattern deny/write policy, virtual files, optional `.heimdall-*` fragments, and network isolation.

### Modified Capabilities
- `sandbox-core-runtime`: JSON policy supports `filesystem.deny`, `filesystem.writable`, `filesystem.virtual`, Linux `network: "none"`, and filesystem isolation.

## Impact

- Affects `crates/heimdall-core` request types, Linux execution dispatch, and error mapping.
- Adds `crates/heimdall-linux-sandbox` for Linux bubblewrap argument construction, launcher compatibility probing, selected runtime mounts, virtual file data binds, and path-pattern materialization.
- Affects `crates/heimdall-sandbox` JSON policy parsing, validation, and schema generation.
- Adds the `ignore` crate dependency for gitignore-style matching and the `schemars` crate dependency for JSON Schema generation.
- Adds Linux-focused integration tests that require usable bubblewrap, while preserving existing direct execution behavior on unsupported platforms.
