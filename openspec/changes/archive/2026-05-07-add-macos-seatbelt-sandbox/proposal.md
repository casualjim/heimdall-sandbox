## Why

Phase 2 added real Linux filesystem and network isolation, but macOS still rejects isolation requests even though the runtime already accepts shared sandbox policy documents. Phase 3 completes the planned macOS path by executing isolated commands through Seatbelt so the same deny/writable/network/env/stdio configuration can be used on Linux and macOS.

## What Changes

- Add macOS Seatbelt execution for requests that need filesystem or network isolation.
- Invoke only `/usr/bin/sandbox-exec`, never a PATH-discovered executable.
- Generate a deny-default SBPL policy from the existing shared JSON policy shape.
- Preserve Linux-compatible cwd-relative gitignore semantics for `filesystem.deny` and `filesystem.writable`, including fragment merge order and deny-over-writable precedence.
- Preserve shared `env`, `stdio`, `network`, and `proc` policy parsing; `proc` remains accepted on macOS for config compatibility but has no Seatbelt effect.
- Accept `filesystem.virtual` on macOS for shared config compatibility, ignore supplied contents because Seatbelt cannot overlay files, and treat the target paths as readonly/write-denied compatibility paths.
- Keep protected workspace control paths readonly under broad writable grants.
- Fail closed when Seatbelt setup or invocation fails; never fall back to unsandboxed execution after isolation was requested.

## Capabilities

### New Capabilities
- `macos-seatbelt-sandbox`: macOS Seatbelt execution, SBPL filesystem policy generation, network policy generation, protected path handling, and Seatbelt invocation behavior.

### Modified Capabilities
- `sandbox-core-runtime`: Isolation requests are no longer Linux-only; shared policy fields route to macOS Seatbelt on macOS while preserving direct execution for requests that do not need isolation.

## Impact

- Affects platform dispatch in `heimdall-core` so macOS isolation routes to a Seatbelt executor instead of returning unsupported.
- Adds a macOS-specific sandbox planning crate or module for SBPL generation, canonical path handling, and `/usr/bin/sandbox-exec` command construction.
- Affects `heimdall-sandbox` policy compatibility documentation/tests for macOS `proc` and `filesystem.virtual` behavior.
- Adds macOS-focused unit and integration tests that require `/usr/bin/sandbox-exec`.
