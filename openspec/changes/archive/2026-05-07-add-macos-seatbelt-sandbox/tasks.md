## 1. Shared Policy Model

- [x] 1.1 Move shared sandbox policy types (`FilesystemPolicy`, `NetworkMode`, `ProcMode`) and filesystem policy validation out of the Linux-specific implementation into a platform-neutral shared location.
- [x] 1.2 Update `heimdall-core`, `heimdall-sandbox`, and `heimdall-linux-sandbox` imports to use the platform-neutral policy model without changing the accepted JSON policy shape.
- [x] 1.3 Keep Linux bubblewrap behavior and tests passing after the shared policy extraction.

## 2. Seatbelt Policy Planning

- [x] 2.1 Add macOS Seatbelt planning code behind `#[cfg(target_os = "macos")]` that builds a `/usr/bin/sandbox-exec` command without PATH lookup.
- [x] 2.2 Add Codex-aligned SBPL sections for deny-default base behavior, process fork/exec, selected sysctls, PTY support, system runtime reads, and restricted platform defaults.
- [x] 2.3 Implement macOS path normalization and canonical alias handling for Seatbelt parameters and deny/write carveouts.
- [x] 2.4 Compile cwd-relative `filesystem.deny` and `filesystem.writable` matchers from JSON patterns followed by cwd-local `.heimdall-deny` and `.heimdall-write` fragments.
- [x] 2.5 Generate readonly project access, writable grants, deny rules, and deny-over-writable precedence in SBPL.
- [x] 2.6 Protect `.git`, `.agents`, `.pi`, `.heimdall-deny`, `.heimdall-write`, and arbitrary `.heimdall-*` paths under broad writable grants.
- [x] 2.7 Accept `filesystem.virtual` on macOS, ignore supplied contents, and generate readonly/write-deny protection for requested and canonical virtual target paths.
- [x] 2.8 Generate Seatbelt network policy for `network: "host"` and `network: "none"`, including DNS/TLS support rules only when host networking is enabled.
- [x] 2.9 Accept `proc` mode in macOS planning as a no-op compatibility field.

## 3. Core Execution Integration

- [x] 3.1 Route macOS requests that need filesystem or network isolation through the Seatbelt executor while preserving direct execution for requests that do not need isolation.
- [x] 3.2 Preserve Phase 1 child environment filtering and dangerous macOS environment stripping for commands executed through Seatbelt.
- [x] 3.3 Preserve inherited and piped stdio behavior through the Seatbelt execution path.
- [x] 3.4 Preserve signal forwarding and child exit status propagation through the Seatbelt execution path.
- [x] 3.5 Map Seatbelt policy preparation, spawn, and setup failures to sandbox misconfiguration without falling back to unsandboxed execution.

## 4. Unit Tests

- [x] 4.1 Add tests for fixed `/usr/bin/sandbox-exec` invocation and absence of PATH lookup.
- [x] 4.2 Add tests for generated SBPL base sections and platform default inclusion needed for standard macOS commands.
- [x] 4.3 Add tests for cwd-relative deny/writable matcher semantics, fragment append order, ordered negation, and deny-over-writable behavior.
- [x] 4.4 Add tests for protected control path carveouts under broad writable grants.
- [x] 4.5 Add tests for `filesystem.virtual` macOS compatibility behavior: contents ignored and virtual targets write-denied.
- [x] 4.6 Add tests for macOS network mode policy generation and proc no-op compatibility.
- [x] 4.7 Add tests proving shared policy extraction does not change JSON schema generation or validation.

## 5. Integration Tests

- [x] 5.1 Add macOS integration tests that skip only when `/usr/bin/sandbox-exec` is unavailable and otherwise verify isolated command execution.
- [x] 5.2 Test that readable but non-writable project files cannot be modified without a matching writable pattern.
- [x] 5.3 Test that writable patterns allow edits and creation within selected writable subtrees.
- [x] 5.4 Test that deny patterns block `.env`-style reads and that later negation can re-allow selected matches.
- [x] 5.5 Test that `.heimdall-deny` and `.heimdall-write` are read from cwd and appended after JSON patterns.
- [x] 5.6 Test that protected control paths cannot be created or modified under broad writable cwd grants.
- [x] 5.7 Test that `filesystem.virtual` targets are not writable on macOS while virtual contents are not materialized.
- [x] 5.8 Test that `network: "none"` blocks general network access on macOS and `network: "host"` preserves network-capable command startup.
- [x] 5.9 Test that env allow/deny, stdio policies, signal forwarding, and non-zero exit propagation still work through Seatbelt.

## 6. Validation

- [x] 6.1 Run `mise format`.
- [x] 6.2 Run `mise run --force test`.
- [x] 6.3 Confirm the OpenSpec requirements for `macos-seatbelt-sandbox` and `sandbox-core-runtime` are covered by implementation tests before marking tasks complete.
