## Context

The runtime already has an explicit JSON policy shape and direct execution path in `heimdall-core`. Phase 2 added Linux isolation through bubblewrap when `network: "none"` or non-empty filesystem controls are present, but non-Linux isolation requests currently fail as unsupported. Phase 3 adds the macOS platform path using Seatbelt (`/usr/bin/sandbox-exec`) while preserving the same caller-facing policy document used by Linux.

The Linux implementation currently owns several policy types that are semantically shared (`NetworkMode`, `ProcMode`, `FilesystemPolicy`). macOS should not depend on a Linux-named crate for shared request types, and the Linux crate contains Linux-only implementation details such as bubblewrap discovery and virtual file data binds. The Seatbelt implementation should therefore make the shared policy surface platform-neutral before wiring in macOS execution.

Codex provides the main precedent: use a deny-default Seatbelt base policy, selected platform read defaults for command/runtime compatibility, dynamic filesystem rules, dynamic network rules, Darwin user cache directory parameters, and canonical path handling because macOS path aliases such as `/tmp` and `/etc` often resolve through `/private`.

## Goals / Non-Goals

**Goals:**

- Route macOS isolation requests through `/usr/bin/sandbox-exec`.
- Keep the shared JSON policy shape compatible across Linux and macOS.
- Preserve cwd-relative gitignore-style semantics for `filesystem.deny` and `filesystem.writable`, including fragment append order.
- Preserve deny-over-writable precedence and protected workspace control paths under broad writable grants.
- Treat macOS `filesystem.virtual` as compatibility input: ignore supplied contents, do not overlay files, and ensure virtual target paths are not writable.
- Preserve existing environment filtering, process hardening, stdio behavior, signal forwarding, and child exit status propagation.
- Fail closed if Seatbelt setup or spawn fails after isolation was requested.

**Non-Goals:**

- Do not implement a mount, bind, FUSE, chroot, or DYLD-based virtual filesystem on macOS.
- Do not implement shell AST policy enforcement, exfiltration detection, managed proxy routing, or seccomp.
- Do not change the JavaScript/Pi config ownership model; native still consumes explicit CLI arguments or explicit JSON policy only.
- Do not change Linux sandbox behavior except where shared policy types must move to support macOS cleanly.
- Do not make `proc` do anything on macOS; it is accepted only for shared config compatibility.

## Decisions

### Use `/usr/bin/sandbox-exec` only

Seatbelt invocation uses the absolute system path `/usr/bin/sandbox-exec`. The planner never searches `PATH`, matching the Codex security model: if an attacker can replace `/usr/bin/sandbox-exec`, they already control the host.

Alternative considered: discover `sandbox-exec` from `PATH`. Rejected because it makes the sandbox launcher injectable by the same environment the sandbox is meant to constrain.

### Keep policy parsing shared, make shared policy types platform-neutral

The accepted JSON document remains the same shape: `enabled`, `network`, `proc`, `filesystem.deny`, `filesystem.writable`, `filesystem.virtual`, `env`, `stdio`, `cwd`, and `command`. The implementation should move shared sandbox policy types and validation out of the Linux-specific crate into a platform-neutral shared location, then make Linux and macOS planners consume that shared model.

A small shared policy crate or equivalent platform-neutral module is preferred over making macOS import `heimdall-linux-sandbox` types. The shared layer should contain only request/policy data and validation; bubblewrap argv construction and Seatbelt SBPL generation remain platform-specific.

Alternative considered: keep shared types in `heimdall-linux-sandbox`. Rejected because phase 3 would make macOS depend on Linux implementation details and Linux-only symbols.

### Generate Seatbelt policy from shared filesystem decisions

Seatbelt does not perform mount overlays. It allows and denies operations on the real macOS path graph. The macOS planner should build an SBPL policy from the same effective policy decisions as Linux:

1. Build ordered gitignore matchers from JSON patterns followed by cwd-local `.heimdall-deny` / `.heimdall-write` fragments.
2. Interpret patterns relative to the policy cwd only; do not walk upward or inspect `.pi` config.
3. Materialize selected existing paths for deny and writable decisions where needed to preserve Linux-compatible negation semantics.
4. Canonicalize effective paths and include important alias spellings where macOS may resolve `/tmp`, `/var`, or `/etc` through `/private`.
5. Generate read permissions for the readonly project view and platform defaults.
6. Generate write permissions only for writable targets, with carveouts for denied paths, protected paths, and virtual target paths.

For broad writable cwd grants such as `filesystem.writable: ["."]`, the write rule should use `require-not` carveouts and/or explicit write denies so `.git`, `.agents`, `.pi`, `.heimdall-deny`, `.heimdall-write`, arbitrary `.heimdall-*`, deny targets, and virtual targets do not become writable.

Alternative considered: translate every deny glob directly into a Seatbelt regex. Rejected as the default because Seatbelt has no ordered gitignore negation model, so a later `!pattern` cannot reliably re-allow an earlier deny without first compiling the pattern stream.

### Use Codex-style base and platform default SBPL sections

The policy starts with a deny-default base inspired by Codex. It should allow process fork/exec inheritance, same-sandbox signals, selected sysctls, OpenDirectory lookup, PTY support, Python multiprocessing semaphores, and readonly preferences. A restricted readonly platform defaults section should grant the minimum system reads needed for ordinary tools to start on macOS, including system libraries/frameworks, `/usr/bin`, `/bin`, `/dev/null`, file descriptors, and Darwin runtime metadata.

Alternative considered: write a tiny policy with only project path rules. Rejected because exploratory Seatbelt runs and Codex precedent show that ordinary commands can abort or fail before reaching user code without broader system runtime allowances.

### Map network modes to Seatbelt network rules

`network: "none"` adds no general outbound/inbound network allowances. `network: "host"` or omitted network policy adds full outbound/inbound network allowances plus the support rules needed for DNS, TLS trust, SecurityServer, networkd, ocspd, trustd, and Darwin cache directory access.

The current phase only needs full host network or no network. Proxy-only/managed network routing remains future work.

Alternative considered: always include Codex restricted network support rules. Rejected because `network: "none"` should stay as closed as practical under Seatbelt.

### Treat `filesystem.virtual` as readonly compatibility paths on macOS

Seatbelt cannot bind caller-supplied contents onto arbitrary absolute paths. On macOS, `filesystem.virtual` is accepted so shared Linux/macOS config documents keep working, but the supplied file contents are ignored and no synthetic file is materialized. Each virtual target path is treated as a readonly compatibility path: reads follow the normal Seatbelt read policy, while writes to the target path and its canonical spelling are denied or carved out of writable grants.

This means a policy that supplies `/etc/passwd` as a virtual file does not replace `/etc/passwd` on macOS, but it also does not allow a broad writable rule to modify that path.

Alternative considered: fail closed on macOS when `filesystem.virtual` is present. Rejected because the config is shared across Linux and macOS today. Alternative considered: materialize under `.tmp/heimdall`; rejected because it would change the path observed by the child and would not provide Linux-equivalent virtual-path behavior.

### Preserve direct execution for non-isolated requests

`ExecRequest::needs_isolation()` remains the switch. Requests with host networking and empty filesystem controls still execute directly with existing hardening/env/stdio/signal behavior. Requests needing isolation dispatch to Linux bubblewrap on Linux and Seatbelt on macOS; unsupported platforms continue to fail with sandbox misconfiguration instead of silently executing unsandboxed.

## Risks / Trade-offs

- Seatbelt is deprecated and undocumented/private in places → Use `/usr/bin/sandbox-exec`, keep the policy small enough to maintain, and mirror proven Codex SBPL sections.
- macOS path aliases can bypass naive literal rules → Canonicalize paths and include canonical spellings for deny/write carveouts.
- `filesystem.virtual` behavior differs from Linux → Keep it compatibility-only on macOS, document that contents are ignored, and make targets readonly rather than pretending Seatbelt can overlay files.
- Walking cwd to preserve gitignore negation can add startup cost → Match Linux behavior and limit walking to policy cwd; callers should keep deny/writable patterns focused.
- Broad platform defaults may expose more system metadata than a pure synthetic root → Keep user/project data constrained; platform defaults are only to let standard macOS tools launch and resolve TLS/DNS when network is enabled.
- Shared policy extraction can touch Linux code → Keep the refactor mechanical and preserve existing Linux tests before adding macOS behavior.

## Migration Plan

1. Extract or relocate shared sandbox policy types/validation so both Linux and macOS planners consume the same request model.
2. Add the macOS Seatbelt planner and SBPL generation behind `#[cfg(target_os = "macos")]`.
3. Wire `heimdall-core` platform dispatch to Seatbelt on macOS for isolation requests.
4. Add unit tests for SBPL construction and macOS-specific compatibility behavior.
5. Add macOS integration tests that run `/usr/bin/sandbox-exec` when available.
6. Roll back by removing the macOS dispatch branch; Linux and direct execution behavior remain unchanged.

## Open Questions

None. The key macOS virtual-file decision is settled: accept the field, ignore contents, and make target paths readonly/write-denied for compatibility.
