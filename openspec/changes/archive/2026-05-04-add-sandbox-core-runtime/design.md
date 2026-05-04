## Context

The repository currently contains only a minimal Rust binary. The sandbox plan calls for a native `heimdall-sandbox` executable delivered in phases. Phase 1 is the minimal hardened sandbox runtime. Later phases add Linux bwrap/seccomp and macOS Seatbelt jail/container isolation. The JavaScript side will own higher-level configuration and call the binary with explicit arguments.

This change implements Phase 1: the cross-platform minimal hardened sandbox runtime. It should create a Cargo workspace with reusable core logic and a thin CLI wrapper. The CLI must not load ambient configuration files; it receives runtime choices as command-line arguments or an explicit JSON policy document supplied by path or stdin. The core crate should be structured so future native bindings can call it without going through argument parsing.

## Goals / Non-Goals

**Goals:**

- Convert the repository to a Cargo workspace with runtime and CLI crates:
  - `heimdall-core`: reusable runtime library.
  - `heimdall-process-hardening`: shared platform hardening helper crate used by core child setup and CLI process startup.
  - `heimdall-sandbox`: binary wrapper that produces the `heimdall-sandbox` executable.
- Provide a thin explicit-input `heimdall-sandbox exec` CLI surface using either direct args (`--cwd <dir> [--allow-env <KEY>]... [--deny-env <KEY>]... [--stdio inherit|piped] -- <command...>`) or `--policy <file|->` JSON.
- Deliver minimal hardened sandbox behavior: environment allowlisting, process hardening, direct argv execution, signal forwarding, and exit status propagation.
- Keep all CLI parsing in `heimdall-sandbox` and all runtime behavior in `heimdall-core`.
- Filter environment variables through an explicit allowlist supplied as arguments.
- Apply platform-specific process hardening where available:
  - Linux: `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, strip `LD_*`.
  - macOS: `PT_DENY_ATTACH`, `RLIMIT_CORE=0`, strip `DYLD_*`.
- Execute the requested command with stdout/stderr inherited directly by the child.
- Forward termination signals to the child process and return the child exit status.
- Establish module boundaries that future Linux and macOS sandbox implementations and future bindings can plug into.

**Non-Goals:**

- No ambient CLI config loading of any kind in this change.
- No TOML config schema in this change.
- No bwrap filesystem namespace construction in this change.
- No macOS Seatbelt policy generation in this change.
- No filesystem or network jail/container isolation in this change; later bwrap and Seatbelt changes add that containment.
- No shell AST parsing, command policy enforcement, exfiltration detection, seccomp, proxy routing, or npm packaging in this change.
- No cross-compilation setup; platform binaries will be produced natively later.

## Decisions

### Treat Phase 1 as a minimal hardened sandbox runtime

This change delivers the first sandbox runtime slice: environment isolation through explicit allowlisting, platform process hardening, direct argv command execution, signal forwarding, and exit status propagation. It is not the later filesystem/network jail or container layer.

Alternative considered: describe this as only a foundation. Rejected because the Phase 1 deliverable is a real minimal sandbox runtime, even though full OS containment arrives in later bwrap and Seatbelt changes.

### Use a Cargo workspace with core, hardening, and cli crates

The workspace separates reusable runtime behavior from argument parsing. `heimdall-core` owns the execution API, environment filtering orchestration, child hardening setup, and error model. `heimdall-process-hardening` owns the low-level platform hardening calls and dangerous environment key detection shared by process startup and child execution. `heimdall-sandbox` owns `clap` parsing, applies startup hardening to the sandbox process itself, and delegates execution to core.

Alternative considered: keep a single binary crate. Rejected because it would couple reusable runtime behavior to CLI parsing and make future bindings harder. Another alternative considered: keep all hardening helpers private to `heimdall-core`. Rejected because the CLI process also needs startup hardening before parsing/execution, while core still owns reusable child execution behavior.

### Keep the CLI explicit-input only

The CLI does not accept `--config` and does not read ambient TOML configuration. The JavaScript side can pass direct CLI arguments or provide a JSON policy document explicitly with `--policy <file>` or `--policy -`. This keeps the native binary deterministic while avoiding very long argument lists for larger sandbox policies.

Alternative considered: ambient CLI config loading. Rejected because configuration discovery is not the CLI's responsibility in this architecture.

### Use `clap` only in the CLI crate

`clap` provides robust subcommand parsing, trailing argument handling after `--`, generated help, and typed validation. Keeping it in `heimdall-sandbox` prevents the core crate from depending on a CLI framework.

Alternative considered: hand-written parsing. Rejected because correct handling of trailing command arguments and help/version output is easy to get wrong.

### Model execution as a core request type

`heimdall-core` exposes a request type such as `ExecRequest { cwd, command, allowed_env }`. The CLI converts parsed arguments into this request and calls the core runtime. Future bindings can construct the same request directly.

Alternative considered: pass raw CLI argv into core. Rejected because it would make core depend on CLI syntax and reduce binding usefulness.

### Keep command execution argument-vector based

The runtime executes a program plus arguments directly. If callers need shell semantics, the JavaScript side must explicitly invoke `sh -lc <command>` or another shell wrapper. This avoids accidentally adding another shell parsing/evasion layer to the core runtime.

Alternative considered: accept a single shell string and always invoke a shell. Rejected because it hides the actual executable and complicates later policy enforcement.

### Use explicit environment selection

The default child environment is built from allowlist keys supplied through CLI args (for example, repeated `--allow-env KEY`) or JSON `env.allow`. `Command::env_clear()` ensures secrets such as cloud credentials and tokens are not inherited accidentally.

For callers that need most of the parent environment, direct args support repeated `--deny-env KEY`; JSON can omit `env.allow` and provide `env.deny`. Dangerous platform variables are still stripped. When JSON provides both `env.allow` and `env.deny`, denied keys override allowed keys.

Alternative considered: ambient config-driven environment policy. Rejected because the CLI does not load config.

### Apply hardening through a shared helper crate

Low-level platform hardening lives in `heimdall-process-hardening`. The CLI invokes process startup hardening before it parses and executes requests, which disables debugging/core dumps for the sandbox process and strips dangerous loader environment variables. `heimdall-core` invokes child hardening from its execution path before the requested command is executed. Linux and macOS implementations are compiled conditionally. Hardening failures return a sandbox misconfiguration error and the child command is not executed.

Alternative considered: use a constructor/pre-main hook. Rejected for this first change because explicit startup ordering is easier to test and reason about. Another alternative considered: put every hardening helper directly in `heimdall-core`. Rejected because sharing a small infrastructure helper avoids duplicating platform-specific libc code while preserving the CLI/core boundary: CLI parsing remains in `heimdall-sandbox`, execution policy remains in `heimdall-core`, and platform syscall helpers remain in `heimdall-process-hardening`.

### Support Codex-compatible stdio policies

The default child process stdio policy inherits stdin, stdout, and stderr from the sandbox process. This keeps terminal behavior faithful to the child command and preserves the original Phase 1 behavior.

The runtime also supports a Codex-compatible piped stdio policy. In this mode, child stdin is null and child stdout/stderr are piped. Because the Phase 1 CLI returns an exit code rather than a structured output object, the CLI forwards piped stdout/stderr bytes back to its own stdout/stderr so callers still observe the child output.

Alternative considered: keep inherited stdio only. Rejected because parity with Codex's `StdioPolicy::Piped` is useful for future tool-call integration and prevents commands from hanging on inherited stdin when piped style execution is requested.

### Use cross-platform future policy arguments

Future Linux bwrap and macOS Seatbelt work should expose platform-neutral policy intent to the JavaScript integration, such as read paths, write paths, deny-read patterns, and network mode. Platform-specific layers should translate that intent into bwrap arguments or Seatbelt policy.

Alternative considered: expose bwrap-shaped or Seatbelt-shaped passthrough arguments directly. Rejected because it would leak platform mechanics into the JavaScript contract and fit one platform better than the other.

## Risks / Trade-offs

- **Signal forwarding can be platform-sensitive** → Keep forwarding Unix-only initially and isolate it in core execution code; unsupported platforms can still run commands without custom forwarding.
- **Hardening may fail in restrictive environments** → Return exit code 2 with a clear error so callers know the sandbox could not be established safely.
- **Direct argv execution differs from shell-string behavior** → The JavaScript caller must explicitly choose any shell wrapper it needs.
- **Args-only CLI can become verbose** → This is intentional; the JavaScript layer owns higher-level configuration and can generate the arguments.
- **No jail/container isolation yet** → This change is the minimal hardened sandbox runtime; follow-up changes must add Linux bwrap and macOS Seatbelt before treating it as the full filesystem/network-contained sandbox.

## Migration Plan

1. Replace the single-package `Cargo.toml` with a workspace manifest.
2. Add `crates/heimdall-core` as a library crate.
3. Add `crates/heimdall-process-hardening` as a shared platform hardening helper crate.
4. Add `crates/heimdall-sandbox` as the binary crate producing `heimdall-sandbox`.
5. Move runtime behavior into `heimdall-core`, low-level hardening helpers into `heimdall-process-hardening`, and keep CLI parsing in `heimdall-sandbox`.
6. Add unit tests for core request validation, env filtering, hardening helpers, and exit-code mapping.
7. Add CLI smoke tests that run a simple command through `heimdall-sandbox exec`.

Rollback is straightforward: revert the workspace and crate additions. No persistent data migration is required.

## Resolved Questions

- Future platform policy arguments should be cross-platform intent, not bwrap or Seatbelt passthrough.
- Required hardening failures are fatal; the child command is not executed.
- Child stdout and stderr are inherited directly rather than piped through core for structured capture.
