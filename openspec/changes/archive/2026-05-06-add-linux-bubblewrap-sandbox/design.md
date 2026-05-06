## Context

Phase 1 established a Cargo workspace with a reusable `heimdall-core` runtime and a `heimdall-sandbox` CLI that accepts explicit argv or a JSON policy from `--policy <file>` / `--policy -`. That runtime currently hardens processes, filters environment variables, handles stdio, forwards signals, and propagates child exit status, but it still executes the command directly on the host filesystem.

The next step is to adapt the known Codex Linux sandbox model into Heimdall: bubblewrap builds a restricted filesystem/network namespace, then Heimdall re-enters itself inside the namespace before executing the requested command. The native binary remains an execution engine. It receives the JSON policy from callers and may read cwd-local `.heimdall-deny` / `.heimdall-write` fragments, but it does not discover or create Pi-specific config such as `.pi/heimdall.json`.

Implementation uses a dedicated `crates/heimdall-linux-sandbox` crate for Linux-only bubblewrap planning, launcher probing, virtual file preparation, selected runtime mounts, and cwd-relative filesystem policy materialization. `heimdall-core` owns reusable execution orchestration and request dispatch, while `heimdall-sandbox` remains the CLI/policy parsing face.

## Goals / Non-Goals

**Goals:**

- Execute Linux commands through bubblewrap when filesystem or network isolation is requested.
- Keep the base project view readable but readonly unless a writable ignore-pattern matcher grants write access.
- Mask deny-pattern matches as concrete bubblewrap mounts, with deny taking precedence over writable grants.
- Parse filesystem policy from `filesystem.deny`, `filesystem.writable`, and `filesystem.virtual`.
- Produce a JSON Schema for accepted policy documents so callers can validate config before invocation.
- Use the `ignore` crate for gitignore-style ordered pattern streams, matching the existing ecosystem precedent in `../niblits`.
- Merge cwd-relative `.heimdall-deny` and `.heimdall-write` after JSON patterns so later fragment lines can refine earlier JSON/default lines supplied by the caller.
- Preserve Phase 1 hardening, environment selection, stdio, signal forwarding, and exit status behavior.

**Non-Goals:**

- Do not implement macOS Seatbelt in this change.
- Do not implement seccomp filtering beyond the re-entry hook needed for the future inner stage.
- Do not implement Pi/TypeScript config discovery, default file creation, or `.pi/heimdall.json` ownership in native Rust.
- Do not implement shell AST policy enforcement or exfiltration detection.
- Do not vendor bubblewrap in this change; missing bubblewrap remains a sandbox misconfiguration.

## Decisions

### Generate policy JSON Schema from the parser types

The CLI exposes `heimdall-sandbox policy schema` to print the JSON Schema for `exec --policy` documents and `heimdall-sandbox policy validate [POLICY-FILE|-]` to validate policy documents without executing them. The schema is generated from the same Rust parser types with `schemars`, including strict top-level field validation and nested `filesystem` / `env` unknown-field rejection. This keeps documented policy shape, generated schema, validation, and runtime parsing in one place.

### Use `filesystem` sections for filesystem policy

The JSON policy will use this shape:

```json
{
  "filesystem": {
    "deny": ["**/.env*", "!**/.env.example"],
    "writable": [".", "!.git/**", "!.agents/**", "!.pi/**", "!.heimdall-*"],
    "virtual": {
      "/etc/passwd": "nobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n"
    }
  }
}
```

`deny` and `writable` are ordered pattern lists. `virtual` maps absolute sandbox paths to readonly file contents. This keeps filesystem policy expressed in the same pattern language used by policy materialization.

### Use `ignore::gitignore::GitignoreBuilder` for ordered pattern streams

Heimdall should compile deny and writable matchers with `GitignoreBuilder`, not `OverrideBuilder`. `OverrideBuilder` intentionally inverts gitignore semantics for CLI include/exclude overrides, while Heimdall wants normal gitignore semantics:

- `pattern` selects a path for the matcher.
- `!pattern` re-allows / unselects a path matched by earlier lines.
- Later lines have higher precedence.

For each matcher, native builds one ordered stream:

```text
deny      = JSON filesystem.deny      + cwd/.heimdall-deny
writable  = JSON filesystem.writable  + cwd/.heimdall-write
```

The Pi plugin can place its defaults into the JSON before invoking the native binary. Native does not know whether a pattern came from Pi defaults, user JSON, or another caller, except that cwd-local `.heimdall-*` fragments are appended after the JSON lists.

Alternative considered: use `globset` directly. `globset` can match glob patterns, but `ignore` already provides gitignore-style comments, negation, slash rules, and ripgrep-aligned behavior.

### Resolve `.heimdall-*` fragments relative to policy cwd

Native looks only at:

```text
<cwd>/.heimdall-deny
<cwd>/.heimdall-write
```

It does not walk upward to a git root, inspect `.pi`, or discover repository metadata. If a caller wants repo-root behavior, it must pass the repo root as `cwd` or include desired patterns directly in JSON.

Alternative considered: discover repository root or `.pi/heimdall.json` in native. That would blur the boundary between the reusable native execution engine and Pi-specific configuration ownership.

### Keep Linux sandbox planning in a dedicated crate

`crates/heimdall-linux-sandbox` owns Linux-only details: `bwrap` discovery/probing, bubblewrap argv construction, selected readonly runtime roots, virtual data files, protected control path placeholders, and ignore-pattern materialization. `heimdall-core` depends on that crate to decide when to route Linux isolation requests through bubblewrap, but it does not parse CLI policy documents. `heimdall-sandbox` parses CLI/JSON input and converts it into core request types.

This keeps platform-specific mounting and namespace code out of the core runtime request/execution model without moving business or CLI parsing behavior into the Linux adapter.

### Bubblewrap receives concrete paths, not patterns

Bubblewrap cannot mount a glob. Heimdall therefore materializes pattern decisions into concrete filesystem operations before spawning bubblewrap:

```text
ignore pattern stream → walk cwd → matching concrete paths → bwrap masks/binds
```

Deny matches are materialized as concrete masks such as `--ro-bind /dev/null <file>`. Writable matches are converted into writable bind roots and protected readonly/missing targets for negated control paths as needed.

### Deny wins over writable

Final access is determined in this order:

```text
if deny matcher selects path:       masked / unreadable
else if writable matcher selects:  writable
else:                              readonly
```

This lets callers provide broad write patterns while still masking secrets:

```json
{
  "filesystem": {
    "writable": ["."],
    "deny": ["**/.env*"]
  }
}
```

### Preserve the two-stage Linux execution shape

Linux execution uses the Codex-style two-stage pipeline:

```text
outer heimdall-sandbox exec
  → build bwrap argv
  → spawn/exec bwrap
  → re-enter heimdall-sandbox --apply-seccomp-then-exec inside namespace
  → exec requested command
```

The inner stage does not need to install seccomp in this change, but the CLI/internal request shape should reserve the hook so seccomp can be added later without changing the public execution model.

### Require Codex-compatible bubblewrap lifecycle handling

Heimdall must match the Codex lifecycle model for the Linux bubblewrap child:

- Probe the discovered system `bwrap` for `--argv0` support and build a compatible inner re-entry command for both new and old bubblewrap versions.
- Include `--unshare-user` and `--unshare-pid` for isolated Linux execution.
- Put the bubblewrap child in its own process group before exec, install `PR_SET_PDEATHSIG`, and forward `SIGHUP`, `SIGINT`, `SIGQUIT`, and `SIGTERM` to the child process group.
- Block forwarded signals during setup, record any pending signal, and replay it after forwarding is installed so shutdown races do not leave bwrap running unsupervised.

### Mount selected system files, not the full host `/etc`

The readonly base filesystem should expose platform runtime roots and only the host `/etc` files or directories needed for DNS and TLS (`/etc/resolv.conf`, `/etc/hosts`, `/etc/ssl`, and `/etc/ca-certificates` when present). It must not bind the full host `/etc` directory, because that leaks more host configuration than the sandbox needs.

Heimdall should provide synthetic readonly `/etc/passwd` and `/etc/group` defaults with minimal `nobody`/`nogroup` contents. Explicit `filesystem.virtual` entries for those paths override the defaults.

### Preflight `/proc` and support no-proc execution

`/proc` should be mounted by default only when supported. Heimdall should run a short bubblewrap preflight that attempts the `/proc` mount and, when the host/container rejects it with a known proc mount error, retry the real command without `/proc`. Callers must also have an explicit no-proc execution mode for environments where `/proc` must be suppressed without probing.

### Treat virtual files as readonly data mounts

`filesystem.virtual` entries create readonly file contents in the sandbox, implemented with bubblewrap data binds. They are appropriate for synthetic `/etc/passwd`, `/etc/group`, or other small caller-supplied files. They do not grant write access, and paths must be absolute sandbox paths.

### Keep fallback behavior explicit

If Linux isolation is requested and bubblewrap cannot be found or cannot be executed, Heimdall exits with the sandbox misconfiguration code. It must not silently fall back to direct execution because that would weaken the security contract.

## Risks / Trade-offs

- **Pattern semantics differ from ad hoc glob expectations** → Use `ignore` consistently and document that patterns are gitignore-style and cwd-relative.
- **Negated writable paths can be recreated if only existing paths are rebound readonly** → Apply protected-create handling for important named control paths so missing `.git`, `.agents`, `.pi`, `.heimdall-deny`, and `.heimdall-write` cannot be created under a broader writable root. Existing `.heimdall-*` paths are rebound readonly, and newly-created wildcard `.heimdall-*` paths are removed before sandbox execution completes so they do not persist on the host. Broad cwd grants such as `filesystem.writable: ["."]` must still allow regular descendants while protecting control paths.
- **Walking large trees to materialize deny masks has startup cost** → Use the `ignore` crate walker/matcher behavior and scope scanning to cwd; callers can keep deny patterns focused.
- **Bubblewrap availability varies by host/container** → Return a clear sandbox misconfiguration error instead of weakening to unsandboxed execution.

## Implementation Plan

- Update native JSON parsing to accept `filesystem` and reject unknown policy fields.
- Add `schemars` derives for policy parser types and expose `heimdall-sandbox policy schema` plus `heimdall-sandbox policy validate [POLICY-FILE|-]`.
- Keep `--policy <file>` and `--policy -` unchanged as input mechanisms.
- Let the Pi/TypeScript integration generate or store `.pi/heimdall.json` and pass the resulting execution JSON to native.
- Rollback is to pass policies without Linux filesystem/network isolation, preserving Phase 1 direct execution behavior where no isolation is requested.

## Open Questions

None. The remaining work is implementation detail against the agreed native/TypeScript boundary and the Codex reference model.
