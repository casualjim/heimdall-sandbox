## 1. Policy Schema and Request Model

- [x] 1.1 Add the `ignore` crate dependency for `heimdall-core`, add the `schemars` crate dependency for `heimdall-sandbox`, and keep dependency declarations workspace-managed.
- [x] 1.2 Parse JSON filesystem policy from `filesystem.deny`, `filesystem.writable`, and `filesystem.virtual` while preserving `--policy <file>` and `--policy -` input mechanisms.
- [x] 1.3 Reject unknown policy document fields with a clear sandbox misconfiguration error.
- [x] 1.4 Add core request types for network mode, filesystem deny patterns, writable patterns, and virtual readonly files without introducing CLI-specific types into `heimdall-core`.
- [x] 1.5 Validate filesystem policy syntactically at the boundary, including absolute virtual-file targets and valid gitignore-style pattern lines.
- [x] 1.6 Add CLI/core unit tests for the JSON policy shape, stdin policy parsing, unknown-field rejection, and omitted optional filesystem fields.
- [x] 1.7 Generate and expose a JSON Schema for accepted policy documents.
- [x] 1.8 Output the JSON Schema as a deliverable via `heimdall-sandbox policy schema`.
- [x] 1.9 Validate policy documents without execution via `heimdall-sandbox policy validate [POLICY-FILE|-]`.

## 2. Ignore Pattern Policy

- [x] 2.1 Implement cwd-relative deny matcher construction with `ignore::gitignore::GitignoreBuilder` using JSON `filesystem.deny` followed by `<cwd>/.heimdall-deny` when present.
- [x] 2.2 Implement cwd-relative writable matcher construction with `ignore::gitignore::GitignoreBuilder` using JSON `filesystem.writable` followed by `<cwd>/.heimdall-write` when present.
- [x] 2.3 Materialize deny matches by walking cwd and collecting selected existing files, symlinks, and directories into concrete mask targets.
- [x] 2.4 Materialize writable matches into writable bind roots while preserving readonly behavior for paths not selected by the writable matcher.
- [x] 2.5 Apply deny-over-writable precedence when a path is selected by both matchers.
- [x] 2.6 Add unit tests for ordered negation, `.heimdall-*` merge order, cwd-relative lookup only, and deny-over-writable decisions.

## 3. Linux Bubblewrap Argument Construction

- [x] 3.1 Add a Linux bubblewrap module that constructs argv from the core execution request and policy materialization output.
- [x] 3.2 Discover system `bwrap` from `PATH`, verify it is executable, and return sandbox misconfiguration when isolation is requested but bubblewrap is unavailable.
- [x] 3.3 Build the readonly base filesystem view with platform runtime roots, minimal `/dev`, selected readonly `/etc` support files, cwd readonly access, and optional `/proc` handling.
- [x] 3.4 Add writable bind mounts for materialized writable paths and protected create handling for negated/control paths such as `.git`, `.agents`, `.pi`, and `.heimdall-*` when they are excluded under broader writable grants.
- [x] 3.5 Add deny masks for materialized deny targets using concrete bubblewrap mounts.
- [x] 3.6 Add readonly virtual file mounts for `filesystem.virtual` using bubblewrap data binds.
- [x] 3.7 Add bubblewrap network flags for `network: "none"` and preserve host networking for `network: "host"` or omitted network policy.
- [x] 3.8 Add unit tests for generated bubblewrap argv ordering, readonly/writable/deny layering, virtual files, and network flags.

## 4. Linux Execution Pipeline

- [x] 4.1 Route Linux requests that need filesystem or network isolation through the bubblewrap executor while preserving direct execution for requests that do not need isolation.
- [x] 4.2 Add the internal re-entry mode for the two-stage pipeline so outer Heimdall invokes bubblewrap and inner Heimdall executes the requested command inside the namespace.
- [x] 4.3 Preserve Phase 1 child environment filtering and dangerous environment stripping for commands executed through bubblewrap.
- [x] 4.4 Preserve inherited and piped stdio behavior through the bubblewrap execution path.
- [x] 4.5 Forward termination signals to the bubblewrap child process group and preserve child exit status mapping.
- [x] 4.6 Ensure hardening, spawn, wait, and bubblewrap setup failures map to documented sandbox misconfiguration behavior without falling back to unsandboxed execution.

## 5. Integration Tests

- [x] 5.1 Add Linux integration tests that skip only when bubblewrap is unavailable and otherwise verify isolated command execution.
- [x] 5.2 Test that readable but non-writable project files cannot be modified without a matching writable pattern.
- [x] 5.3 Test that writable patterns allow edits and creation within selected writable subtrees.
- [x] 5.4 Test that deny patterns mask `.env`-style files and that later negation can re-allow selected matches.
- [x] 5.5 Test that `.heimdall-deny` and `.heimdall-write` are read from cwd and appended after JSON patterns.
- [x] 5.6 Test that `filesystem.virtual` content is visible and readonly inside the sandbox.
- [x] 5.7 Test that `network: "none"` requests bubblewrap network isolation on Linux.
- [x] 5.8 Test that env allow/deny, stdio policies, signal forwarding, and non-zero exit propagation still work through bubblewrap.

## 6. Validation

- [x] 6.1 Run `mise format`.
- [x] 6.2 Run `mise run --force test`.
- [x] 6.3 Confirm the OpenSpec requirements for `linux-bubblewrap-sandbox` and `sandbox-core-runtime` are covered by implementation tests before marking tasks complete.

## 7. Codex-Aligned Linux Sandbox Hardening

- [x] 7.1 Add `--unshare-user` to isolated Linux bubblewrap invocations and cover it in argv construction tests.
- [x] 7.2 Probe discovered system `bwrap` for `--argv0` support, use `--argv0` when supported, and use a compatible inner re-entry executable path when unsupported.
- [x] 7.3 Replace full host `/etc` binding with selected readonly DNS/TLS support files and default synthetic readonly `/etc/passwd` plus `/etc/group`, while preserving explicit `filesystem.virtual` overrides.
- [x] 7.4 Add `/proc` preflight fallback and explicit no-proc execution mode plumbing through CLI/policy, core request, and Linux bubblewrap planning.
- [x] 7.5 Rework bubblewrap lifecycle handling to place the child in its own process group, install `PR_SET_PDEATHSIG`, block/replay `SIGHUP`, `SIGINT`, `SIGQUIT`, and `SIGTERM` during setup, and forward those signals to the process group.
- [x] 7.6 Strengthen protected-create handling for `.git`, `.agents`, `.pi`, named `.heimdall-*` fragments, and arbitrary `.heimdall-*` persistence cleanup under broad writable grants such as `filesystem.writable: ["."]`, including existing and missing protected paths.
- [x] 7.7 Add or update Linux integration/unit tests for all new hardening requirements, then rerun `mise format` and `mise run --force test` before marking this section complete.
