## 1. Workspace Setup

- [x] 1.1 Replace the root package manifest with a Cargo workspace manifest.
- [x] 1.2 Create `crates/heimdall-core` as a library crate for reusable runtime behavior.
- [x] 1.3 Create `crates/heimdall-sandbox` as a binary crate that builds the `heimdall-sandbox` executable.
- [x] 1.4 Add workspace dependencies for error handling, libc, signal handling, and CLI parsing only where needed.

## 2. Core Runtime API

- [x] 2.1 Define a core `ExecRequest` type containing cwd, command argv, and allowed environment variable names.
- [x] 2.2 Define a core error type that maps runtime failures to documented exit codes.
- [x] 2.3 Implement cwd validation in core.
- [x] 2.4 Add unit tests for valid requests, missing command, invalid cwd, and exit-code mapping.

## 3. CLI Interface

- [x] 3.1 Implement direct `heimdall-sandbox exec --cwd <dir> [--allow-env <KEY>]... [--deny-env <KEY>]... [--stdio inherit|piped] -- <command...>` parsing in `crates/heimdall-sandbox` with `clap`.
- [x] 3.2 Ensure the CLI defaults missing cwd to the current directory and rejects missing command invocations.
- [x] 3.3 Ensure the CLI does not accept or load config-file arguments.
- [x] 3.4 Convert parsed CLI args into a `heimdall-core` execution request.
- [x] 3.5 Add CLI tests for valid invocation, missing cwd, invalid cwd, missing command, and rejected config argument.
- [x] 3.6 Add explicit JSON policy input via `--policy <file>` and `--policy -`.

## 4. Environment Filtering

- [x] 4.1 Implement allowlist-based child environment construction in `heimdall-core` using `Command::env_clear()` semantics.
- [x] 4.2 Preserve environment variables listed by `--allow-env` when present in the parent process.
- [x] 4.3 Remove non-allowed variables from the child environment.
- [x] 4.4 Add tests proving allowed variables are preserved and secret variables are removed.
- [x] 4.5 Add blocklist environment support with `--deny-env` for cases where the deny list is shorter.

## 5. Process Hardening

- [x] 5.1 Implement Linux hardening in `heimdall-core`: disable process dumping, disable core dumps, and remove `LD_*` variables.
- [x] 5.2 Implement macOS hardening in `heimdall-core`: deny debugger attach, disable core dumps, and remove `DYLD_*` variables.
- [x] 5.3 Implement unsupported-platform behavior behind conditional compilation.
- [x] 5.4 Map hardening failures to sandbox misconfiguration exit code 2.
- [x] 5.5 Add unit tests for environment-prefix stripping and hardening error mapping where practical.

## 6. Command Execution

- [x] 6.1 Implement child process spawning in `heimdall-core` with validated cwd and filtered environment.
- [x] 6.2 Inherit child stdout and stderr directly from the sandbox process.
- [x] 6.3 Return the child command's exit status when it exits normally.
- [x] 6.4 Return `128 + signal` when the child terminates by signal on Unix.
- [x] 6.5 Map child spawn failures to sandbox misconfiguration exit code 2.
- [x] 6.6 Add Codex-compatible stdio policy support with inherited stdio by default and piped stdio on request.

## 7. Signal Forwarding

- [x] 7.1 Install Unix signal handling while a child is running.
- [x] 7.2 Forward SIGINT and SIGTERM to the child process.
- [x] 7.3 Restore signal handling after the child exits.
- [x] 7.4 Add integration coverage for forwarding behavior where practical.

## 8. Verification

- [x] 8.1 Add an integration smoke test that runs a simple command through `heimdall-sandbox exec`.
- [x] 8.2 Add an integration test proving the child process runs in the requested cwd.
- [x] 8.3 Add an integration test proving `--allow-env` controls inherited environment variables.
- [x] 8.4 Add an integration test proving non-zero child exit statuses are propagated.
- [x] 8.5 Add integration tests proving inherited stdin and piped stdin/stdout/stderr behavior.
- [x] 8.6 Add integration tests proving JSON policy file and stdin input behavior.
- [x] 8.7 Run `mise test` and ensure all tests pass.
- [x] 8.8 Run `mise format` and ensure formatting is clean.
