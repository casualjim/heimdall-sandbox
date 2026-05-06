## Purpose

Provide the Phase 1 minimal hardened sandbox runtime: explicit argument-driven execution, reusable core request handling, environment selection, process hardening, stdio policy handling, signal forwarding, and exit status propagation.

## Requirements

### Requirement: Workspace structure
The system SHALL be organized as a Cargo workspace with separate core library and CLI binary crates.

#### Scenario: Workspace contains core crate
- **WHEN** the repository is built
- **THEN** the workspace includes a `heimdall-core` library crate that contains reusable runtime behavior

#### Scenario: Workspace contains cli crate
- **WHEN** the repository is built
- **THEN** the workspace includes a `heimdall-sandbox` binary crate under `crates/heimdall-sandbox` that produces the `heimdall-sandbox` executable

#### Scenario: Core crate has no CLI dependency
- **WHEN** the core crate is compiled
- **THEN** it does not require CLI argument parsing dependencies or CLI-specific types

### Requirement: Explicit-input CLI
The system SHALL provide an `exec` command driven by explicit command-line arguments or an explicit JSON policy document and SHALL NOT load TOML configuration files from the CLI.

#### Scenario: Execute command with cwd
- **WHEN** the user runs `heimdall-sandbox exec --cwd <dir> -- <program> <args>`
- **THEN** the CLI creates a core execution request for `<program> <args>` with `<dir>` as the child process working directory

#### Scenario: Missing command is rejected
- **WHEN** the user runs `heimdall-sandbox exec --cwd <dir> --` without a command
- **THEN** the system exits with a sandbox misconfiguration error

#### Scenario: Missing cwd defaults to current directory
- **WHEN** the user runs `heimdall-sandbox exec -- <program>` without `--cwd`
- **THEN** the child process working directory is the sandbox process current directory

#### Scenario: Config file is not accepted by CLI
- **WHEN** the user tries to pass a config-file option to the CLI
- **THEN** the CLI rejects the invocation instead of loading a config file

#### Scenario: JSON policy file is accepted
- **WHEN** the user runs `heimdall-sandbox exec --policy <file>` with a JSON policy containing cwd, command, stdio, and shared sandbox config fields (`enabled`, `network`, `filesystem`, and `env`)
- **THEN** the CLI creates a core execution request from that JSON policy

#### Scenario: JSON policy accepts shared sandbox config shape
- **WHEN** a JSON policy contains `enabled: true`, `network: "host"`, `filesystem.deny`, `filesystem.writable`, `filesystem.virtual`, `env.allow`, and `env.deny`
- **THEN** the CLI parses those fields using the shared sandbox config shape

#### Scenario: Explicit no-proc execution is accepted
- **WHEN** a Linux caller explicitly requests no-proc execution mode through CLI arguments or the JSON policy document
- **THEN** the CLI creates a core execution request that carries the proc-mount-disabled request to platform execution

#### Scenario: JSON policy accepts network isolation request
- **WHEN** a JSON policy contains `network: "none"`
- **THEN** the CLI creates a core execution request that carries the network isolation request to platform execution

#### Scenario: JSON policy accepts filesystem isolation request
- **WHEN** a JSON policy contains non-empty `filesystem.deny`, `filesystem.writable`, or `filesystem.virtual`
- **THEN** the CLI creates a core execution request that carries the filesystem isolation request to platform execution

#### Scenario: Unknown JSON policy field is rejected
- **WHEN** a JSON policy contains a field outside the supported policy schema
- **THEN** the system exits with a sandbox misconfiguration error that identifies the unknown field

#### Scenario: JSON policy stdin is accepted
- **WHEN** the user runs `heimdall-sandbox exec --policy -` and writes a JSON policy to stdin
- **THEN** the CLI creates a core execution request from stdin

#### Scenario: JSON policy schema is generated
- **WHEN** the user runs `heimdall-sandbox policy schema`
- **THEN** the CLI prints a JSON Schema for accepted policy documents
- **AND** the schema rejects unknown top-level, `filesystem`, and `env` fields

#### Scenario: JSON policy file is validated without execution
- **WHEN** the user runs `heimdall-sandbox policy validate <file>`
- **THEN** the CLI validates the policy document and exits without running the policy command

#### Scenario: JSON policy stdin is validated without execution
- **WHEN** the user runs `heimdall-sandbox policy validate -` and writes a JSON policy to stdin
- **THEN** the CLI validates the policy document from stdin and exits without running the policy command

### Requirement: Core execution request
The system SHALL expose reusable core runtime APIs that accept structured execution requests independent of CLI parsing.

#### Scenario: CLI delegates to core
- **WHEN** the CLI parses a valid `exec` invocation
- **THEN** it constructs a core execution request and delegates execution to `heimdall-core`

#### Scenario: Future bindings can bypass CLI parsing
- **WHEN** another caller links to `heimdall-core`
- **THEN** it can construct an execution request without using CLI argv parsing

#### Scenario: Core request carries sandbox policy
- **WHEN** the CLI parses JSON `network`, `filesystem`, or proc-mount policy
- **THEN** the core execution request carries the structured sandbox policy independently from CLI parsing types

### Requirement: Environment selection arguments
The system SHALL default to explicitly allowlisted environment variables and SHALL also support blocklisted environment variables.

#### Scenario: Allowed variable is preserved
- **WHEN** the user passes `--allow-env KEY` and the parent process has environment variable `KEY`
- **THEN** the child process receives `KEY` with its original value

#### Scenario: Non-allowed variable is removed
- **WHEN** the parent process has an environment variable that was not passed via `--allow-env`
- **THEN** the child process does not receive that environment variable

#### Scenario: Multiple allowed variables are preserved
- **WHEN** the user passes multiple `--allow-env` arguments
- **THEN** the child process receives each listed environment variable that exists in the parent process

#### Scenario: Denied blocklisted variable is removed
- **WHEN** the user passes `--deny-env KEY` and the parent process has environment variable `KEY`
- **THEN** the child process does not receive `KEY`

#### Scenario: JSON env allow omitted inherits parent environment
- **WHEN** the JSON policy contains `env: { "deny": ["KEY"] }` without `env.allow`
- **THEN** the child process receives parent environment variables except denied and dangerous platform keys

#### Scenario: JSON env deny overrides allow
- **WHEN** the JSON policy contains both `env.allow` and `env.deny` with the same key
- **THEN** the child process does not receive that denied key

#### Scenario: JSON env null values are accepted
- **WHEN** the JSON policy contains `env.allow: null` or `env.deny: null`
- **THEN** the CLI treats that field the same as an omitted environment list

### Requirement: Process hardening
The system SHALL apply platform-specific process hardening before executing child commands.

#### Scenario: Linux hardening is applied
- **WHEN** the system runs on Linux
- **THEN** it disables process dumping, disables core dumps, and removes `LD_*` environment variables before command execution

#### Scenario: macOS hardening is applied
- **WHEN** the system runs on macOS
- **THEN** it denies debugger attach, disables core dumps, and removes `DYLD_*` environment variables before command execution

#### Scenario: Hardening failure is fatal
- **WHEN** required process hardening fails
- **THEN** the system exits with a sandbox misconfiguration error and does not execute the child command

### Requirement: Child command stdio
The system SHALL support Codex-compatible stdio policies for child command execution and SHALL default to inherited stdio.

#### Scenario: Default child stdio is inherited
- **WHEN** the user runs `heimdall-sandbox exec --cwd <dir> -- <program> <args>` without a stdio policy
- **THEN** the child process inherits stdin, stdout, and stderr from the sandbox process

#### Scenario: Child writes stdout
- **WHEN** the child command writes data to stdout with inherited stdio
- **THEN** the caller observes the same stdout data

#### Scenario: Child writes stderr
- **WHEN** the child command writes data to stderr with inherited stdio
- **THEN** the caller observes the same stderr data

#### Scenario: Piped stdio uses null stdin
- **WHEN** the user runs `heimdall-sandbox exec --cwd <dir> --stdio piped -- <program> <args>`
- **THEN** the child process receives null stdin

#### Scenario: Piped stdio captures output streams
- **WHEN** the child command writes stdout or stderr with piped stdio
- **THEN** the sandbox process preserves those stdout and stderr bytes for its caller

### Requirement: Signal forwarding
The system SHALL forward termination signals it receives to the running child command.

#### Scenario: SIGINT is received
- **WHEN** the sandbox process receives SIGINT while a child command is running
- **THEN** the system forwards SIGINT to the child command

#### Scenario: SIGTERM is received
- **WHEN** the sandbox process receives SIGTERM while a child command is running
- **THEN** the system forwards SIGTERM to the child command

### Requirement: Exit status propagation
The system SHALL return the child command's exit status when command execution completes.

#### Scenario: Child exits successfully
- **WHEN** the child command exits with status 0
- **THEN** the system exits with status 0

#### Scenario: Child exits with failure
- **WHEN** the child command exits with a non-zero status
- **THEN** the system exits with the same non-zero status

#### Scenario: Sandbox misconfiguration
- **WHEN** the sandbox runtime cannot validate cwd, apply hardening, or start the child command
- **THEN** the system exits with status 2
