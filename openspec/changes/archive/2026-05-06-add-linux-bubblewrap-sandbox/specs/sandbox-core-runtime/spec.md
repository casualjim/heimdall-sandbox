## MODIFIED Requirements

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
