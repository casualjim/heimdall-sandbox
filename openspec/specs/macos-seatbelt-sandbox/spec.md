## Purpose

Specify macOS Seatbelt sandbox behavior for filesystem, network, proc-compatibility, and runtime-preservation semantics.

## Requirements

### Requirement: macOS Seatbelt execution
The system SHALL execute isolated macOS commands through Seatbelt using `/usr/bin/sandbox-exec` whenever filesystem isolation or network isolation is requested.

#### Scenario: Filesystem isolation uses Seatbelt
- **WHEN** a macOS caller runs `heimdall-sandbox exec` with a policy containing `filesystem` controls
- **THEN** the command runs under a Seatbelt policy generated from that filesystem policy

#### Scenario: Network isolation uses Seatbelt
- **WHEN** a macOS caller runs `heimdall-sandbox exec` with `network: "none"`
- **THEN** the command runs under a Seatbelt policy without general outbound or inbound network allowances

#### Scenario: Seatbelt executable path is fixed
- **WHEN** macOS isolation is requested
- **THEN** the system invokes `/usr/bin/sandbox-exec`
- **AND** the system does not search `PATH` for `sandbox-exec`

#### Scenario: Seatbelt setup failure is fatal
- **WHEN** macOS isolation is requested and Seatbelt cannot be started or the policy cannot be prepared
- **THEN** the system exits with the sandbox misconfiguration code
- **AND** the requested command is not executed directly on the host

### Requirement: Seatbelt base policy
The system SHALL generate a deny-default Seatbelt policy that allows only the macOS system operations required for normal command execution and explicit sandbox policy grants.

#### Scenario: Deny-default policy is used
- **WHEN** a macOS isolation policy is generated
- **THEN** the generated SBPL starts from a default-deny policy

#### Scenario: Child process execution is allowed
- **WHEN** a sandboxed macOS command forks or executes child processes
- **THEN** Seatbelt allows those child processes to run under the inherited sandbox policy

#### Scenario: Standard runtime reads are allowed
- **WHEN** a sandboxed macOS command starts a standard system executable such as `/bin/sh` or `/usr/bin/env`
- **THEN** Seatbelt allows the system library, framework, device, and metadata reads required for that executable to start

#### Scenario: Interactive terminal basics are allowed
- **WHEN** a sandboxed macOS command uses inherited terminal file descriptors or PTY devices
- **THEN** Seatbelt allows the minimal device and ioctl operations required for interactive shells to work

### Requirement: Seatbelt filesystem policy
The system SHALL expose the policy cwd as readable by default and SHALL grant write access only through writable policy matches after applying deny and protected-path precedence.

#### Scenario: Non-writable project file is readonly
- **WHEN** a macOS policy includes the cwd in the readable sandbox view but no writable pattern matches a project file
- **THEN** the command can read that file
- **AND** the command cannot modify that file

#### Scenario: Writable pattern grants write access
- **WHEN** `filesystem.writable` contains a gitignore-style pattern that selects a cwd-relative file or subtree
- **THEN** the selected path is writable under the Seatbelt policy

#### Scenario: Writable fragment is appended after JSON patterns
- **WHEN** `filesystem.writable` contains patterns and `<cwd>/.heimdall-write` exists
- **THEN** the system compiles a single writable matcher from the JSON patterns followed by the `.heimdall-write` lines

#### Scenario: Writable fragment is absent
- **WHEN** `<cwd>/.heimdall-write` does not exist
- **THEN** the writable matcher is compiled from the JSON `filesystem.writable` patterns alone

#### Scenario: Deny pattern blocks existing file reads
- **WHEN** `filesystem.deny` selects an existing file under cwd
- **THEN** the generated Seatbelt policy prevents the command from reading that file's host contents

#### Scenario: Deny negation re-allows earlier deny pattern
- **WHEN** `filesystem.deny` contains a pattern followed by a later negated pattern that matches the same path
- **THEN** the later negated pattern removes that path from the deny set used for Seatbelt policy generation

#### Scenario: Deny fragment is appended after JSON patterns
- **WHEN** `filesystem.deny` contains patterns and `<cwd>/.heimdall-deny` exists
- **THEN** the system compiles a single deny matcher from the JSON patterns followed by the `.heimdall-deny` lines

#### Scenario: Deny wins over writable
- **WHEN** a path is selected by both the deny matcher and the writable matcher
- **THEN** the generated Seatbelt policy makes the path unreadable and not writable

#### Scenario: Cwd-relative pattern matches cwd path
- **WHEN** cwd is `/repo` and `filesystem.deny` contains `**/.env*`
- **THEN** `/repo/.env` and `/repo/packages/api/.env.local` are eligible for Seatbelt deny rules

#### Scenario: Native does not discover Pi config
- **WHEN** `.pi/heimdall.json` exists under cwd but its contents are not passed through the JSON policy document
- **THEN** native macOS execution does not load or merge `.pi/heimdall.json`

#### Scenario: Native does not walk upward for fragments
- **WHEN** cwd is `/repo/subdir` and `/repo/.heimdall-deny` exists but `/repo/subdir/.heimdall-deny` does not exist
- **THEN** native macOS execution does not merge `/repo/.heimdall-deny`

### Requirement: Protected control paths under writable grants
The system SHALL prevent protected workspace control paths from becoming writable when broader writable patterns grant access to their parent directories.

#### Scenario: Existing protected control path stays readonly
- **WHEN** `filesystem.writable` broadly grants write access to cwd and `.git`, `.agents`, `.pi`, or an existing `.heimdall-*` path exists under cwd without an explicit writable grant
- **THEN** the protected control path remains readonly under the Seatbelt policy

#### Scenario: Missing named protected control path cannot be created
- **WHEN** `filesystem.writable` broadly grants write access to cwd and `.git`, `.agents`, `.pi`, `.heimdall-deny`, or `.heimdall-write` does not exist under cwd without an explicit writable grant
- **THEN** the sandboxed command cannot create that protected control path

#### Scenario: Missing Heimdall wildcard control path cannot persist
- **WHEN** `filesystem.writable` broadly grants write access to cwd and the sandboxed command attempts to create a new `.heimdall-*` path other than `.heimdall-deny` or `.heimdall-write`
- **THEN** the generated Seatbelt policy prevents that path from becoming writable or persistent on the host

#### Scenario: Broad writable cwd pattern grants regular writes
- **WHEN** `filesystem.writable` contains a broad cwd grant such as `.`
- **THEN** regular non-protected cwd descendants are writable while protected control paths remain protected

### Requirement: Virtual filesystem compatibility on macOS
The system SHALL accept `filesystem.virtual` entries on macOS for shared policy compatibility, SHALL ignore their supplied contents, and SHALL make each virtual target path readonly under Seatbelt.

#### Scenario: Virtual file content is not materialized
- **WHEN** a macOS policy contains `filesystem.virtual` mapping an absolute path to supplied content
- **THEN** the generated Seatbelt policy does not overlay or replace that path with the supplied content
- **AND** the command still runs with the rest of the sandbox policy applied

#### Scenario: Virtual target is not writable
- **WHEN** a macOS policy contains `filesystem.virtual` and a writable pattern would otherwise grant write access to the virtual target path
- **THEN** the generated Seatbelt policy prevents writes to that virtual target path

#### Scenario: Virtual target read follows normal read policy
- **WHEN** a macOS policy contains `filesystem.virtual`
- **THEN** reads from the virtual target path are allowed or denied according to the normal Seatbelt read policy for that path

#### Scenario: Virtual target aliases are protected
- **WHEN** a macOS virtual target has a canonical host spelling different from the requested spelling, such as `/etc/passwd` resolving through `/private/etc/passwd`
- **THEN** the generated Seatbelt write protection covers the requested path and its canonical host spelling

### Requirement: macOS network modes
The system SHALL map JSON network policy to Seatbelt network behavior on macOS.

#### Scenario: Host network remains available
- **WHEN** the JSON policy contains `network: "host"` or omits the network field
- **THEN** the generated Seatbelt policy allows outbound and inbound network access
- **AND** it allows the macOS system services required for DNS and TLS trust evaluation

#### Scenario: Network none blocks general network access
- **WHEN** the JSON policy contains `network: "none"`
- **THEN** the generated Seatbelt policy does not allow general outbound or inbound network access

### Requirement: macOS proc compatibility
The system SHALL accept proc-mount policy on macOS for shared config compatibility without changing Seatbelt behavior.

#### Scenario: No-proc policy is accepted on macOS
- **WHEN** a macOS caller supplies `proc: "none"` in a JSON policy
- **THEN** the CLI creates a valid execution request
- **AND** the Seatbelt policy generation ignores the proc setting

### Requirement: Existing runtime behavior is preserved on macOS
The system SHALL preserve Phase 1 execution behavior while adding macOS Seatbelt isolation.

#### Scenario: Environment filtering is preserved
- **WHEN** a macOS command runs through Seatbelt with `env.allow` or `env.deny`
- **THEN** the child environment follows the same allowlist/blocklist behavior as direct execution

#### Scenario: Dangerous macOS environment stripping is preserved
- **WHEN** a macOS command runs through Seatbelt
- **THEN** dangerous `DYLD_*` and macOS allocator logging environment keys are not passed to the child process

#### Scenario: Stdio behavior is preserved
- **WHEN** a macOS command runs through Seatbelt with inherited or piped stdio
- **THEN** stdout, stderr, and stdin follow the existing stdio policy behavior

#### Scenario: Exit status is preserved
- **WHEN** a macOS command running through Seatbelt exits with a non-zero status
- **THEN** the sandbox process exits with the same status

#### Scenario: Termination signals are forwarded
- **WHEN** the sandbox process receives `SIGHUP`, `SIGINT`, `SIGQUIT`, or `SIGTERM` while a Seatbelt command is running
- **THEN** the signal is forwarded to the running sandboxed command
