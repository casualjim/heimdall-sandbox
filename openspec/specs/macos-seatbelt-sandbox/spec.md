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

### Requirement: Missing concrete host paths preserve Seatbelt policy intent
macOS Seatbelt policy generation SHALL tolerate confirmed-missing concrete host paths without creating host paths and SHALL preserve deny-over-writable behavior for missing deny paths covered by writable directories. Paths whose existence is indeterminate MUST NOT be treated as missing.

#### Scenario: Missing writable path is not granted
- **WHEN** `filesystem.writable` contains an absolute or tilde-expanded concrete host path that is confirmed not to exist
- **THEN** Seatbelt policy generation does not grant that missing path as writable
- **AND** the host path is not created

#### Scenario: Existing writable path remains writable
- **WHEN** `filesystem.writable` contains an absolute or tilde-expanded concrete host path that exists
- **THEN** Seatbelt policy generation grants writable access according to existing writable behavior

#### Scenario: Missing deny path outside writable coverage does not require existence
- **WHEN** `filesystem.deny` contains an absolute or tilde-expanded concrete host path that is confirmed not to exist
- **AND** no effective writable directory target covers that path
- **THEN** Seatbelt policy generation does not add a deny rule solely for that missing path
- **AND** Seatbelt policy generation does not grant writable access to that missing path
- **AND** the host path is not created

#### Scenario: Missing deny path inside writable coverage remains denied
- **WHEN** `filesystem.deny` contains an absolute or tilde-expanded concrete host path that is confirmed not to exist
- **AND** an effective writable directory target covers that path
- **THEN** Seatbelt policy generation makes that path unreadable and not writable through the writable grant
- **AND** the host path is not created

#### Scenario: Existing deny path remains denied
- **WHEN** `filesystem.deny` contains an absolute or tilde-expanded concrete host path that exists
- **THEN** Seatbelt policy generation denies that path according to existing deny behavior

#### Scenario: Existing deny path still wins over writable
- **WHEN** `filesystem.deny` contains an absolute or tilde-expanded concrete host path that exists
- **AND** `filesystem.writable` grants write access to that path or one of its parents
- **THEN** Seatbelt policy generation makes the denied path unreadable and not writable

#### Scenario: Absolute paths under cwd are concrete paths
- **WHEN** macOS policy contains an absolute literal deny or writable path under `cwd`
- **AND** that path is confirmed missing
- **THEN** Seatbelt policy generation handles that path as a concrete host path according to the missing-path scenarios
- **AND** it is not ignored as an unsynthesized relative pattern match

#### Scenario: Missing ancestor means the concrete path is missing
- **WHEN** an absolute or tilde-expanded concrete host path has an ancestor that is confirmed not to exist
- **THEN** the requested concrete path is treated as confirmed missing
- **AND** Seatbelt policy generation applies the relevant missing-path behavior

#### Scenario: Indeterminate paths are rejected
- **WHEN** the system cannot determine whether a concrete host path exists because metadata, traversal, canonicalization, permissions, or another non-not-found filesystem check fails before final-component symlink classification can determine that the entry exists
- **THEN** Seatbelt planning fails with sandbox misconfiguration
- **AND** the path is not treated as confirmed missing

#### Scenario: Final symlink entries are existing paths
- **WHEN** a concrete host path exists as a final path component symlink, including a dangling symlink
- **THEN** the path is not treated as confirmed missing
- **AND** existing path behavior is preserved

#### Scenario: Relative and pattern semantics are unchanged
- **WHEN** macOS policy contains cwd-relative or glob-style deny or writable entries
- **THEN** those entries keep the existing cwd-relative gitignore-style matching semantics
- **AND** missing pattern matches are not synthesized as concrete policy targets

#### Scenario: Special sandbox targets are unchanged
- **WHEN** Seatbelt policy generation handles protected control paths or `filesystem.virtual` entries
- **THEN** those special sandbox targets keep their existing behavior
- **AND** they are not skipped merely because their sandbox destination is absent on the host

#### Scenario: Seatbelt remains policy-only
- **WHEN** Seatbelt policy generation handles a confirmed-missing concrete host path
- **THEN** it does not add Linux-style bind, readonly-bind, or mask behavior for that path

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

### Requirement: PATH-discovered platform read roots preserve macOS runtime access
macOS Seatbelt policy generation SHALL derive bounded platform read roots from existing absolute entries in the planner process `PATH` when those entries are under supported platform prefixes such as `/opt/homebrew` or `/usr/local`, so toolchain/runtime directories needed to launch configured commands remain readable without granting arbitrary PATH directories. Missing PATH-derived platform roots SHALL be skipped, and paths that cannot be inspected SHALL fail planning rather than being silently granted or skipped.

#### Scenario: Existing supported PATH roots are readable
- **WHEN** the planner process `PATH` contains an absolute directory under a supported platform prefix
- **AND** the derived platform root exists
- **THEN** Seatbelt policy generation grants read access to that platform root according to macOS runtime support behavior

#### Scenario: Unsupported PATH roots are ignored
- **WHEN** the planner process `PATH` contains an absolute directory outside supported platform prefixes
- **THEN** Seatbelt policy generation does not grant read access solely because of that PATH entry

#### Scenario: Missing PATH-derived platform roots are skipped
- **WHEN** the planner process `PATH` contains an absolute directory whose supported platform root is confirmed missing
- **THEN** Seatbelt policy generation does not grant read access for that missing root

#### Scenario: Indeterminate PATH-derived platform roots are rejected
- **WHEN** the planner process `PATH` contains an absolute directory whose supported platform root cannot be inspected
- **THEN** Seatbelt planning fails with sandbox misconfiguration

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
