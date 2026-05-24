## Purpose

Provide Linux bubblewrap sandbox execution with filesystem isolation, network isolation, and compatibility across supported bubblewrap versions.

## Requirements

### Requirement: Linux bubblewrap execution
The system SHALL execute isolated Linux commands through bubblewrap instead of direct host execution whenever filesystem isolation or network isolation is requested.

#### Scenario: Filesystem isolation uses bubblewrap
- **WHEN** a Linux caller runs `heimdall-sandbox exec` with a policy containing `filesystem` controls
- **THEN** the command runs inside a bubblewrap namespace built from that filesystem policy

#### Scenario: Network isolation uses bubblewrap
- **WHEN** a Linux caller runs `heimdall-sandbox exec` with `network: "none"`
- **THEN** the command runs inside a bubblewrap namespace with host networking isolated

#### Scenario: Bubblewrap unavailable
- **WHEN** Linux isolation is requested and bubblewrap cannot be found or executed
- **THEN** the system exits with the sandbox misconfiguration code and does not run the requested command directly on the host

#### Scenario: User namespace is isolated
- **WHEN** Linux isolation is requested
- **THEN** the bubblewrap invocation includes user and process namespace isolation with `--unshare-user` and `--unshare-pid`

### Requirement: Bubblewrap launcher compatibility
The system SHALL discover a system `bwrap` executable from `PATH`, verify it is executable, probe whether it supports `--argv0`, and construct the inner Heimdall re-entry command in a way that works with both new and old bubblewrap versions.

#### Scenario: Bubblewrap supports argv0
- **WHEN** the discovered `bwrap` help output reports `--argv0` support
- **THEN** the bubblewrap invocation uses `--argv0` for the inner Heimdall re-entry command

#### Scenario: Bubblewrap lacks argv0
- **WHEN** the discovered `bwrap` executable does not support `--argv0`
- **THEN** the system omits `--argv0` and uses a compatible inner re-entry executable path instead of failing due to an unsupported bubblewrap flag

### Requirement: Missing concrete host-backed paths are handled before Bubblewrap mounts
Linux Bubblewrap planning SHALL skip confirmed-missing ordinary concrete host-backed operations when skipping does not weaken policy, SHALL enforce confirmed-missing denied paths that are creatable through writable directories, and SHALL preserve behavior for existing concrete paths. Missing-deny guard enforcement MAY use Bubblewrap-created empty mountpoint directories under writable parents as transient runtime artifacts, but those artifacts MUST be removed after sandbox execution when they remain empty. Paths whose existence is indeterminate MUST NOT be treated as missing.

#### Scenario: Missing concrete writable path is skipped
- **WHEN** `filesystem.writable` contains an absolute or tilde-expanded concrete host path that is confirmed not to exist
- **THEN** Linux Bubblewrap planning does not emit a writable bind mount for that missing path
- **AND** sandbox startup does not fail because of that missing path
- **AND** the host path is not created

#### Scenario: Existing concrete writable path remains writable
- **WHEN** `filesystem.writable` contains an absolute or tilde-expanded concrete host path that exists
- **THEN** Linux Bubblewrap planning maps that path writable according to existing writable behavior

#### Scenario: Missing concrete deny path outside writable coverage is skipped
- **WHEN** `filesystem.deny` contains an absolute or tilde-expanded concrete host path that is confirmed not to exist
- **AND** no effective writable directory target covers that path
- **THEN** Linux Bubblewrap planning does not emit a deny mask for that missing path
- **AND** sandbox startup does not fail because of that missing path
- **AND** the host path is not created

#### Scenario: Missing concrete deny path inside writable coverage remains denied
- **WHEN** `filesystem.deny` contains an absolute or tilde-expanded concrete host path that is confirmed not to exist
- **AND** an effective writable directory target covers that path
- **THEN** the sandboxed command cannot read host contents from that denied path
- **AND** the sandboxed command cannot create or write that denied path through the writable directory
- **AND** any empty Bubblewrap mountpoint artifact at the denied host path is removed after sandbox execution

#### Scenario: Existing concrete deny path remains masked
- **WHEN** `filesystem.deny` contains an absolute or tilde-expanded concrete host path that exists
- **THEN** Linux Bubblewrap planning masks that path according to existing deny behavior

#### Scenario: Existing concrete deny path still wins over writable
- **WHEN** `filesystem.deny` contains an absolute or tilde-expanded concrete host path that exists
- **AND** `filesystem.writable` grants write access to that path or one of its parents
- **THEN** Linux Bubblewrap planning masks the denied path instead of making it writable

#### Scenario: Missing restored-readonly path is skipped
- **WHEN** Linux Bubblewrap planning would restore a host-backed readonly path derived from filesystem policy
- **AND** that path is confirmed not to exist
- **THEN** Linux Bubblewrap planning skips that readonly mount
- **AND** the host path is not created

#### Scenario: Existing restored-readonly path remains readonly
- **WHEN** Linux Bubblewrap planning restores a host-backed readonly path derived from filesystem policy
- **AND** that path exists
- **THEN** Linux Bubblewrap planning maps that path readonly according to existing behavior

#### Scenario: Missing optional support mount source is skipped
- **WHEN** Linux Bubblewrap planning would emit an optional implementation-internal host-backed support mount from a concrete source path, such as selected platform read roots, selected `/etc` support paths, resolver targets, runtime sockets, agent sockets, home aliases, or optional sidecar libraries
- **AND** that source path is confirmed not to exist
- **THEN** Linux Bubblewrap planning skips that support mount
- **AND** sandbox startup does not fail because of that missing source path
- **AND** the host path is not created

#### Scenario: Missing deny guard mountpoint cleanup is bounded
- **WHEN** Linux Bubblewrap creates an empty mountpoint directory for a missing deny guard under a writable directory
- **THEN** cleanup targets only the confirmed-missing deny guard path recorded during policy materialization
- **AND** cleanup removes the path only when it is still an empty directory
- **AND** cleanup does not remove user file contents or non-empty directories

#### Scenario: Existing optional support mount source remains mapped
- **WHEN** Linux Bubblewrap planning would emit an optional implementation-internal host-backed support mount from a concrete source path, such as selected platform read roots, selected `/etc` support paths, resolver targets, runtime sockets, agent sockets, home aliases, or optional sidecar libraries
- **AND** that source path exists
- **THEN** Linux Bubblewrap planning maps that source according to existing support mount behavior

#### Scenario: Missing required startup path is rejected
- **WHEN** Linux Bubblewrap planning requires a host path for startup infrastructure, such as the current executable or inner re-entry executable
- **AND** that required path is missing
- **THEN** Linux Bubblewrap planning fails with sandbox misconfiguration before the child command runs

#### Scenario: Missing ancestor means the concrete path is missing
- **WHEN** an absolute or tilde-expanded concrete host path has an ancestor that is confirmed not to exist
- **THEN** the requested concrete path is treated as confirmed missing
- **AND** Linux Bubblewrap planning applies the relevant missing-path behavior

#### Scenario: Indeterminate paths are rejected
- **WHEN** the system cannot determine whether a concrete host-backed path exists because metadata, traversal, canonicalization, permissions, or another non-not-found filesystem check fails before final-component symlink classification can determine that the entry exists
- **THEN** Linux Bubblewrap planning fails with sandbox misconfiguration
- **AND** the path is not treated as confirmed missing

#### Scenario: Final symlink entries are existing paths
- **WHEN** a concrete host-backed path exists as a final path component symlink, including a dangling symlink
- **THEN** the path is not treated as confirmed missing
- **AND** existing path behavior is preserved

#### Scenario: Absolute paths under cwd are concrete paths
- **WHEN** Linux policy contains an absolute literal deny or writable path under `cwd`
- **AND** that path is confirmed missing
- **THEN** Linux Bubblewrap planning handles that path as a concrete host-backed path according to the missing-path scenarios
- **AND** it is not ignored as an unsynthesized relative pattern match

#### Scenario: Relative and pattern semantics are unchanged
- **WHEN** Linux policy contains cwd-relative or glob-style deny or writable entries
- **THEN** those entries keep the existing cwd-relative gitignore-style matching semantics
- **AND** missing pattern matches are not synthesized as concrete mount targets

#### Scenario: Special sandbox targets are unchanged
- **WHEN** Linux planning handles protected control paths or `filesystem.virtual` entries
- **THEN** those special sandbox targets keep their existing behavior
- **AND** they are not skipped merely because their sandbox destination is absent on the host

### Requirement: Readonly base filesystem
The system SHALL expose the sandbox filesystem as readonly by default and SHALL grant write access only through writable policy matches.

#### Scenario: Non-writable project file is readonly
- **WHEN** a Linux policy includes the project cwd in the readable sandbox view but no writable pattern matches a project file
- **THEN** the command can read that file but cannot modify it

#### Scenario: Writable pattern grants write access
- **WHEN** `filesystem.writable` contains a gitignore-style pattern that selects a cwd-relative file or subtree
- **THEN** the selected path is writable inside the sandbox

#### Scenario: Writable fragment is appended after JSON patterns
- **WHEN** `filesystem.writable` contains patterns and `<cwd>/.heimdall-write` exists
- **THEN** the system compiles a single writable matcher from the JSON patterns followed by the `.heimdall-write` lines

#### Scenario: Writable fragment is absent
- **WHEN** `<cwd>/.heimdall-write` does not exist
- **THEN** the writable matcher is compiled from the JSON `filesystem.writable` patterns alone

#### Scenario: Selected readonly etc support files
- **WHEN** the Linux readonly base filesystem is constructed
- **THEN** the system exposes only selected host `/etc` support paths required for DNS and TLS, including `/etc/resolv.conf`, `/etc/hosts`, `/etc/ssl`, and `/etc/ca-certificates` when they exist
- **AND** the system does not bind the full host `/etc` directory into the sandbox

### Requirement: Synthetic identity files
The system SHALL provide readonly synthetic `/etc/passwd` and `/etc/group` files by default so sandboxed commands do not see host user or group databases, while still allowing explicit `filesystem.virtual` entries to override those defaults.

#### Scenario: Synthetic passwd and group are present by default
- **WHEN** a Linux filesystem sandbox is constructed without explicit virtual entries for `/etc/passwd` or `/etc/group`
- **THEN** `/etc/passwd` contains a minimal `nobody` entry and `/etc/group` contains a minimal `nogroup` entry inside the sandbox

#### Scenario: Policy virtual identity file overrides default
- **WHEN** `filesystem.virtual` supplies `/etc/passwd` or `/etc/group`
- **THEN** the supplied readonly virtual file content is mounted at that path instead of the default synthetic content

### Requirement: Deny pattern masking
The system SHALL compile deny policy as ordered gitignore-style patterns and SHALL materialize selected existing paths into concrete bubblewrap masks.

#### Scenario: Deny pattern masks existing file
- **WHEN** `filesystem.deny` selects an existing file under cwd
- **THEN** the file is masked inside the bubblewrap namespace and the command cannot read its host contents

#### Scenario: Deny negation re-allows earlier deny pattern
- **WHEN** `filesystem.deny` contains a pattern followed by a later negated pattern that matches the same path
- **THEN** the later negated pattern removes that path from the deny mask set

#### Scenario: Deny fragment is appended after JSON patterns
- **WHEN** `filesystem.deny` contains patterns and `<cwd>/.heimdall-deny` exists
- **THEN** the system compiles a single deny matcher from the JSON patterns followed by the `.heimdall-deny` lines

#### Scenario: Deny wins over writable
- **WHEN** a path is selected by both the deny matcher and the writable matcher
- **THEN** the path is masked as unreadable instead of writable

### Requirement: Protected control paths under writable grants
The system SHALL prevent protected workspace control paths from becoming writable or persisting when broader writable patterns grant access to their parent directories.

#### Scenario: Existing protected control path stays readonly
- **WHEN** `filesystem.writable` broadly grants write access to cwd and `.git`, `.agents`, `.pi`, or an existing `.heimdall-*` path exists under cwd but is excluded or not selected by the writable matcher
- **THEN** the protected control path remains readonly inside the sandbox

#### Scenario: Missing named protected control path cannot be created
- **WHEN** `filesystem.writable` broadly grants write access to cwd and `.git`, `.agents`, `.pi`, `.heimdall-deny`, or `.heimdall-write` does not exist under cwd and is excluded or not selected by the writable matcher
- **THEN** the sandboxed command cannot create that protected control path

#### Scenario: Missing Heimdall wildcard control path does not persist
- **WHEN** `filesystem.writable` broadly grants write access to cwd and the sandboxed command creates a new `.heimdall-*` path other than `.heimdall-deny` or `.heimdall-write`
- **THEN** the path is removed before the sandbox execution completes so it does not persist on the host

#### Scenario: Broad writable cwd pattern grants regular writes
- **WHEN** `filesystem.writable` contains a broad cwd grant such as `.`
- **THEN** regular non-protected cwd descendants are writable while protected control paths remain protected

### Requirement: Cwd-relative pattern semantics
The system SHALL interpret filesystem deny and writable patterns relative to the policy cwd.

#### Scenario: Relative pattern matches cwd path
- **WHEN** cwd is `/repo` and `filesystem.deny` contains `**/.env*`
- **THEN** `/repo/.env` and `/repo/packages/api/.env.local` are eligible for deny masking

#### Scenario: Native does not discover Pi config
- **WHEN** `.pi/heimdall.json` exists under cwd but its contents are not passed through the JSON policy document
- **THEN** native execution does not load or merge `.pi/heimdall.json`

#### Scenario: Native does not walk upward for fragments
- **WHEN** cwd is `/repo/subdir` and `/repo/.heimdall-deny` exists but `/repo/subdir/.heimdall-deny` does not exist
- **THEN** native execution does not merge `/repo/.heimdall-deny`

### Requirement: Virtual filesystem files
The system SHALL support readonly virtual files from `filesystem.virtual` by mounting the supplied contents at absolute sandbox paths.

#### Scenario: Virtual file is readable
- **WHEN** `filesystem.virtual` maps `/etc/passwd` to supplied content
- **THEN** the sandboxed command reads the supplied content at `/etc/passwd`

#### Scenario: Virtual file is readonly
- **WHEN** a sandboxed command attempts to modify a file supplied by `filesystem.virtual`
- **THEN** the write is denied unless a separate writable policy explicitly grants a compatible writable path

#### Scenario: Relative virtual path is rejected
- **WHEN** `filesystem.virtual` contains a path that is not absolute
- **THEN** the system exits with the sandbox misconfiguration code before running the requested command

### Requirement: Proc mount compatibility
The system SHALL mount `/proc` inside the bubblewrap namespace by default when supported, SHALL support an explicit no-proc execution mode, and SHALL retry without `/proc` when a host or container rejects the proc mount during preflight.

#### Scenario: Proc is mounted when supported
- **WHEN** Linux isolation is requested and the proc preflight succeeds
- **THEN** the bubblewrap invocation mounts `/proc` inside the sandbox

#### Scenario: Proc mount failure falls back without proc
- **WHEN** Linux isolation is requested and a proc preflight fails with a known mount-permission or invalid-argument error
- **THEN** the requested command is retried without mounting `/proc` instead of failing solely because `/proc` could not be mounted

#### Scenario: No-proc mode skips proc mount
- **WHEN** the caller requests explicit no-proc execution mode
- **THEN** the bubblewrap invocation does not include `--proc /proc`

### Requirement: Linux network modes
The system SHALL map JSON network policy to bubblewrap network behavior on Linux.

#### Scenario: Host network remains available
- **WHEN** the JSON policy contains `network: "host"` or omits the network field
- **THEN** the Linux bubblewrap invocation does not request network namespace isolation

#### Scenario: Network none isolates host networking
- **WHEN** the JSON policy contains `network: "none"`
- **THEN** the Linux bubblewrap invocation requests network namespace isolation

### Requirement: Existing runtime behavior is preserved
The system SHALL preserve Phase 1 execution behavior while adding Linux namespace isolation.

#### Scenario: Environment filtering is preserved
- **WHEN** a Linux command runs through bubblewrap with `env.allow` or `env.deny`
- **THEN** the child environment follows the same allowlist/blocklist behavior as direct execution

#### Scenario: Stdio behavior is preserved
- **WHEN** a Linux command runs through bubblewrap with inherited or piped stdio
- **THEN** stdout, stderr, and stdin follow the existing stdio policy behavior

#### Scenario: Exit status is preserved
- **WHEN** a Linux command running through bubblewrap exits with a non-zero status
- **THEN** the sandbox process exits with the same status

#### Scenario: Termination signals are forwarded to the bubblewrap process group
- **WHEN** the sandbox process receives `SIGHUP`, `SIGINT`, `SIGQUIT`, or `SIGTERM` while bubblewrap is running the command
- **THEN** the signal is forwarded to the bubblewrap child process group, not just the immediate bubblewrap PID

#### Scenario: Signals during bubblewrap setup are not lost
- **WHEN** the sandbox process receives `SIGHUP`, `SIGINT`, `SIGQUIT`, or `SIGTERM` while bubblewrap signal forwarding is being installed
- **THEN** setup blocks and records the signal until forwarding is ready, then replays it to the bubblewrap child process group

#### Scenario: Bubblewrap dies when parent crashes
- **WHEN** the outer Heimdall process exits unexpectedly after spawning bubblewrap
- **THEN** the bubblewrap child is configured with `PR_SET_PDEATHSIG` so it receives `SIGTERM` instead of continuing unsupervised
