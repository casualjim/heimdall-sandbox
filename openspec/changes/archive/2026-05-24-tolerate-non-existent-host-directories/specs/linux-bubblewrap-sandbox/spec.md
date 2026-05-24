## ADDED Requirements

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
