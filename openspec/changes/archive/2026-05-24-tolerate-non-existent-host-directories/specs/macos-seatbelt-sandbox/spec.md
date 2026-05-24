## ADDED Requirements

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
