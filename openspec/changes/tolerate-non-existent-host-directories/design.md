## Context

Native filesystem isolation is built from shared policy materialization plus platform-specific enforcement:

- `FilesystemPolicyMaterializer` expands deny/writable entries, walks cwd-relative pattern matches, and produces materialized filesystem targets.
- Linux Bubblewrap planning converts materialized targets into bind, readonly-bind, virtual-file, and empty-mask operations.
- macOS Seatbelt planning converts materialized targets into SBPL allow/deny rules and derives bounded runtime read roots from existing absolute `PATH` entries under supported platform prefixes so command/toolchain support directories remain readable.

The failure happens when a confirmed-missing concrete host path reaches Linux Bubblewrap as a host-backed mount or mask operation. Bubblewrap startup can then fail before the child command runs. The fix is to avoid host-backed operations for missing host paths while preserving deny-over-writable semantics.

## Scope

This change covers concrete absolute host paths after tilde expansion, including literal absolute paths under `cwd`. Existing cwd-relative and glob-style pattern semantics remain unchanged for relative or non-literal pattern entries. Existing paths discovered by the current cwd walk continue to behave as today. Missing relative pattern matches are not synthesized.

## Design Rules

- Existing concrete paths keep existing behavior.
- Confirmed-missing ordinary writable and restored-readonly host-backed paths are skipped.
- Confirmed-missing deny paths outside effective writable directory coverage are skipped.
- Confirmed-missing deny paths inside effective writable directory coverage are enforced as deny guards.
- Indeterminate paths fail planning with sandbox misconfiguration.
- A final path component that exists as a symlink, including a dangling symlink, is existing rather than missing.
- Protected-control targets and virtual-file targets keep their current special behavior.
- The implementation must not create missing host paths on the real host filesystem.
- The implementation must not rely on post-execution cleanup of arbitrary user paths.

## Concrete Path Classification

Add a shared classifier for concrete absolute paths after tilde expansion. Literal absolute paths under `cwd` are classified as concrete paths before they are converted to cwd-relative matcher patterns, so `/cwd/missing` is handled by this change while relative entries such as `missing` keep existing pattern semantics.


- `Existing`: the final path entry exists. A final-component symlink, including a dangling symlink, is `Existing` because the host directory entry exists and current policy behavior must be preserved.
- `Missing`: the final path entry is confirmed absent, or any ancestor is confirmed absent with a not-found result.
- `Indeterminate`: existence cannot be determined because metadata, traversal, canonicalization, permissions, or another non-not-found filesystem check failed.

Classification checks ancestors first, then the final component with symlink-aware metadata (`symlink_metadata`/`lstat` semantics). If an ancestor is confirmed absent, classify the requested concrete path as `Missing`. If the final component exists as a directory entry, including a dangling symlink, classify it as `Existing` before attempting canonicalization of the full path. Traversal failures before the final component are `Indeterminate` only for permission, I/O, symlink traversal, or other non-not-found failures.

Only `Missing` can be skipped or converted into a missing deny guard. `Existing` keeps current behavior. `Indeterminate` returns sandbox misconfiguration.

## Writable Coverage

A missing deny path is covered by writable policy when it is equal to or below an effective writable directory target that exists. Writable file targets do not cover descendants.

Coverage is computed from materialized writable targets after expansion and existence classification. Literal absolute writable paths under `cwd` are classified as concrete paths; relative/glob writable entries continue to use existing walk-and-match behavior and do not synthesize missing matches.

## Shared Materialization

Shared materialization should produce:

- ordinary deny targets for existing denied paths;
- ordinary writable targets for existing writable paths;
- restored-readonly targets for existing negated/restored paths;
- skipped missing ordinary writable/restored-readonly paths;
- skipped missing deny paths outside writable coverage;
- missing deny guards for confirmed-missing deny paths inside writable coverage.

A missing deny guard is a policy enforcement target, not a host-backed source path.

## Linux Bubblewrap Strategy

Linux planning handles materialized targets as follows:

- Existing deny, writable, restored-readonly, protected-control, and virtual-file behavior remains unchanged.
- Confirmed-missing ordinary writable mounts are not emitted.
- Confirmed-missing restored-readonly mounts are not emitted.
- Confirmed-missing optional support mounts are not emitted.
- Confirmed-missing deny paths outside writable coverage are not emitted.
- Missing deny guards inside writable coverage are enforced with sandbox-only staged synthetic mounts.

### Staged synthetic prevention for missing deny guards

For a missing deny guard at `<writable-parent>/denied`, Linux uses Bubblewrap argument ordering and existing synthetic resource helpers to construct the denied path in sandbox namespace state, then masks it above the writable parent view. The implementation must use Bubblewrap sandbox construction primitives such as staged mountpoints, tmpfs, synthetic data/file resources, and empty file/directory masks; it must not create `<writable-parent>/denied` on the real host filesystem.

The required outcome is:

1. the effective writable parent remains available with its existing writable behavior;
2. the denied missing child is represented only inside the sandbox namespace;
3. the final layer at the denied child path prevents host-data reads and prevents creating or writing that path through the writable parent;
4. the denied child path remains absent on the host after planning and execution.

Because no host object exists at the denied path, the Linux guard is not required to make every possible read/open syscall fail; it is required to prevent host content exposure and block creation/writes through the writable parent. An empty synthetic mask is acceptable when it satisfies those outcomes.

The existing staged mountpoint pattern in Linux planning is the integration point. The implementation may extend that staging logic for this inverse case, but tests must prove the host path is not created and the guard remains effective after writable parent setup.

## Linux Support Mounts

Support mounts are split into required and optional categories:

- Required runtime infrastructure:
  - current executable / inner re-entry executable;
  - any path required for the sandbox command itself to start.
  Missing or indeterminate required infrastructure fails as sandbox misconfiguration.
- Optional host convenience/support paths:
  - platform read roots from `platform_read_roots()`;
  - home aliases used for readonly home visibility;
  - resolver symlink targets;
  - runtime sockets such as D-Bus;
  - agent sockets discovered from environment variables or runtime dirs;
  - optional sidecar runtime libraries discovered by `runtime_libraries()`.
  Confirmed-missing optional support paths are skipped. Existing optional support paths remain mapped as today. Indeterminate optional support paths fail as sandbox misconfiguration rather than being treated as missing.

## macOS Seatbelt Strategy

macOS does not need synthetic directories or mount staging because Seatbelt is policy-based.

- Existing absolute platform roots derived from supported `PATH` prefixes such as `/opt/homebrew` and `/usr/local` remain readable so sandboxed commands can load runtime/toolchain support files; unsupported PATH entries are ignored, confirmed-missing supported roots are skipped, and indeterminate supported roots fail planning.
- Missing writable targets are not granted as writable.
- Missing deny paths outside writable coverage do not require the path to exist and do not grant access.
- Missing deny guards inside writable coverage emit literal deny rules that make the path unreadable and not writable through the broader writable grant.
- Existing deny and writable paths keep current Seatbelt behavior.
- Seatbelt policy generation must not add Linux-style bind, readonly-bind, or mask behavior.

## Alternatives Considered

- **Skip every missing deny path.** Rejected because a writable directory could create a path the policy explicitly denies.
- **Reject missing deny paths under writable coverage.** Rejected because deny-over-writable is an existing policy rule and Bubblewrap can construct sandbox namespace state using ordered synthetic/staged mounts.
- **Delete created paths after execution.** Rejected because sandbox ownership of arbitrary paths cannot be proven and cleanup can race with host processes.
- **Create missing host paths before sandbox startup.** Rejected because sandbox planning must not mutate the host to make policy enforcement possible.
- **Fail on all missing concrete paths.** Rejected because shared policies commonly include optional host paths.

## Risks / Trade-offs

- Linux missing-deny guards require careful Bubblewrap argument ordering. Regression tests must prove the guard blocks access and no host path is created.
- The synthetic Linux guard may make an explicitly denied missing path observable inside the sandbox as denied/synthetic state. That is acceptable because the path is explicitly denied and the host path remains absent.
- macOS can enforce the same policy intent without staging because Seatbelt rules do not require mount destinations.
- Existence checks must distinguish confirmed missing from indeterminate errors so sensitive existing paths are not silently skipped.
