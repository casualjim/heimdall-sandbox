## Why

heimdall-sandbox policies can include concrete host paths that are absent on the current machine, such as optional dotfiles or configuration directories. Native sandbox startup should not fail just because a policy mentions a missing path that is valid on another host.

Shared policies should work across hosts with different local filesystem layouts. Missing concrete host paths should be tolerated when no host object exists, while existing host paths must continue to receive the protections or access requested by policy. Deny rules must continue to win over writable grants.

## What Changes

- Native sandbox behavior will tolerate confirmed-missing concrete host paths without creating those paths on the host.
- macOS Seatbelt policy generation will preserve dynamic runtime read access for existing supported platform roots discovered from `PATH`.
- Existing concrete host paths will continue to be denied, writable, restored readonly, or mapped according to existing behavior.
- Confirmed-missing denied paths remain denied when they are covered by writable access.
- Relative, glob, and pattern-based policy entries will keep their existing semantics.
- Protected workspace control path behavior and virtual file behavior will remain unchanged.

## Non-Goals

- Changing the filesystem policy JSON shape.
- Changing existing glob, relative, or pattern matching semantics.
- Creating missing ordinary host paths during sandbox planning.
- Cleaning up arbitrary user paths after sandbox execution.
- Weakening protections for existing concrete host paths.
- Adding Linux-style mount behavior to macOS Seatbelt.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `linux-bubblewrap-sandbox`: tolerate confirmed-missing concrete host paths while preserving existing deny, writable, restored-readonly, protected-control, and virtual-file behavior.
- `macos-seatbelt-sandbox`: tolerate confirmed-missing concrete host paths while preserving Seatbelt deny and writable policy behavior.

## Impact

- Affects native filesystem policy planning for Linux Bubblewrap and macOS Seatbelt.
- Improves compatibility for shared policies across hosts with different optional paths.
- Requires regression coverage for missing, existing, and mixed concrete host paths; missing denied paths under writable directories; unchanged relative/pattern behavior; and preserved protected-control and virtual-file behavior.
