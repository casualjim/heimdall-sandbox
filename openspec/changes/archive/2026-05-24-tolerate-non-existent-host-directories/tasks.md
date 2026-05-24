## 1. Shared Policy Materialization

- [x] 1.1 Add a concrete-path existence classifier for absolute and tilde-expanded paths: existing, confirmed-missing, and indeterminate/error.
- [x] 1.2 Add classifier tests for absolute and tilde-expanded inputs.
- [x] 1.3 Add classifier tests proving final-component symlinks, including dangling symlinks, classify as existing.
- [x] 1.4 Add classifier tests proving confirmed-missing ancestors classify the requested concrete path as missing, while traversal metadata, canonicalization, permission, and other non-not-found errors classify as indeterminate/error.
- [x] 1.5 Preserve existing external deny and writable target materialization for paths classified as existing.
- [x] 1.6 Skip confirmed-missing writable paths so they do not become host-backed writable targets.
- [x] 1.7 Skip confirmed-missing restored-readonly paths so they do not become host-backed readonly targets.
- [x] 1.8 Skip confirmed-missing deny paths when no effective writable directory target covers them.
- [x] 1.9 Record confirmed-missing deny paths as Linux/macOS missing deny guards when an effective writable directory target covers them.
- [x] 1.10 Define writable coverage using existing effective writable directory targets only; writable file targets do not cover descendants.
- [x] 1.11 Add tests proving literal absolute paths under `cwd` are classified as concrete paths before cwd-relative matcher conversion, including missing deny under writable cwd.
- [x] 1.12 Preserve cwd-relative and glob-style deny/writable pattern semantics.
- [x] 1.13 Preserve protected-control target materialization as a separate special case.

## 2. Linux Bubblewrap Planning

- [x] 2.1 Add plan tests proving missing ordinary writable and restored-readonly host-backed paths are skipped and do not emit bind or readonly-bind operations.
- [x] 2.2 Add Linux planning tests with tilde-expanded missing and existing paths.
- [x] 2.3 Add plan tests proving existing writable and restored-readonly host-backed paths still emit existing bind or readonly-bind operations.
- [x] 2.4 Add plan tests proving missing deny paths outside writable coverage are skipped without emitting masks.
- [x] 2.5 Add plan/execution tests proving missing deny guards under writable coverage prevent host-content reads and prevent create/write through the writable directory.
- [x] 2.6 Implement missing deny guards with Bubblewrap ordered staged mountpoint/synthetic resource handling; allow Bubblewrap-created empty mountpoint artifacts under writable parents when they are removed after sandbox execution.
- [x] 2.7 Prove with tests that Linux missing deny guards block create/write attempts and do not leave the denied host path behind after bounded cleanup.
- [x] 2.8 Verify existing denied paths still mask as before and still win over writable grants.
- [x] 2.9 Preserve virtual-file mounts and protected-control masks when their sandbox destinations are absent.
- [x] 2.10 Inventory Linux support mounts as required or optional in code comments or tests.
- [x] 2.11 Update optional support mount builders to skip confirmed-missing sources while preserving existing sources.
- [x] 2.12 Add execution regressions proving missing writable, restored-readonly, and optional-support paths do not fail sandbox startup, the command runs, and no host path is created.
- [x] 2.13 Add plan tests proving existing optional support mount sources remain mapped.
- [x] 2.14 Add plan tests proving missing required support paths fail with sandbox misconfiguration.
- [x] 2.15 Add plan tests proving indeterminate/error path states fail with sandbox misconfiguration instead of being treated as missing.
- [x] 2.16 Add plan tests proving indeterminate optional support mount sources fail with sandbox misconfiguration instead of being skipped.

## 3. macOS Seatbelt Planning

- [x] 3.1 Update Seatbelt policy generation to consume missing deny guards and emit literal deny rules that make those paths unreadable and not writable through broader writable grants.
- [x] 3.2 Add policy-generation tests with tilde-expanded missing and existing paths.
- [x] 3.3 Add policy-generation tests proving missing writable paths are not granted writable access and remain absent on the host.
- [x] 3.4 Add policy-generation tests proving existing writable paths still grant writable access.
- [x] 3.5 Add policy-generation tests proving missing deny paths outside writable coverage do not add deny rules solely for those missing paths, do not grant writable access, and remain absent on the host.
- [x] 3.6 Add policy-generation tests proving missing deny paths under writable coverage produce Seatbelt rules that make the path unreadable and not writable while leaving the host path absent.
- [x] 3.7 Add policy-generation tests proving existing deny paths remain denied and still win over writable grants.
- [x] 3.8 Add tests proving missing ancestors are treated as confirmed-missing paths and indeterminate/error path states fail with sandbox misconfiguration instead of being treated as missing.
- [x] 3.9 Add tests proving macOS relative/glob semantics, protected-control behavior, and virtual-file behavior remain unchanged.
- [x] 3.10 Add tests proving Seatbelt remains policy-only and does not add Linux-style mount behavior.

## 4. Regression Coverage

- [x] 4.1 Add Linux execution regression for a missing concrete deny path such as `~/.vim` outside writable coverage: sandbox starts, command runs, and host path is not created.
- [x] 4.2 Add Linux regression for a mixed deny list: existing path is denied, missing path outside writable coverage is tolerated.
- [x] 4.3 Add Linux regression for a missing deny path under a writable directory: the sandboxed command cannot read host contents from the denied path, cannot create or write the denied path, and no empty Bubblewrap mountpoint artifact is left behind after sandbox execution.
- [x] 4.4 Add regression coverage proving missing writable/restored-readonly/optional-support paths do not create host paths or access-granting sandbox paths.
- [x] 4.5 Add regression coverage proving cwd-relative/glob deny and writable semantics remain unchanged.
- [x] 4.6 Add regression coverage proving missing pattern matches are not synthesized as concrete mount targets.
- [x] 4.7 Add regression coverage proving protected-control and virtual-file behavior is unchanged.

## 5. Verification

- [x] 5.1 Add a short code-adjacent note or test comment explaining the rule: skip confirmed-missing ordinary host-backed paths only when skipping does not weaken policy; enforce missing-deny-under-writable guards with staged Bubblewrap mounts and bounded empty mountpoint cleanup.
- [x] 5.2 Run `mise format`.
- [x] 5.3 Run `mise run --force test`.
