## 1. Shared Policy Materialization

- [ ] 1.1 Add a concrete-path existence classifier for absolute and tilde-expanded paths: existing, confirmed-missing, and indeterminate/error.
- [ ] 1.2 Add classifier tests for absolute and tilde-expanded inputs.
- [ ] 1.3 Add classifier tests proving final-component symlinks, including dangling symlinks, classify as existing.
- [ ] 1.4 Add classifier tests proving confirmed-missing ancestors classify the requested concrete path as missing, while traversal metadata, canonicalization, permission, and other non-not-found errors classify as indeterminate/error.
- [ ] 1.5 Preserve existing external deny and writable target materialization for paths classified as existing.
- [ ] 1.6 Skip confirmed-missing writable paths so they do not become host-backed writable targets.
- [ ] 1.7 Skip confirmed-missing restored-readonly paths so they do not become host-backed readonly targets.
- [ ] 1.8 Skip confirmed-missing deny paths when no effective writable directory target covers them.
- [ ] 1.9 Record confirmed-missing deny paths as Linux/macOS missing deny guards when an effective writable directory target covers them.
- [ ] 1.10 Define writable coverage using existing effective writable directory targets only; writable file targets do not cover descendants.
- [ ] 1.11 Add tests proving literal absolute paths under `cwd` are classified as concrete paths before cwd-relative matcher conversion, including missing deny under writable cwd.
- [ ] 1.12 Preserve cwd-relative and glob-style deny/writable pattern semantics.
- [ ] 1.13 Preserve protected-control target materialization as a separate special case.

## 2. Linux Bubblewrap Planning

- [ ] 2.1 Add plan tests proving missing ordinary writable and restored-readonly host-backed paths are skipped and do not emit bind or readonly-bind operations.
- [ ] 2.2 Add Linux planning tests with tilde-expanded missing and existing paths.
- [ ] 2.3 Add plan tests proving existing writable and restored-readonly host-backed paths still emit existing bind or readonly-bind operations.
- [ ] 2.4 Add plan tests proving missing deny paths outside writable coverage are skipped without emitting masks.
- [ ] 2.5 Add plan/execution tests proving missing deny guards under writable coverage prevent host-content reads and prevent create/write through the writable directory.
- [ ] 2.6 Implement missing deny guards with Bubblewrap ordered staged mountpoint/synthetic resource handling so the guard is sandbox-only and the host path is not created.
- [ ] 2.7 Prove with tests that Linux missing deny guards do not create the denied host path.
- [ ] 2.8 Verify existing denied paths still mask as before and still win over writable grants.
- [ ] 2.9 Preserve virtual-file mounts and protected-control masks when their sandbox destinations are absent.
- [ ] 2.10 Inventory Linux support mounts as required or optional in code comments or tests.
- [ ] 2.11 Update optional support mount builders to skip confirmed-missing sources while preserving existing sources.
- [ ] 2.12 Add execution regressions proving missing writable, restored-readonly, and optional-support paths do not fail sandbox startup, the command runs, and no host path is created.
- [ ] 2.13 Add plan tests proving existing optional support mount sources remain mapped.
- [ ] 2.14 Add plan tests proving missing required support paths fail with sandbox misconfiguration.
- [ ] 2.15 Add plan tests proving indeterminate/error path states fail with sandbox misconfiguration instead of being treated as missing.
- [ ] 2.16 Add plan tests proving indeterminate optional support mount sources fail with sandbox misconfiguration instead of being skipped.

## 3. macOS Seatbelt Planning

- [ ] 3.1 Update Seatbelt policy generation to consume missing deny guards and emit literal deny rules that make those paths unreadable and not writable through broader writable grants.
- [ ] 3.2 Add policy-generation tests with tilde-expanded missing and existing paths.
- [ ] 3.3 Add policy-generation tests proving missing writable paths are not granted writable access and remain absent on the host.
- [ ] 3.4 Add policy-generation tests proving existing writable paths still grant writable access.
- [ ] 3.5 Add policy-generation tests proving missing deny paths outside writable coverage do not add deny rules solely for those missing paths, do not grant writable access, and remain absent on the host.
- [ ] 3.6 Add policy-generation tests proving missing deny paths under writable coverage produce Seatbelt rules that make the path unreadable and not writable while leaving the host path absent.
- [ ] 3.7 Add policy-generation tests proving existing deny paths remain denied and still win over writable grants.
- [ ] 3.8 Add tests proving missing ancestors are treated as confirmed-missing paths and indeterminate/error path states fail with sandbox misconfiguration instead of being treated as missing.
- [ ] 3.9 Add tests proving macOS relative/glob semantics, protected-control behavior, and virtual-file behavior remain unchanged.
- [ ] 3.10 Add tests proving Seatbelt remains policy-only and does not add Linux-style mount behavior.

## 4. Regression Coverage

- [ ] 4.1 Add Linux execution regression for a missing concrete deny path such as `~/.vim` outside writable coverage: sandbox starts, command runs, and host path is not created.
- [ ] 4.2 Add Linux regression for a mixed deny list: existing path is denied, missing path outside writable coverage is tolerated.
- [ ] 4.3 Add Linux regression for a missing deny path under a writable directory: the sandboxed command cannot read host contents from the denied path, cannot create or write the denied path, and no host path is created.
- [ ] 4.4 Add regression coverage proving missing writable/restored-readonly/optional-support paths do not create host paths or access-granting sandbox paths.
- [ ] 4.5 Add regression coverage proving cwd-relative/glob deny and writable semantics remain unchanged.
- [ ] 4.6 Add regression coverage proving missing pattern matches are not synthesized as concrete mount targets.
- [ ] 4.7 Add regression coverage proving protected-control and virtual-file behavior is unchanged.

## 5. Verification

- [ ] 5.1 Add a short code-adjacent note or test comment explaining the rule: skip confirmed-missing ordinary host-backed paths only when skipping does not weaken policy; enforce missing-deny-under-writable guards without creating host paths.
- [ ] 5.2 Run `mise format`.
- [ ] 5.3 Run `mise run --force test`.
