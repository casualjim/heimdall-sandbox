//! Landlock-based read-rejection enforcement for denied filesystem paths.
//!
//! Mount namespaces can hide denied paths behind empty overlay mounts, but they
//! cannot reject access: a masked directory still lists as empty with exit code 0.
//! Landlock (LSM, Linux >= 5.13) makes every non-granted read fail with EACCES,
//! which is what callers need to distinguish "policy refusal" from "path does not
//! exist".
//!
//! The official `landlock` crate drives the kernel interface on Linux; its
//! compatibility machinery replaces hand-rolled ABI negotiation, so the dependency
//! is target-gated to Linux. Handled access rights deliberately exclude write and
//! file-management families: writability stays owned by the bubblewrap mounts, so
//! this module only sharpens how reads fail. Rule sets are purely additive over an
//! empty-by-default universe, so callers enumerate the grant universe (see plan.rs)
//! and this module applies it.

use std::path::PathBuf;

#[cfg(target_os = "linux")]
use landlock::{AccessFs, PathBeneath, PathFd};
#[cfg(target_os = "linux")]
use std::io as linux_io;

/// Kernel support state for the Landlock read-rejection axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockSupport {
    /// Landlock is usable; denied reads fail with EACCES instead of being hidden.
    Available,
    /// Landlock is not usable; callers must fall back to mount masking.
    Unavailable(LandlockUnavailableReason),
}

/// Why Landlock could not be enabled on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockUnavailableReason {
    /// Kernel predates Landlock (< 5.13) or the LSM is disabled.
    UnsupportedKernel,
    /// Self-restriction was refused despite version support (broken stacking).
    RestrictRefused,
}

/// Probe Landlock support for this host.
///
/// Creates and drops a real ruleset so consumers observe actual kernel capability
/// rather than a version number.
#[cfg(target_os = "linux")]
#[must_use]
pub fn probe_support() -> LandlockSupport {
    use landlock::{AccessFs, Compatible, Ruleset, RulesetAttr, make_bitflags};

    const HANDLED_ACCESS: landlock::BitFlags<AccessFs> =
        make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir | Refer});

    // Creating a ruleset exercises the real syscalls: ENOSYS/EOPNOTSUPP here means
    // enforcement is impossible and callers must keep mount masking.
    if Ruleset::default()
        .set_compatibility(landlock::CompatLevel::BestEffort)
        .handle_access(HANDLED_ACCESS)
        .and_then(|ruleset| ruleset.create())
        .is_ok()
    {
        LandlockSupport::Available
    } else {
        LandlockSupport::Unavailable(LandlockUnavailableReason::UnsupportedKernel)
    }
}

/// Non-Linux hosts have no Landlock: callers keep mount masking.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn probe_support() -> LandlockSupport {
    LandlockSupport::Unavailable(LandlockUnavailableReason::UnsupportedKernel)
}

/// Apply a Landlock ruleset granting the handled reads beneath each root.
///
/// Every path outside the given roots becomes inaccessible to this process and to
/// every child it subsequently spawns; Landlock state is inherited across fork and
/// execve and can only ever shrink. Roots in traverse_only receive execute-only
/// rules (or, when absent themselves, on their nearest surviving ancestor) so path
/// lookups keep resolving without exposing listings or contents: glibc execvp(3)
/// aborts its PATH search at the first EACCES candidate, which ancestor grants
/// convert into plain ENOENT skips instead. Writing remains governed by the mount
/// namespace setup and is intentionally not narrowed here.
///
/// # Errors
///
/// Returns an I/O error identifying the failing stage and root. Failure is fatal by
/// contract: a partial restriction would silently weaken the requested policy.
#[cfg(target_os = "linux")]
pub fn restrict_fs_read_universe(
    roots: &[PathBuf],
    traverse_only: &[PathBuf],
) -> std::io::Result<()> {
    use landlock::{AccessFs, Compatible, PathFd, make_bitflags};
    use landlock::{Ruleset, RulesetAttr, RulesetCreatedAttr as _, RulesetStatus};

    if roots.is_empty() {
        return Err(std::io::Error::other(
            "landlock read enforcement requires at least one granted root",
        ));
    }

    // Refer must be handled AND granted: Landlock denies link(2)/rename(2)
    // reparenting with EXDEV for every enforced ruleset unless this right is
    // explicitly handled and allowed on both parent directories. Without it,
    // every cross-directory hardlink inside a writable workspace fails
    // (cargo's incremental working copy is the loudest victim).
    // Refer must be handled AND granted: Landlock denies link(2)/rename(2)
    // reparenting with EXDEV for every enforced ruleset unless this right is
    // explicitly handled and allowed on both parent directories. Without it,
    // every cross-directory hardlink inside a writable workspace fails
    // (cargo's incremental working copy is the loudest victim).
    const HANDLED_ACCESS: landlock::BitFlags<AccessFs> =
        make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir | Refer});
    // Traversal-only ancestors must also open O_RDONLY: tools that walk their
    // cwd's parents at startup (bun 1.3.14's current-directory check, realpath
    // implementations) abort on EACCES. Files beneath stay ReadFile-denied.
    const EXECUTE_AND_READ_DIR: landlock::BitFlags<AccessFs> =
        make_bitflags!(AccessFs::{Execute | ReadDir});

    let open_root = |path: &std::path::Path| -> std::io::Result<PathFd> {
        PathFd::new(path).map_err(|error| {
            // Preserve the OS kind: NotFound routes callers into the
            // lookup-grant fallback instead of failing the launch.
            let source = match error {
                landlock::PathFdError::OpenCall { source, .. } => source,
                other => io_error(other.to_string()),
            };
            std::io::Error::new(
                source.kind(),
                format!(
                    "failed to open landlock grant root {}: {source}",
                    path.display()
                ),
            )
        })
    };

    let mut created = Ruleset::default()
        .set_compatibility(landlock::CompatLevel::BestEffort)
        .handle_access(HANDLED_ACCESS)
        .and_then(|ruleset| ruleset.create())
        .map_err(|error| io_error(format!("failed to create landlock ruleset: {error}")))?;

    for root in roots {
        match open_root(root) {
            Ok(parent) => add_rule(&mut created, parent, HANDLED_ACCESS)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Lookup-grant fallback: a vanished root narrows to execute-only on
                // its nearest surviving ancestor instead of aborting the launch.
                let mut narrowed = Err(io_error(format!(
                    "landlock grant root {} vanished before any rule landed",
                    root.display()
                )));
                for ancestor in root.ancestors().skip(1) {
                    match PathFd::new(ancestor) {
                        Ok(parent) => {
                            if add_rule(&mut created, parent, EXECUTE_AND_READ_DIR).is_ok() {
                                narrowed = Ok(());
                                break;
                            }
                        }
                        _ => continue,
                    }
                }
                narrowed?;
            }
            Err(error) => return Err(error),
        }
    }

    for directory in traverse_only {
        if roots.iter().any(|granted| granted == directory)
            || traverse_only
                .iter()
                .any(|other| other != directory && directory.starts_with(other))
        {
            continue;
        }
        if let Ok(parent) = PathFd::new(directory) {
            add_rule(&mut created, parent, EXECUTE_AND_READ_DIR)?;
        }
    }

    let status = created
        .no_new_privs(true)
        .restrict_self()
        .map_err(|error| io_error(format!("landlock restrict failed: {error}")))?;
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(linux_io::Error::other(
            "landlock is not enforced by this kernel (ABI unsupported or disabled)",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod imports_for_helpers {}

#[cfg(target_os = "linux")]
fn add_rule(
    ruleset: &mut landlock::RulesetCreated,
    parent: PathFd,
    access: landlock::BitFlags<AccessFs>,
) -> linux_io::Result<()> {
    use landlock::RulesetCreatedAttr as _;
    let rule = PathBeneath::new(parent, access);
    ruleset
        .add_rule(rule)
        .map(|_| ())
        .map_err(|error| io_error(format!("failed to add landlock rule: {error}")))
}

#[cfg(target_os = "linux")]
fn io_error(message: String) -> std::io::Error {
    std::io::Error::other(message)
}

/// Non-Linux hosts have no Landlock kernel support; enforcement is a no-op so the
/// crate keeps compiling cross-platform for workspace checks while macOS runs the
/// Seatbelt backend.
#[cfg(not(target_os = "linux"))]
pub fn restrict_fs_read_universe(
    roots: &[PathBuf],
    traverse_only: &[PathBuf],
) -> std::io::Result<()> {
    let _ = (roots, traverse_only);
    Ok(())
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn probe_reports_unsupported_on_non_linux_hosts() {
        assert!(matches!(
            probe_support(),
            LandlockSupport::Unavailable(LandlockUnavailableReason::UnsupportedKernel,),
        ));
    }

    #[test]
    fn restriction_is_a_noop_without_kernel_support() {
        let roots = Vec::new();
        restrict_fs_read_universe(&roots, &[]).expect("non-linux restriction cannot fail");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::collections::BTreeSet;

    fn stage(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "heimdall-landlock-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("open/sub")).expect("stage dirs created");
        std::fs::write(dir.join("open/sub/file.txt"), "payload").expect("stage file written");
        std::fs::create_dir_all(dir.join("secret")).expect("secret dir created");
        std::fs::write(dir.join("secret/key.txt"), "hunter2").expect("secret file written");
        dir
    }

    #[test]
    fn probe_is_stable_within_a_process() {
        assert_eq!(probe_support(), probe_support());
    }

    #[test]
    fn restriction_makes_non_granted_reads_fail_with_permission_denied() {
        if probe_support() != LandlockSupport::Available {
            return;
        }
        let dir = stage("deny");
        let secret = dir.join("secret");

        let mut roots = BTreeSet::new();
        for entry in std::fs::read_dir(&dir).expect("stage entries") {
            let entry = entry.expect("stage entry");
            if entry.path() == secret {
                continue;
            }
            roots.insert(entry.path());
        }

        let seeds: Vec<PathBuf> = roots.into_iter().collect();
        restrict_fs_read_universe(&seeds, &[]).expect("landlock restriction applies");

        assert_eq!(
            std::fs::read_to_string(dir.join("open/sub/file.txt")).expect("granted read"),
            "payload"
        );
        // Denied content reads reject loudly on every generation.
        let denied =
            std::fs::read_to_string(secret.join("key.txt")).expect_err("denied read must fail");
        assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn cross_directory_links_and_renames_survive_restriction() {
        if probe_support() != LandlockSupport::Available {
            return;
        }
        let dir = stage("refer");
        let seeds = vec![dir.join("open")];
        restrict_fs_read_universe(&seeds, &[]).expect("landlock restriction applies");

        // Landlock denies reparenting link(2)/rename(2) with EXDEV unless the
        // Refer right is handled and granted; the workspace must keep both.
        std::fs::hard_link(
            dir.join("open/sub/file.txt"),
            dir.join("open/file-link.txt"),
        )
        .expect("cross-directory hardlink inside granted root");
        std::fs::rename(
            dir.join("open/file-link.txt"),
            dir.join("open/sub/file-renamed.txt"),
        )
        .expect("cross-directory rename inside granted root");
        assert_eq!(
            std::fs::read_to_string(dir.join("open/sub/file-renamed.txt")).expect("linked read"),
            "payload"
        );
    }

    #[test]
    fn empty_root_set_is_rejected_rather_than_locking_out_everything() {
        let error = restrict_fs_read_universe(&[], &[]).expect_err("empty universe rejected");
        assert!(error.to_string().contains("at least one"));
    }

    #[test]
    fn traverse_only_ancestors_open_readonly_and_files_beneath_stay_denied() {
        if probe_support() != LandlockSupport::Available {
            return;
        }
        let dir = stage("traverse");
        let seeds = vec![dir.join("open")];
        let traverse_only = vec![dir.clone()];
        restrict_fs_read_universe(&seeds, &traverse_only).expect("landlock restriction applies");

        // bun-style cwd-parent walk: the traverse-only ancestor must open
        // O_RDONLY|O_DIRECTORY (read_dir is the same open(2) path) and list
        // its directory names instead of dying with EACCES.
        let listed: Vec<String> = std::fs::read_dir(&dir)
            .expect("traverse-only directory must open O_RDONLY")
            .map(|entry| {
                entry
                    .expect("stage entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert!(
            listed.iter().any(|name| name == "secret"),
            "names visible: {listed:?}"
        );

        // Content beneath the traverse-only ancestor stays ReadFile-denied.
        let denied =
            std::fs::read_to_string(dir.join("secret/key.txt")).expect_err("denied read must fail");
        assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
