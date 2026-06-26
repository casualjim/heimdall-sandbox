//! Pure translation of a materialized filesystem policy into microVM volume
//! mounts and rootfs patches.
//!
//! The microVM backend has no bind-mount masking primitive, so denied paths are
//! never mounted instead of being shadowed: anything the guest cannot see (or
//! recreates locally in its ephemeral overlay) cannot reach the host. The
//! workspace (cwd) is always mounted; everything outside it is deny-by-default
//! and only reachable through explicit writable or readable (negated-deny)
//! targets.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use heimdall_sandbox_policy::MaterializedFilesystemPolicy;

use crate::{Error, Result};

/// Guest path the workspace (cwd) is mounted at and the child process runs in.
pub(crate) const GUEST_WORKDIR: &str = "/workspace";

/// A single host directory or file mounted into the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VolumePlan {
    /// Absolute guest mount path.
    pub guest: String,
    /// Host path bound at `guest`.
    pub host: PathBuf,
    /// Whether the mount denies writes.
    pub readonly: bool,
}

/// Read-only virtual file content baked into the rootfs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VirtualFilePlan {
    /// Absolute guest path the content is written to.
    pub guest: String,
    /// File content.
    pub content: String,
}

/// Concrete microVM filesystem plan derived from policy.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct FilesystemPlan {
    /// Bind mounts to apply, deduplicated and ordered by guest path.
    pub volumes: Vec<VolumePlan>,
    /// Virtual files to write into the rootfs.
    pub virtual_files: Vec<VirtualFilePlan>,
}

/// Translate the materialized policy and virtual files into a microVM plan.
///
/// `cwd` must be the canonical workspace directory. Writable targets bind
/// read-write, readable and protected targets bind read-only, deny targets are
/// carved out (never mounted), and virtual files are written into the rootfs
/// read-only.
///
/// # Errors
///
/// Returns a sandbox misconfiguration when a host directory cannot be walked
/// while carving deny holes, or when a resolved guest path is not representable
/// for the microVM backend.
pub(crate) fn plan_filesystem(
    cwd: &Path,
    materialized: &MaterializedFilesystemPolicy,
    virtual_files: &BTreeMap<PathBuf, String>,
) -> Result<FilesystemPlan> {
    let holes = materialized.deny_targets().clone();
    let writable = materialized.writable_targets().clone();

    let mut readonly_targets: BTreeSet<PathBuf> = materialized
        .readable_targets()
        .union(materialized.protected_targets())
        .cloned()
        .collect();
    // The workspace is always mounted. When no writable rule covers it, it is
    // exposed read-only, matching the bubblewrap backend's default cwd binding.
    if !writable.contains(cwd) && !readonly_targets.contains(cwd) {
        readonly_targets.insert(cwd.to_path_buf());
    }

    let mut out: BTreeMap<String, VolumePlan> = BTreeMap::new();

    // Read-only pass carves around deny holes and writable islands.
    let readonly_cuts: BTreeSet<PathBuf> = holes.union(&writable).cloned().collect();
    for target in &readonly_targets {
        add_target(cwd, target, true, &readonly_cuts, &mut out)?;
    }

    // Writable pass carves around deny holes and read-only islands.
    let writable_cuts: BTreeSet<PathBuf> = holes.union(&readonly_targets).cloned().collect();
    for target in &writable {
        add_target(cwd, target, false, &writable_cuts, &mut out)?;
    }

    let mut plan = FilesystemPlan {
        volumes: out.into_values().collect(),
        virtual_files: Vec::new(),
    };
    for (path, content) in virtual_files {
        plan.virtual_files.push(VirtualFilePlan {
            guest: map_guest(cwd, path)?,
            content: content.clone(),
        });
    }
    Ok(plan)
}

/// Mount `target` with the given access, splitting it around any `cuts` it
/// contains so denied or opposite-access descendants are excluded.
fn add_target(
    cwd: &Path,
    target: &Path,
    readonly: bool,
    cuts: &BTreeSet<PathBuf>,
    out: &mut BTreeMap<String, VolumePlan>,
) -> Result<()> {
    // ponytail: a missing target is a no-op; nothing to bind and the guest path
    // simply stays absent (deny-by-default). Matches bubblewrap optional binds.
    if !target.exists() {
        return Ok(());
    }
    if target.is_dir() && has_descendant_cut(target, cuts) {
        cover_split(cwd, target, readonly, cuts, out)?;
    } else {
        insert_mount(cwd, target, readonly, out)?;
    }
    Ok(())
}

/// Mount each child of `dir` that is neither a cut nor contains a cut, recursing
/// into children that still straddle a cut.
fn cover_split(
    cwd: &Path,
    dir: &Path,
    readonly: bool,
    cuts: &BTreeSet<PathBuf>,
    out: &mut BTreeMap<String, VolumePlan>,
) -> Result<()> {
    let entries = std::fs::read_dir(dir).map_err(|source| Error::FilesystemPlan {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| Error::FilesystemPlan {
            path: dir.to_path_buf(),
            source,
        })?;
        let child = entry.path();
        if cuts.contains(&child) {
            // A deny hole, or a target handled by its own pass; never mount here.
            continue;
        }
        if has_descendant_cut(&child, cuts) {
            cover_split(cwd, &child, readonly, cuts, out)?;
        } else {
            insert_mount(cwd, &child, readonly, out)?;
        }
    }
    Ok(())
}

/// Whether any cut is a strict descendant of `dir`.
fn has_descendant_cut(dir: &Path, cuts: &BTreeSet<PathBuf>) -> bool {
    cuts.iter().any(|cut| cut != dir && cut.starts_with(dir))
}

/// Insert a single mount, rejecting any conflicting duplicate guest path.
fn insert_mount(
    cwd: &Path,
    host: &Path,
    readonly: bool,
    out: &mut BTreeMap<String, VolumePlan>,
) -> Result<()> {
    let guest = map_guest(cwd, host)?;
    let plan = VolumePlan {
        guest: guest.clone(),
        host: host.to_path_buf(),
        readonly,
    };
    if let Some(existing) = out.get(&guest) {
        if existing != &plan {
            return Err(Error::unsupported_policy(format!(
                "microvm filesystem policy maps conflicting mounts to guest path {guest}"
            )));
        }
        return Ok(());
    }
    out.insert(guest, plan);
    Ok(())
}

/// Map a host path to its guest mount path: workspace-relative paths land under
/// [`GUEST_WORKDIR`]; everything else keeps its absolute path.
fn map_guest(cwd: &Path, host: &Path) -> Result<String> {
    let guest = match host.strip_prefix(cwd) {
        Ok(relative) if relative.as_os_str().is_empty() => PathBuf::from(GUEST_WORKDIR),
        Ok(relative) => Path::new(GUEST_WORKDIR).join(relative),
        Err(_) => host.to_path_buf(),
    };
    let guest = guest.to_str().ok_or_else(|| {
        Error::unsupported_policy(format!(
            "microvm guest path is not valid UTF-8: {}",
            guest.display()
        ))
    })?;
    if guest.contains([':', ';', ',']) {
        return Err(Error::unsupported_policy(format!(
            "microvm guest path may not contain ':', ';', or ',': {guest}"
        )));
    }
    Ok(guest.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(name: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("hd-fsplan-{name}-{stamp}"));
        std::fs::create_dir_all(&dir).expect("temp dir created");
        std::fs::canonicalize(&dir).expect("temp dir canonicalizes")
    }

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent created");
        }
        std::fs::write(path, b"x").expect("file written");
    }

    fn mkdir(path: &Path) {
        std::fs::create_dir_all(path).expect("dir created");
    }

    fn set(paths: &[&Path]) -> BTreeSet<PathBuf> {
        paths.iter().map(|p| p.to_path_buf()).collect()
    }

    #[test]
    fn empty_policy_mounts_workspace_readonly() {
        let cwd = unique_dir("empty");
        let materialized = MaterializedFilesystemPolicy::empty();

        let plan = plan_filesystem(&cwd, &materialized, &BTreeMap::new()).expect("plan built");

        assert_eq!(
            plan.volumes,
            vec![VolumePlan {
                guest: "/workspace".to_string(),
                host: cwd.clone(),
                readonly: true,
            }]
        );
    }

    #[test]
    fn writable_cwd_mounts_workspace_readwrite() {
        let cwd = unique_dir("rw-cwd");
        let materialized =
            MaterializedFilesystemPolicy::new(BTreeSet::new(), set(&[&cwd]), BTreeSet::new());

        let plan = plan_filesystem(&cwd, &materialized, &BTreeMap::new()).expect("plan built");

        assert_eq!(plan.volumes.len(), 1);
        assert_eq!(plan.volumes[0].guest, "/workspace");
        assert!(!plan.volumes[0].readonly);
    }

    #[test]
    fn deny_inside_writable_cwd_is_carved_out() {
        let cwd = unique_dir("deny-carve");
        let keep = cwd.join("src");
        let keep_file = cwd.join("README");
        let secret = cwd.join("secret");
        mkdir(&keep);
        touch(&keep_file);
        touch(&secret);
        let materialized =
            MaterializedFilesystemPolicy::new(set(&[&secret]), set(&[&cwd]), BTreeSet::new());

        let plan = plan_filesystem(&cwd, &materialized, &BTreeMap::new()).expect("plan built");

        let guests: BTreeSet<&str> = plan.volumes.iter().map(|v| v.guest.as_str()).collect();
        assert!(guests.contains("/workspace/src"), "kept dir mounted");
        assert!(guests.contains("/workspace/README"), "kept file mounted");
        assert!(
            !guests.iter().any(|g| g.contains("secret")),
            "denied path never mounted: {guests:?}"
        );
        assert!(
            plan.volumes.iter().all(|v| !v.readonly),
            "kept paths writable"
        );
    }

    #[test]
    fn protected_island_inside_writable_cwd_is_readonly() {
        let cwd = unique_dir("protected");
        let src = cwd.join("src");
        let control = cwd.join("control");
        mkdir(&src);
        mkdir(&control);
        let materialized =
            MaterializedFilesystemPolicy::new(BTreeSet::new(), set(&[&cwd]), set(&[&control]));

        let plan = plan_filesystem(&cwd, &materialized, &BTreeMap::new()).expect("plan built");

        let control_mount = plan
            .volumes
            .iter()
            .find(|v| v.guest == "/workspace/control")
            .expect("control mounted");
        assert!(control_mount.readonly, "protected island read-only");
        let src_mount = plan
            .volumes
            .iter()
            .find(|v| v.guest == "/workspace/src")
            .expect("src mounted");
        assert!(!src_mount.readonly, "sibling stays writable");
        assert!(
            !plan.volumes.iter().any(|v| v.guest == "/workspace"),
            "cwd split around protected island, not bound whole"
        );
    }

    #[test]
    fn external_writable_target_keeps_absolute_path() {
        let cwd = unique_dir("ext-cwd");
        let external = unique_dir("ext-target");
        let materialized = MaterializedFilesystemPolicy::new(
            BTreeSet::new(),
            set(&[&cwd, &external]),
            BTreeSet::new(),
        );

        let plan = plan_filesystem(&cwd, &materialized, &BTreeMap::new()).expect("plan built");

        let ext = plan
            .volumes
            .iter()
            .find(|v| v.host == external)
            .expect("external mounted");
        assert_eq!(ext.guest, external.to_str().unwrap());
        assert!(!ext.readonly);
    }

    #[test]
    fn virtual_files_map_into_workspace() {
        let cwd = unique_dir("virtual");
        let materialized = MaterializedFilesystemPolicy::empty();
        let mut virtual_files = BTreeMap::new();
        virtual_files.insert(cwd.join(".env"), "SECRET=redacted".to_string());

        let plan = plan_filesystem(&cwd, &materialized, &virtual_files).expect("plan built");

        assert_eq!(
            plan.virtual_files,
            vec![VirtualFilePlan {
                guest: "/workspace/.env".to_string(),
                content: "SECRET=redacted".to_string(),
            }]
        );
    }
}
