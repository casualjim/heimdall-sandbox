use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use std::sync::OnceLock;

use crate::landlock::{LandlockSupport, probe_support};
use crate::launcher::BubblewrapLauncher;
use crate::policy::{
    AgentPolicy, FilesystemPolicy, FilesystemPolicyMaterializer, MaterializedFilesystemPolicy,
    NetworkMode, ProcMode, concrete_path_state,
};
use crate::virtual_files::{BubblewrapResources, VirtualDataFile};
use crate::{Error, Result};

/// Structured input used to build a Linux bubblewrap invocation.
pub struct BubblewrapRequest<'a> {
    /// Child working directory and filesystem policy root.
    pub cwd: &'a Path,
    /// Child argv to pass to the inner Heimdall re-entry command.
    pub argv: &'a [String],
    /// Child network isolation policy.
    pub network_mode: NetworkMode,
    /// Child stdio policy as passed through the inner CLI.
    pub stdio_policy: &'a str,
    /// Child filesystem isolation policy.
    pub filesystem_policy: &'a FilesystemPolicy,
    /// Child proc mount policy.
    pub proc_mode: ProcMode,
    /// Host agent sockets explicitly enabled for mounting.
    pub agent_policy: AgentPolicy,
}

const GPG_RUNTIME_SOCKET_NAMES: &[&str] = &[
    "S.gpg-agent",
    "S.gpg-agent.extra",
    "S.gpg-agent.ssh",
    "S.gpg-agent.browser",
    "S.keyboxd",
    "S.dirmngr",
];

const GPGCONF_SOCKET_KEYS: &[&str] = &[
    "agent-socket",
    "agent-ssh-socket",
    "agent-extra-socket",
    "agent-browser-socket",
    "keyboxd-socket",
    "dirmngr-socket",
];

/// How denied and protected paths are enforced for one launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DenyEnforcement {
    /// Empty readonly mounts mask denied paths: contents hidden, access silent.
    MaskMounts,
    /// Landlock rejects reads outside the computed grant universe with EACCES.
    LandlockReadRejection,
}

static FALLBACK_WARNING: OnceLock<()> = OnceLock::new();

/// Map probe support to an enforcement decision, warning once on fallback.
fn enforcement_for_support(has_denials: bool, support: LandlockSupport) -> DenyEnforcement {
    if !has_denials {
        return DenyEnforcement::MaskMounts;
    }
    match support {
        LandlockSupport::Available => DenyEnforcement::LandlockReadRejection,
        LandlockSupport::Unavailable(reason) => {
            if FALLBACK_WARNING.set(()).is_ok() {
                eprintln!(
                    "heimdall-sandbox: landlock unavailable ({reason:?});                      denied paths fall back to empty-directory masking"
                );
            }
            DenyEnforcement::MaskMounts
        }
    }
}

fn resolve_deny_enforcement(has_denials: bool) -> DenyEnforcement {
    enforcement_for_support(has_denials, probe_support())
}

/// Extract bubblewrap mount destinations from a prepared argument vector.
///
/// Returns every destination plus whether it mirrors a REAL host tree (binds) or is
/// sandbox-synthetic (tmpfs/created directories), since Landlock grants must follow
/// host truth while synthetic entries only need to stay traversable.
fn extract_mount_destinations(args: &[OsString]) -> Vec<(PathBuf, bool)> {
    const TWO_VALUE_REAL_FLAGS: [&str; 3] = ["--bind", "--ro-bind", "--dev-bind"];
    const TWO_VALUE_SYNTHETIC_FLAGS: [&str; 1] = ["--ro-bind-data"];
    const ONE_VALUE_SYNTHETIC_FLAGS: [&str; 5] =
        ["--tmpfs", "--dir", "--proc", "--dev", "--remount-ro"];

    let mut destinations = Vec::new();
    let mut skip_next_value = false;
    let mut index = 0;
    while index < args.len() {
        let raw = args[index].to_string_lossy().into_owned();
        index += 1;
        if skip_next_value {
            // Permission-mode style value tokens preceding their owning flag.
            skip_next_value = false;
            continue;
        }
        if TWO_VALUE_REAL_FLAGS.contains(&raw.as_str()) {
            index += 1;
            if let Some(destination) = args.get(index) {
                let path = PathBuf::from(destination);
                if path.is_absolute() {
                    destinations.push((path, true));
                }
            }
            index += 1;
        } else if TWO_VALUE_SYNTHETIC_FLAGS.contains(&raw.as_str()) {
            index += 1;
            if let Some(destination) = args.get(index) {
                let path = PathBuf::from(destination);
                if path.is_absolute() {
                    destinations.push((path, false));
                }
            }
            index += 1;
        } else if ONE_VALUE_SYNTHETIC_FLAGS.contains(&raw.as_str()) {
            if let Some(destination) = args.get(index) {
                let path = PathBuf::from(destination);
                if path.is_absolute() {
                    destinations.push((path, false));
                }
            }
            index += 1;
        } else if raw == "--perms" {
            skip_next_value = true;
        }
    }
    destinations
}

/// Compute the Landlock grant universes from extracted mount destinations.
///
/// Returns the fully readable trees plus directories that must stay traversable
/// (execute-only) so paths inside granted trees resolve without exposing their own
/// listings. Only the filesystem ROOT is treated as pure traversal; mount-seeded
/// ancestors nearer than it were mounted deliberately and keep full access.
///
/// Grants mirror what mount masking used to expose: every mounted tree and its
/// ancestor chain stay reachable, each denial boundary carves out its own subtree
/// while keeping unmasked siblings beside it readable, and only corridors that a
/// restored target - deny negations and writable children - legitimately reopens
/// are walked back inward. Paths covered by any denial receive no grant, so reads
/// beneath them fail with EACCES instead of resolving to empty mounts.
fn expand_read_universe(
    mounts: &[(PathBuf, bool)],
    denied: &BTreeSet<PathBuf>,
    protected: &BTreeSet<PathBuf>,
    restored: &BTreeSet<PathBuf>,
) -> (BTreeSet<PathBuf>, BTreeSet<PathBuf>) {
    let blocked: BTreeSet<PathBuf> = denied.iter().chain(protected.iter()).cloned().collect();
    let mut universe = BTreeSet::new();
    let mut traverse: BTreeSet<PathBuf> = BTreeSet::new();

    fn insert_visible(out: &mut BTreeSet<PathBuf>, path: &Path, blocked: &BTreeSet<PathBuf>) {
        if deepest_blocked_covering(path, blocked).is_none() {
            out.insert(path.to_path_buf());
        }
    }

    // Around every denial: reveal its unmasked siblings in the shared parent scope.
    for boundary in &blocked {
        let Some(directory) = boundary.parent() else {
            continue;
        };
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            insert_visible(&mut universe, &entry.path(), &blocked);
        }
    }

    // Restored targets reopen precisely their own corridor through the masks.
    for target in restored {
        if deepest_blocked_covering(target, &blocked).is_some() {
            grant_corridor(&mut universe, &mut traverse, target, &blocked);
        }
    }

    let real_seeds: BTreeSet<PathBuf> = mounts
        .iter()
        .filter(|(_, is_real)| *is_real)
        .map(|(path, _)| path.clone())
        .collect();

    // Ancestors of every mount stay traversable at minimum; those that mirror REAL
    // host trees additionally become fully readable when uncovered.
    for (path, is_real) in mounts {
        for ancestor in path.ancestors().skip(1) {
            // Ancestors containing a denial stay traversal-only: granting such a
            // directory would hand its denied descendants back wholesale.
            let covered = deepest_blocked_covering(ancestor, &blocked);
            if covered.is_some() {
                continue;
            }
            let spans = blocked.iter().any(|b| b.starts_with(ancestor));
            if !spans && *is_real && ancestor.parent().is_some() {
                universe.insert(ancestor.to_path_buf());
            }
            traverse.insert(ancestor.to_path_buf());
        }
    }

    for seed in &real_seeds {
        // A spanning seed stays OUT of readable grants (its real contents would be
        // exposed), but it must remain resolvable: payloads resolve relative working
        // directories and cross mounts THROUGH it, so it becomes execute-only.
        if deepest_blocked_covering(seed, &blocked).is_none() {
            if blocked.iter().any(|boundary| boundary.starts_with(seed)) {
                traverse.insert(seed.to_path_buf());
                grant_spanning_tree(&mut universe, seed, &blocked);
            } else {
                insert_visible(&mut universe, seed, &blocked);
            }
        }
    }

    (universe, traverse)
}

/// Grant every path below `tree` except denial boundaries and their subtrees.
///
/// Called only when `tree` is uncovered but contains boundaries deeper down; the
/// walk stops at each boundary, so denied contents neither resolve nor enumerate.
fn grant_spanning_tree(out: &mut BTreeSet<PathBuf>, tree: &Path, blocked: &BTreeSet<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(tree) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if deepest_blocked_covering(&child, blocked).is_some() {
            continue;
        }
        if blocked.iter().any(|boundary| boundary.starts_with(&child)) {
            grant_spanning_tree(out, &child, blocked);
        } else {
            out.insert(child);
        }
    }
}

fn deepest_blocked_covering<'s>(
    path: &Path,
    blocked: &'s BTreeSet<PathBuf>,
) -> Option<&'s PathBuf> {
    blocked
        .iter()
        .filter(|boundary| path.starts_with(boundary.as_path()))
        .max_by_key(|boundary| boundary.components().count())
}

/// Grant the directory chain from the outermost denial boundary down to target.
///
/// Called only when target lies beneath some denial; intermediate nodes become
/// individual grants, which is the minimum visibility a restored path needs.
fn grant_corridor(
    out: &mut BTreeSet<PathBuf>,
    out_traverse: &mut BTreeSet<PathBuf>,
    target: &Path,
    blocked: &BTreeSet<PathBuf>,
) {
    let Some(boundary) = deepest_blocked_covering(target, blocked) else {
        out.insert(target.to_path_buf());
        return;
    };

    let mut node = boundary.clone();
    let Ok(relative) = target.strip_prefix(&node) else {
        return;
    };
    let total = relative.components().count();
    for (index, component) in relative.components().enumerate() {
        node.push(component);
        match deepest_blocked_covering(&node, blocked) {
            // Walking beneath the entered boundary is expected along a
            // legitimate restoration corridor. INTERMEDIATE levels stay
            // traverse-only so a restored directory never re-admits its
            // sibling files; only the final restored leaf gets full rights.
            Some(covered) if covered.as_path() == boundary => {
                if index + 1 == total {
                    out.insert(node.clone());
                } else {
                    out_traverse.insert(node.clone());
                }
            }
            // A DIFFERENT, deeper denial intercepts the corridor; stop.
            Some(_) => return,
            None if index + 1 == total => {
                out.insert(node.clone());
            }
            None => {
                out_traverse.insert(node.clone());
            }
        }
    }
}

#[derive(Debug, Default)]
struct AgentRuntimePaths {
    sockets: BTreeSet<PathBuf>,
    readable_dirs: BTreeSet<PathBuf>,
}

impl BubblewrapRequest<'_> {
    /// Convert this request into a prepared bubblewrap invocation.
    ///
    /// # Errors
    ///
    /// Returns a sandbox misconfiguration when bubblewrap discovery, filesystem materialization,
    /// or virtual file preparation fails.
    pub fn into_plan(self) -> Result<BubblewrapPlan> {
        BubblewrapPlanner::new(self).prepare()
    }

    #[cfg(test)]
    fn into_plan_with_bwrap(
        self,
        materialized: MaterializedFilesystemPolicy,
        bwrap: PathBuf,
    ) -> Result<BubblewrapPlan> {
        // Legacy mask-mount semantics pinned so these assertions stay deterministic
        // on hosts whose kernels support Landlock.
        self.into_plan_with_enforcement(materialized, bwrap, DenyEnforcement::MaskMounts)
    }

    #[cfg(test)]
    fn into_plan_with_enforcement(
        self,
        materialized: MaterializedFilesystemPolicy,
        bwrap: PathBuf,
        enforcement: DenyEnforcement,
    ) -> Result<BubblewrapPlan> {
        BubblewrapPlanner {
            request: self,
            enforcement_override: Some(enforcement),
        }
        .prepare_with_materialized(
            materialized,
            BubblewrapLauncher {
                path: bwrap,
                supports_argv0: true,
            },
        )
    }

    #[cfg(test)]
    fn into_plan_with_launcher(
        self,
        materialized: MaterializedFilesystemPolicy,
        launcher: BubblewrapLauncher,
    ) -> Result<BubblewrapPlan> {
        BubblewrapPlanner {
            request: self,
            enforcement_override: None,
        }
        .prepare_with_materialized(materialized, launcher)
    }
}

struct BubblewrapPlanner<'a> {
    request: BubblewrapRequest<'a>,
    enforcement_override: Option<DenyEnforcement>,
}

impl<'a> BubblewrapPlanner<'a> {
    const fn new(request: BubblewrapRequest<'a>) -> Self {
        Self {
            request,
            enforcement_override: None,
        }
    }

    fn prepare(self) -> Result<BubblewrapPlan> {
        self.discover()?.materialize()?.prepare_resources()?.build()
    }

    fn discover(self) -> Result<DiscoveredBubblewrap<'a>> {
        let launcher = BubblewrapLauncher::discover()?;
        let proc_mode = launcher.effective_proc_mode(self.request.proc_mode)?;
        let request = BubblewrapRequest {
            proc_mode,
            ..self.request
        };
        Ok(DiscoveredBubblewrap {
            request,
            launcher,
            enforcement_override: self.enforcement_override,
        })
    }

    #[cfg(test)]
    fn prepare_with_materialized(
        self,
        materialized: MaterializedFilesystemPolicy,
        launcher: BubblewrapLauncher,
    ) -> Result<BubblewrapPlan> {
        DiscoveredBubblewrap {
            request: self.request,
            launcher,
            enforcement_override: self.enforcement_override,
        }
        .with_materialized(materialized)
        .prepare_resources()?
        .build()
    }
}

struct DiscoveredBubblewrap<'a> {
    request: BubblewrapRequest<'a>,
    launcher: BubblewrapLauncher,
    enforcement_override: Option<DenyEnforcement>,
}

impl<'a> DiscoveredBubblewrap<'a> {
    fn materialize(self) -> Result<MaterializedBubblewrap<'a>> {
        let materialized =
            FilesystemPolicyMaterializer::new(self.request.cwd, self.request.filesystem_policy)
                .materialize()?;
        Ok(self.with_materialized(materialized))
    }

    fn with_materialized(
        self,
        materialized: MaterializedFilesystemPolicy,
    ) -> MaterializedBubblewrap<'a> {
        MaterializedBubblewrap {
            request: self.request,
            launcher: self.launcher,
            materialized,
            enforcement_override: self.enforcement_override,
        }
    }
}

struct MaterializedBubblewrap<'a> {
    request: BubblewrapRequest<'a>,
    launcher: BubblewrapLauncher,
    materialized: MaterializedFilesystemPolicy,
    enforcement_override: Option<DenyEnforcement>,
}

impl<'a> MaterializedBubblewrap<'a> {
    fn prepare_resources(self) -> Result<PreparedBubblewrap<'a>> {
        let resources = BubblewrapResources::prepare(
            self.request.cwd,
            &self.materialized,
            self.request.filesystem_policy,
        )?;
        Ok(PreparedBubblewrap {
            request: self.request,
            launcher: self.launcher,
            materialized: self.materialized,
            resources,
            enforcement_override: self.enforcement_override,
        })
    }
}

struct PreparedBubblewrap<'a> {
    request: BubblewrapRequest<'a>,
    launcher: BubblewrapLauncher,
    materialized: MaterializedFilesystemPolicy,
    resources: BubblewrapResources,
    enforcement_override: Option<DenyEnforcement>,
}

impl PreparedBubblewrap<'_> {
    fn build(self) -> Result<BubblewrapPlan> {
        let enforcement = self.enforcement_override.unwrap_or_else(|| {
            let has_denials = !self.materialized.deny_targets().is_empty();
            // Denied paths whose on-disk identity is a symlink or otherwise
            // diverges from the policy-literal path keep mount masking: masking
            // operates on namespace view semantics that survive aliasing, while
            // Landlock rules anchor on final-object inodes and would leave the
            // aliased interior readable.
            let aliased = self
                .materialized
                .deny_targets()
                .iter()
                .chain(self.materialized.protected_targets())
                .any(|target| {
                    std::fs::canonicalize(target)
                        .map(|canonical| canonical != *target)
                        .unwrap_or(false)
                });
            if has_denials && aliased {
                DenyEnforcement::MaskMounts
            } else {
                resolve_deny_enforcement(has_denials)
            }
        });
        let (read_grants, read_traverse) = self.compute_read_grants(enforcement)?;
        let args = BubblewrapArgBuilder::new(
            &self.request,
            &self.materialized,
            &self.resources,
            &self.launcher,
            enforcement,
            read_grants.as_slice(),
            read_traverse.as_slice(),
        )
        .build()?;

        Ok(BubblewrapPlan {
            bwrap: self.launcher.path,
            args,
            resources: self.resources,
            missing_deny_guards: self.materialized.missing_deny_guards().clone(),
        })
    }
}

impl PreparedBubblewrap<'_> {
    /// Compute granted read trees plus traversal-only ancestors, empty under masking.
    fn compute_read_grants(
        &self,
        enforcement: DenyEnforcement,
    ) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
        if enforcement != DenyEnforcement::LandlockReadRejection {
            return Ok((Vec::new(), Vec::new()));
        }

        let staged_args = BubblewrapArgBuilder::new(
            &self.request,
            &self.materialized,
            &self.resources,
            &self.launcher,
            enforcement,
            &[],
            &[],
        )
        .build()?;
        let mut mounts = extract_mount_destinations(&staged_args);
        // Synthetic sandbox roots payloads touch at runtime: stdio-null opens
        // /dev/null and proc-aware tools stat /proc; the namespace tmpfs
        // instances are what gets ruled here, never host content.
        mounts.push((PathBuf::from("/dev"), true));
        mounts.push((PathBuf::from("/proc"), true));
        mounts.push((PathBuf::from("/tmp"), true));
        let restored: BTreeSet<PathBuf> = self
            .materialized
            .readable_targets()
            .union(self.materialized.writable_targets())
            .cloned()
            .collect();
        let universe = expand_read_universe(
            &mounts,
            self.materialized.deny_targets(),
            self.materialized.protected_targets(),
            &restored,
        );

        if universe.0.is_empty() {
            return Err(Error::sandbox_misconfiguration(
                "landlock enforcement requires a non-empty read-grant universe",
            ));
        }
        Ok((
            universe.0.into_iter().collect(),
            universe.1.into_iter().collect(),
        ))
    }
}

/// Prepared bubblewrap invocation and resources that must stay alive until spawn.
pub struct BubblewrapPlan {
    bwrap: PathBuf,
    args: Vec<OsString>,
    resources: BubblewrapResources,
    missing_deny_guards: BTreeSet<PathBuf>,
}

impl BubblewrapPlan {
    /// Convert this prepared bubblewrap invocation into a command.
    #[must_use]
    pub fn command(&self) -> Command {
        let _keep_resources_alive = &self.resources;
        let mut command = Command::new(&self.bwrap);
        command.args(&self.args);
        command
    }

    /// Remove sandbox-only mountpoints that bubblewrap created for missing deny guards.
    ///
    /// # Errors
    ///
    /// Returns a sandbox misconfiguration when an empty mountpoint artifact cannot be removed.
    pub fn cleanup_missing_deny_guards(&self) -> Result<()> {
        for guard in &self.missing_deny_guards {
            match fs::remove_dir(guard) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
                Err(error) => {
                    return Err(Error::sandbox_misconfiguration(format!(
                        "failed to remove missing deny guard mountpoint {}: {error}",
                        guard.display()
                    )));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct PolicyMount<'a> {
    source: &'a Path,
    destination: &'a Path,
    kind: PolicyMountKind,
}

impl<'a> PolicyMount<'a> {
    fn writable(path: &'a Path) -> Self {
        Self {
            source: path,
            destination: path,
            kind: PolicyMountKind::Writable,
        }
    }

    fn readable(path: &'a Path) -> Self {
        Self {
            source: path,
            destination: path,
            kind: PolicyMountKind::Readable,
        }
    }

    fn virtual_file(file: &'a VirtualDataFile) -> Self {
        Self {
            source: file.sandbox_path.as_path(),
            destination: file.sandbox_path.as_path(),
            kind: PolicyMountKind::VirtualFile { fd: file.fd() },
        }
    }

    fn deny(source: &'a Path, destination: &'a Path) -> Self {
        Self {
            source,
            destination,
            kind: PolicyMountKind::Deny,
        }
    }

    fn protected(source: &'a Path, destination: &'a Path) -> Self {
        Self {
            source,
            destination,
            kind: PolicyMountKind::Protected,
        }
    }

    fn agent_readable(path: &'a Path) -> Self {
        Self {
            source: path,
            destination: path,
            kind: PolicyMountKind::AgentReadable,
        }
    }

    fn runtime_socket(path: &'a Path) -> Self {
        Self {
            source: path,
            destination: path,
            kind: PolicyMountKind::RuntimeSocket,
        }
    }

    fn sort_key(&self) -> (usize, u8, PathBuf) {
        (
            self.destination.components().count(),
            self.kind.precedence(),
            self.destination.to_path_buf(),
        )
    }

    fn is_directory_mask(&self) -> bool {
        matches!(
            self.kind,
            PolicyMountKind::Deny | PolicyMountKind::Protected
        ) && self.source.is_dir()
    }

    fn is_missing_deny_guard_for(&self, parent: &Self) -> bool {
        self.kind == PolicyMountKind::MissingDenyGuard
            && self.destination != parent.destination
            && self.destination.starts_with(parent.destination)
    }

    fn must_stage_mountpoint_for(&self, child: &Self) -> bool {
        self.is_directory_mask()
            && child.destination != self.destination
            && child.destination.starts_with(self.destination)
    }

    fn mountpoint_kind(&self) -> MountpointKind {
        match self.kind {
            PolicyMountKind::VirtualFile { .. } | PolicyMountKind::RuntimeSocket => {
                MountpointKind::File
            }
            PolicyMountKind::MissingDenyGuard => MountpointKind::Directory,
            PolicyMountKind::Writable
            | PolicyMountKind::Readable
            | PolicyMountKind::Deny
            | PolicyMountKind::Protected
            | PolicyMountKind::AgentReadable => {
                if self.source.is_dir() {
                    MountpointKind::Directory
                } else {
                    MountpointKind::File
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MountpointKind {
    Directory,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyMountKind {
    Writable,
    Readable,
    VirtualFile { fd: i32 },
    Deny,
    Protected,
    MissingDenyGuard,
    AgentReadable,
    RuntimeSocket,
}

impl PolicyMountKind {
    const fn precedence(self) -> u8 {
        match self {
            Self::Writable => 0,
            Self::Readable => 1,
            Self::VirtualFile { .. } => 2,
            Self::Deny => 3,
            Self::Protected => 4,
            Self::MissingDenyGuard => 5,
            Self::AgentReadable => 6,
            Self::RuntimeSocket => 7,
        }
    }
}

struct BubblewrapArgBuilder<'a> {
    request: &'a BubblewrapRequest<'a>,
    materialized: &'a MaterializedFilesystemPolicy,
    resources: &'a BubblewrapResources,
    launcher: &'a BubblewrapLauncher,
    enforcement: DenyEnforcement,
    read_grants: &'a [PathBuf],
    read_traverse: &'a [PathBuf],
    args: Vec<OsString>,
}

impl<'a> BubblewrapArgBuilder<'a> {
    fn new(
        request: &'a BubblewrapRequest<'a>,
        materialized: &'a MaterializedFilesystemPolicy,
        resources: &'a BubblewrapResources,
        launcher: &'a BubblewrapLauncher,
        enforcement: DenyEnforcement,
        read_grants: &'a [PathBuf],
        read_traverse: &'a [PathBuf],
    ) -> Self {
        Self {
            request,
            materialized,
            resources,
            launcher,
            enforcement,
            read_grants,
            read_traverse,
            args: Vec::new(),
        }
    }

    fn build(mut self) -> Result<Vec<OsString>> {
        self.validate_required_startup_paths()?;
        self.add_namespaces();
        self.add_readonly_base_filesystem()?;
        self.add_policy_mounts()?;
        self.add_inner_reentry()?;
        Ok(self.args)
    }

    fn validate_required_startup_paths(&self) -> Result<()> {
        required_path_exists(&self.launcher.path)?;
        Ok(())
    }

    fn add_namespaces(&mut self) {
        self.args.extend(os_args([
            "--die-with-parent",
            "--unshare-user",
            "--unshare-pid",
        ]));
        if self.request.network_mode == NetworkMode::None {
            self.args.push("--unshare-net".into());
        }
        if self.request.proc_mode == ProcMode::Default {
            self.args.extend(os_args(["--proc", "/proc"]));
        }
        self.args.extend(os_args(["--dev", "/dev"]));
        self.tmpfs_with_perms(Path::new("/tmp"), "1777");
    }

    fn add_readonly_base_filesystem(&mut self) -> Result<()> {
        // Optional support mounts are skipped only when confirmed missing; indeterminate
        // states remain planning errors so policy never weakens on ambiguous host state.
        for root in Self::platform_read_roots() {
            if optional_path_exists(&root)? {
                self.ro_bind(&root, &root);
            }
        }
        if self.request.network_mode == NetworkMode::Host {
            self.add_host_network_runtime_paths()?;
        }
        if let Some(home) = dirs_home() {
            for alias in path_aliases(&home) {
                if optional_path_exists(&alias)? && alias.is_dir() {
                    self.ro_bind(&alias, &alias);
                }
            }
        }
        Ok(())
    }

    fn add_policy_mounts(&mut self) -> Result<()> {
        self.ro_bind(self.request.cwd, self.request.cwd);

        let empty_file = self.resources.empty_file();
        let empty_dir = self.resources.empty_dir();
        let agent_runtime_paths = Self::agent_runtime_paths(self.request.agent_policy)?;
        let mut mounts = Vec::new();
        mounts.extend(
            self.materialized
                .writable_targets()
                .iter()
                .map(|path| PolicyMount::writable(path.as_path())),
        );
        mounts.extend(
            self.materialized
                .readable_targets()
                .iter()
                .map(|path| PolicyMount::readable(path.as_path())),
        );
        mounts.extend(
            self.resources
                .virtual_files()
                .iter()
                .map(PolicyMount::virtual_file),
        );
        if self.enforcement == DenyEnforcement::MaskMounts {
            mounts.extend(self.materialized.deny_targets().iter().map(|path| {
                let source = if path.is_dir() {
                    empty_dir.as_path()
                } else {
                    empty_file.as_path()
                };
                PolicyMount::deny(source, path)
            }));
        }
        mounts.extend(
            self.materialized
                .missing_deny_guards()
                .iter()
                .map(|path| PolicyMount {
                    source: empty_dir.as_path(),
                    destination: path.as_path(),
                    kind: PolicyMountKind::MissingDenyGuard,
                }),
        );
        if self.enforcement == DenyEnforcement::MaskMounts {
            mounts.extend(self.materialized.protected_targets().iter().map(|path| {
                let source = if path.exists() && !path.is_dir() {
                    empty_file.as_path()
                } else {
                    empty_dir.as_path()
                };
                PolicyMount::protected(source, path)
            }));
        }
        mounts.extend(
            agent_runtime_paths
                .readable_dirs
                .iter()
                .map(|path| PolicyMount::agent_readable(path.as_path())),
        );
        mounts.extend(
            agent_runtime_paths
                .sockets
                .iter()
                .map(|path| PolicyMount::runtime_socket(path.as_path())),
        );
        mounts.sort_by_key(PolicyMount::sort_key);

        for index in 0..mounts.len() {
            let mount = mounts[index];
            if mount.is_directory_mask()
                && mounts
                    .iter()
                    .any(|candidate| mount.must_stage_mountpoint_for(candidate))
            {
                // Bubblewrap creates bind destinations inside the current sandbox view.
                // A readonly empty-dir mask would make later child mountpoints impossible
                // to create, so stage the masked directory as writable tmpfs, create the
                // nested mountpoints, seal it readonly, then layer the specific child
                // mounts later in sorted order.
                self.tmpfs(mount.destination);
                for candidate in mounts
                    .iter()
                    .filter(|candidate| mount.must_stage_mountpoint_for(candidate))
                {
                    self.add_staged_mountpoint(mount.destination, candidate, &empty_file);
                }
                self.remount_ro(mount.destination);
                continue;
            }

            if mount.kind == PolicyMountKind::Writable
                && mounts
                    .iter()
                    .any(|candidate| candidate.is_missing_deny_guard_for(&mount))
            {
                // Missing deny guards under a writable parent need a sandbox-only
                // mountpoint before the host writable tree is visible. Stage the
                // writable destination as tmpfs, create/mount the guarded child
                // there, then bind the writable parent and later layer the final
                // guard in sorted order. This preserves deny-over-writable without
                // creating the missing path on the host.
                self.tmpfs(mount.destination);
                for candidate in mounts
                    .iter()
                    .filter(|candidate| candidate.is_missing_deny_guard_for(&mount))
                {
                    self.add_staged_mountpoint(mount.destination, candidate, &empty_file);
                    self.ro_bind(candidate.source, candidate.destination);
                }
                self.add_policy_mount(mount)?;
                continue;
            }

            self.add_policy_mount(mount)?;
        }
        Ok(())
    }

    fn add_policy_mount(&mut self, mount: PolicyMount<'_>) -> Result<()> {
        match mount.kind {
            PolicyMountKind::Writable => {
                let destination = bubblewrap_mount_destination(mount.destination)?;
                if is_device_node(mount.source) {
                    self.dev_bind(mount.source, &destination);
                } else {
                    self.bind(mount.source, &destination);
                }
            }
            PolicyMountKind::Readable | PolicyMountKind::AgentReadable => {
                let destination = bubblewrap_mount_destination(mount.destination)?;
                self.ro_bind(mount.source, &destination);
            }
            PolicyMountKind::VirtualFile { fd } => {
                self.args.push("--ro-bind-data".into());
                self.args.push(fd.to_string().into());
                self.args.push(mount.destination.as_os_str().to_os_string());
            }
            PolicyMountKind::Deny | PolicyMountKind::Protected => {
                let destination = bubblewrap_mount_destination(mount.destination)?;
                self.ro_bind(mount.source, &destination);
            }
            PolicyMountKind::MissingDenyGuard => {
                self.ro_bind(mount.source, mount.destination);
            }
            PolicyMountKind::RuntimeSocket => {
                self.bind(mount.source, mount.destination);
            }
        }
        Ok(())
    }

    fn add_staged_mountpoint(&mut self, mask: &Path, mount: &PolicyMount<'_>, empty_file: &Path) {
        let placeholder_directory = match mount.mountpoint_kind() {
            MountpointKind::Directory => mount.destination,
            MountpointKind::File => mount.destination.parent().unwrap_or(mask),
        };
        self.add_staged_directories(mask, placeholder_directory);
        if mount.mountpoint_kind() == MountpointKind::File {
            self.ro_bind(empty_file, mount.destination);
        }
    }

    fn add_staged_directories(&mut self, mask: &Path, destination: &Path) {
        if destination == mask || !destination.starts_with(mask) {
            return;
        }

        let mut directories = Vec::new();
        let mut current = destination;
        while current != mask {
            directories.push(current.to_path_buf());
            let Some(parent) = current.parent() else {
                break;
            };
            current = parent;
        }
        directories.reverse();
        for directory in directories {
            self.dir(&directory);
        }
    }

    fn add_inner_reentry(&mut self) -> Result<()> {
        let current_exe = std::env::current_exe().map_err(|error| {
            Error::sandbox_misconfiguration(format!(
                "failed to resolve current executable: {error}"
            ))
        })?;
        required_path_exists(&current_exe)?;
        self.ro_bind(&current_exe, Path::new("/heimdall-inner"));
        for library in Self::runtime_libraries(&current_exe)? {
            self.ro_bind(
                &library,
                Path::new("/")
                    .join(library.file_name().unwrap_or_default())
                    .as_path(),
            );
        }
        self.args.push("--setenv".into());
        self.args.push("LD_LIBRARY_PATH".into());
        self.args.push("/".into());
        self.args.push("--chdir".into());
        self.args.push(self.request.cwd.as_os_str().to_os_string());
        if self.launcher.supports_argv0 {
            self.args.push("--argv0".into());
            self.args.push("heimdall-sandbox".into());
        }
        self.args.push("--".into());
        self.args.push("/heimdall-inner".into());
        self.args.push("__heimdall-inner-exec".into());
        self.args.push("--cwd".into());
        self.args.push(self.request.cwd.as_os_str().to_os_string());
        self.args.push("--stdio".into());
        self.args.push(self.request.stdio_policy.into());
        // Landlock grants ride the inner re-entry argv: bwrap only accepts its own
        // options before the namespace terminator.
        for grant in self.read_grants {
            self.args.push("--read-grant".into());
            self.args.push(grant.as_os_str().to_os_string());
        }
        for directory in self.read_traverse {
            self.args.push("--read-traverse".into());
            self.args.push(directory.as_os_str().to_os_string());
        }
        self.args.push("--".into());
        self.args
            .extend(self.request.argv.iter().map(OsString::from));
        Ok(())
    }

    fn runtime_libraries(executable: &Path) -> Result<Vec<PathBuf>> {
        let Some(parent) = executable.parent() else {
            return Ok(Vec::new());
        };
        let mut libraries = Vec::new();
        for library in ["libwebgpu_dawn.so"]
            .into_iter()
            .map(|name| parent.join(name))
        {
            if optional_path_exists(&library)? && library.is_file() {
                libraries.push(library);
            }
        }
        Ok(libraries)
    }

    fn add_host_network_runtime_paths(&mut self) -> Result<()> {
        self.add_resolver_symlink_target()?;
        self.add_runtime_socket(Path::new("/run/dbus/system_bus_socket"))
    }

    fn add_resolver_symlink_target(&mut self) -> Result<()> {
        let Some(target) = Self::resolver_symlink_target(Path::new("/etc/resolv.conf")) else {
            return Ok(());
        };
        if optional_path_exists(&target)? {
            self.add_destination_parent_dirs(&target);
            self.ro_bind(&target, &target);
        }
        Ok(())
    }

    fn add_runtime_socket(&mut self, socket: &Path) -> Result<()> {
        if !optional_path_exists(socket)? {
            return Ok(());
        }
        self.add_destination_parent_dirs(socket);
        self.bind(socket, socket);
        Ok(())
    }

    fn resolver_symlink_target(resolv_conf: &Path) -> Option<PathBuf> {
        let target = fs::read_link(resolv_conf).ok()?;
        let absolute = if target.is_absolute() {
            target
        } else {
            resolv_conf.parent()?.join(target)
        };
        absolute.canonicalize().ok()
    }

    fn agent_runtime_paths(agent_policy: AgentPolicy) -> Result<AgentRuntimePaths> {
        let mut paths = AgentRuntimePaths::default();
        if agent_policy.ssh_agent()
            && let Some(path) = env_socket_path(env::var_os("SSH_AUTH_SOCK").as_deref())?
        {
            paths.sockets.insert(path);
        }
        if agent_policy.age_agent() {
            for key in ["AGE_AUTH_SOCK", "GOPASS_AGE_AGENT_SOCK"] {
                if let Some(path) = env_socket_path(env::var_os(key).as_deref())? {
                    paths.sockets.insert(path);
                }
            }
        }
        if agent_policy.gpg_agent() {
            if let Some(path) = gpg_agent_info_socket(env::var_os("GPG_AGENT_INFO").as_deref())? {
                paths.sockets.insert(path);
            }
            if let Some(runtime_dir) = env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
                Self::insert_existing_gpg_socket_names(&mut paths, &runtime_dir.join("gnupg"))?;
            }
            Self::insert_gpgconf_runtime_paths(&mut paths)?;
        }
        Ok(paths)
    }

    fn insert_existing_gpg_socket_names(
        paths: &mut AgentRuntimePaths,
        socket_dir: &Path,
    ) -> Result<()> {
        Self::insert_existing_agent_readable_dir(paths, socket_dir)?;
        for name in GPG_RUNTIME_SOCKET_NAMES {
            let path = socket_dir.join(name);
            if optional_path_exists(&path)? {
                paths.sockets.insert(path);
            }
        }
        Ok(())
    }

    fn insert_existing_agent_readable_dir(
        paths: &mut AgentRuntimePaths,
        directory: &Path,
    ) -> Result<()> {
        if directory.is_absolute() && optional_path_exists(directory)? && directory.is_dir() {
            paths.readable_dirs.insert(directory.to_path_buf());
        }
        Ok(())
    }

    fn insert_gpgconf_runtime_paths(paths: &mut AgentRuntimePaths) -> Result<()> {
        let output = match Command::new("gpgconf").arg("--list-dirs").output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(Error::sandbox_misconfiguration(format!(
                    "failed to run gpgconf --list-dirs: {error}"
                )));
            }
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::sandbox_misconfiguration(format!(
                "gpgconf --list-dirs failed: {stderr}"
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::insert_gpgconf_runtime_paths_from_list_dirs(paths, &stdout)
    }

    fn insert_gpgconf_runtime_paths_from_list_dirs(
        paths: &mut AgentRuntimePaths,
        list_dirs: &str,
    ) -> Result<()> {
        for line in list_dirs.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if key == "homedir" {
                Self::insert_existing_agent_readable_dir(paths, &PathBuf::from(value))?;
            } else if key == "socketdir" {
                let socket_dir = PathBuf::from(value);
                if socket_dir.is_absolute() {
                    Self::insert_existing_gpg_socket_names(paths, &socket_dir)?;
                }
            } else if GPGCONF_SOCKET_KEYS.contains(&key)
                && let Some(path) = env_socket_path(Some(OsStr::new(value)))?
            {
                paths.sockets.insert(path);
            }
        }
        Ok(())
    }

    fn add_destination_parent_dirs(&mut self, destination: &Path) {
        let Some(parent) = destination.parent() else {
            return;
        };
        let mut directories = Vec::new();
        let mut current = parent;
        while current != Path::new("/") {
            directories.push(current.to_path_buf());
            let Some(next) = current.parent() else {
                break;
            };
            current = next;
        }
        directories.reverse();
        for directory in directories {
            self.dir(&directory);
        }
    }

    fn ro_bind(&mut self, source: &Path, destination: &Path) {
        self.mount("--ro-bind", source, destination);
    }

    fn bind(&mut self, source: &Path, destination: &Path) {
        self.mount("--bind", source, destination);
    }

    /// Bind a device node so the mount is not `nodev`. `--bind` inherits `nodev` from the
    /// destination's parent (the `--dev /dev` tmpfs is `nodev`), which makes `open(2)` of a
    /// device return `EACCES` regardless of uid/groups/ACL. `--dev-bind` mounts without
    /// `nodev`, so device access depends only on DAC (and the uid POSIX-ACL survives the
    /// bind because supplementary groups do not).
    fn dev_bind(&mut self, source: &Path, destination: &Path) {
        self.mount("--dev-bind", source, destination);
    }

    fn tmpfs(&mut self, destination: &Path) {
        self.single_path_arg("--tmpfs", destination);
    }

    fn tmpfs_with_perms(&mut self, destination: &Path, permissions: &str) {
        self.args.push("--perms".into());
        self.args.push(permissions.into());
        self.tmpfs(destination);
    }

    fn remount_ro(&mut self, destination: &Path) {
        self.single_path_arg("--remount-ro", destination);
    }

    fn dir(&mut self, destination: &Path) {
        self.single_path_arg("--dir", destination);
    }

    fn mount(&mut self, flag: &str, source: &Path, destination: &Path) {
        self.args.push(flag.into());
        self.args.push(source.as_os_str().to_os_string());
        self.args.push(destination.as_os_str().to_os_string());
    }

    fn single_path_arg(&mut self, flag: &str, destination: &Path) {
        self.args.push(flag.into());
        self.args.push(destination.as_os_str().to_os_string());
    }

    fn platform_read_roots() -> Vec<PathBuf> {
        [
            "/usr",
            "/opt",
            "/srv",
            "/etc",
            "/nix/store",
            "/run/current-system/sw",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect()
    }
}

fn os_args<const N: usize>(args: [&str; N]) -> Vec<OsString> {
    args.into_iter().map(OsString::from).collect()
}

fn dirs_home() -> Option<PathBuf> {
    heimdall_sandbox_policy::home_dir()
}

fn path_aliases(path: &Path) -> BTreeSet<PathBuf> {
    let mut aliases = BTreeSet::from([path.to_path_buf()]);
    if let Ok(canonical) = path.canonicalize() {
        aliases.insert(canonical);
    }
    aliases
}

fn env_socket_path(value: Option<&OsStr>) -> Result<Option<PathBuf>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    if path.is_absolute() && optional_path_exists(&path)? {
        Ok(Some(path))
    } else {
        Ok(None)
    }
}

fn gpg_agent_info_socket(value: Option<&OsStr>) -> Result<Option<PathBuf>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.to_string_lossy();
    let Some(path) = value.split(':').next() else {
        return Ok(None);
    };
    env_socket_path(Some(OsStr::new(path)))
}

fn optional_path_exists(path: &Path) -> Result<bool> {
    concrete_path_state(path)
        .map(|state| matches!(state, heimdall_sandbox_policy::ConcretePathState::Existing))
        .map_err(Into::into)
}

/// Whether `path` is a character or block device node. Device nodes must be mounted with
/// `--dev-bind` (not `--bind`) so the mount is not `nodev`, otherwise `open(2)` returns
/// `EACCES` regardless of uid/groups/ACL.
fn is_device_node(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| {
            metadata.file_type().is_char_device() || metadata.file_type().is_block_device()
        })
        .unwrap_or(false)
}

fn bubblewrap_mount_destination(path: &Path) -> Result<PathBuf> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(path.to_path_buf());
        }
        Err(error) => {
            return Err(Error::sandbox_misconfiguration(format!(
                "failed to inspect bubblewrap mount destination {}: {error}",
                path.display()
            )));
        }
    };
    if !metadata.file_type().is_symlink() {
        return Ok(path.to_path_buf());
    }
    path.canonicalize().map_err(|error| {
        Error::sandbox_misconfiguration(format!(
            "failed to resolve symlink bubblewrap mount destination {}: {error}",
            path.display()
        ))
    })
}

fn required_path_exists(path: &Path) -> Result<()> {
    if optional_path_exists(path)? {
        Ok(())
    } else {
        Err(Error::sandbox_misconfiguration(format!(
            "required startup path {} does not exist",
            path.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    use crate::launcher::BubblewrapLauncher;
    use crate::virtual_files::identity_virtual_files;

    use super::*;

    fn empty_materialized_policy() -> MaterializedFilesystemPolicy {
        MaterializedFilesystemPolicy::empty()
    }

    fn existing_bwrap_path() -> PathBuf {
        std::env::current_exe().expect("test executable path exists")
    }

    #[test]
    fn network_none_adds_unshare_net() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let request = BubblewrapRequest {
            cwd: &cwd,
            argv: &["true".into()],
            network_mode: NetworkMode::None,
            stdio_policy: "inherit",
            filesystem_policy: &FilesystemPolicy::default(),
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        };
        let plan = request
            .into_plan_with_bwrap(empty_materialized_policy(), existing_bwrap_path())
            .expect("plan builds");

        assert!(plan.args.iter().any(|arg| arg == "--unshare-net"));
    }

    #[test]
    fn network_host_omits_unshare_net() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let request = BubblewrapRequest {
            cwd: &cwd,
            argv: &["true".into()],
            network_mode: NetworkMode::Host,
            stdio_policy: "inherit",
            filesystem_policy: &FilesystemPolicy::default(),
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        };
        let plan = request
            .into_plan_with_bwrap(empty_materialized_policy(), existing_bwrap_path())
            .expect("plan builds");

        assert!(!plan.args.iter().any(|arg| arg == "--unshare-net"));
    }

    #[test]
    fn unshare_user_is_enabled() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let request = BubblewrapRequest {
            cwd: &cwd,
            argv: &["true".into()],
            network_mode: NetworkMode::Host,
            stdio_policy: "inherit",
            filesystem_policy: &FilesystemPolicy::default(),
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        };
        let plan = request
            .into_plan_with_bwrap(empty_materialized_policy(), existing_bwrap_path())
            .expect("plan builds");

        assert!(plan.args.iter().any(|arg| arg == "--unshare-user"));
    }

    #[test]
    fn argv0_is_used_when_supported() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let request = BubblewrapRequest {
            cwd: &cwd,
            argv: &["true".into()],
            network_mode: NetworkMode::Host,
            stdio_policy: "inherit",
            filesystem_policy: &FilesystemPolicy::default(),
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        };
        let plan = request
            .into_plan_with_launcher(
                empty_materialized_policy(),
                BubblewrapLauncher {
                    path: existing_bwrap_path(),
                    supports_argv0: true,
                },
            )
            .expect("plan builds");
        let args = plan
            .args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();

        assert!(
            args.windows(2)
                .any(|w| w[0] == "--argv0" && w[1] == "heimdall-sandbox")
        );
    }

    #[test]
    fn argv0_is_omitted_when_unsupported() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let request = BubblewrapRequest {
            cwd: &cwd,
            argv: &["true".into()],
            network_mode: NetworkMode::Host,
            stdio_policy: "inherit",
            filesystem_policy: &FilesystemPolicy::default(),
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        };
        let plan = request
            .into_plan_with_launcher(
                empty_materialized_policy(),
                BubblewrapLauncher {
                    path: existing_bwrap_path(),
                    supports_argv0: false,
                },
            )
            .expect("plan builds");

        assert!(!plan.args.iter().any(|arg| arg == "--argv0"));
        assert!(plan.args.iter().any(|arg| arg == "/heimdall-inner"));
    }

    #[test]
    fn proc_preflight_mount_permission_error_falls_back_to_disabled_proc() {
        use std::os::unix::fs::PermissionsExt;

        let script = std::env::temp_dir().join(format!(
            "heimdall-fake-bwrap-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        std::fs::write(
            &script,
            "#!/bin/sh\necho 'proc mount operation not permitted' >&2\nexit 1\n",
        )
        .expect("fake bwrap is written");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("fake bwrap is executable");

        let mode = BubblewrapLauncher {
            path: script.clone(),
            supports_argv0: false,
        }
        .effective_proc_mode(ProcMode::Default)
        .expect("proc mode resolves");
        std::fs::remove_file(script).expect("fake bwrap is removed");

        assert_eq!(mode, ProcMode::Disabled);
    }

    #[test]
    fn proc_mount_can_be_disabled() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let request = BubblewrapRequest {
            cwd: &cwd,
            argv: &["true".into()],
            network_mode: NetworkMode::Host,
            stdio_policy: "inherit",
            filesystem_policy: &FilesystemPolicy::default(),
            proc_mode: ProcMode::Disabled,
            agent_policy: AgentPolicy::default(),
        };
        let plan = request
            .into_plan_with_bwrap(empty_materialized_policy(), existing_bwrap_path())
            .expect("plan builds");

        assert!(!plan.args.iter().any(|arg| arg == "--proc"));
    }

    #[test]
    fn agent_socket_env_values_require_existing_absolute_paths() {
        let root = std::env::temp_dir().join(format!(
            "heimdall-agent-socket-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("test dir created");
        let socket = root.join("agent.sock");
        std::fs::write(&socket, "placeholder").expect("socket placeholder written");

        assert_eq!(
            env_socket_path(Some(socket.as_os_str())).expect("socket path classifies"),
            Some(socket.clone())
        );
        assert_eq!(
            gpg_agent_info_socket(Some(OsStr::new(&format!("{}:0:1", socket.display()))))
                .expect("gpg socket path classifies"),
            Some(socket)
        );
        assert_eq!(
            env_socket_path(Some(OsStr::new("relative.sock"))).expect("relative path ignored"),
            None
        );
        assert_eq!(
            env_socket_path(Some(root.join("missing.sock").as_os_str()))
                .expect("missing socket path classifies"),
            None
        );

        std::fs::remove_dir_all(&root).expect("test dir removed");
    }

    #[test]
    fn default_agent_policy_mounts_no_agent_sockets() {
        let paths = BubblewrapArgBuilder::agent_runtime_paths(AgentPolicy::default())
            .expect("default agent discovery succeeds");

        assert!(paths.sockets.is_empty());
        assert!(paths.readable_dirs.is_empty());
    }

    #[test]
    fn gpgconf_list_dirs_discovers_keyboxd_and_dirmngr_sockets() {
        let root = std::env::temp_dir().join(format!(
            "heimdall-gpgconf-sockets-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        let socket_dir = root.join("gnupg");
        std::fs::create_dir_all(&socket_dir).expect("socket dir created");
        for name in ["S.gpg-agent", "S.keyboxd", "S.dirmngr"] {
            std::fs::write(socket_dir.join(name), "placeholder")
                .expect("socket placeholder written");
        }
        let browser_socket = socket_dir.join("S.gpg-agent.browser");
        std::fs::write(&browser_socket, "placeholder").expect("browser socket placeholder written");
        let list_dirs = format!(
            "homedir:{}\nsocketdir:{}\nagent-browser-socket:{}\nkeyboxd-socket:{}\ndirmngr-socket:{}\n",
            socket_dir.display(),
            socket_dir.display(),
            browser_socket.display(),
            socket_dir.join("S.keyboxd").display(),
            socket_dir.join("S.dirmngr").display()
        );
        let mut paths = AgentRuntimePaths::default();

        BubblewrapArgBuilder::insert_gpgconf_runtime_paths_from_list_dirs(&mut paths, &list_dirs)
            .expect("gpgconf socket output parses");

        for expected in [
            socket_dir.join("S.gpg-agent"),
            socket_dir.join("S.keyboxd"),
            socket_dir.join("S.dirmngr"),
            browser_socket,
        ] {
            assert!(
                paths.sockets.contains(&expected),
                "missing socket {}",
                expected.display()
            );
        }
        assert!(paths.readable_dirs.contains(&socket_dir));
        std::fs::remove_dir_all(root).expect("test dir removed");
    }

    #[test]
    fn missing_required_bubblewrap_path_fails_planning() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let missing_bwrap = std::env::temp_dir().join(format!(
            "heimdall-missing-bwrap-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        let request = BubblewrapRequest {
            cwd: &cwd,
            argv: &["true".into()],
            network_mode: NetworkMode::Host,
            stdio_policy: "inherit",
            filesystem_policy: &FilesystemPolicy::default(),
            proc_mode: ProcMode::Disabled,
            agent_policy: AgentPolicy::default(),
        };

        let result = request.into_plan_with_bwrap(empty_materialized_policy(), missing_bwrap);

        let Err(error) = result else {
            panic!("missing required bwrap path fails");
        };
        assert!(error.to_string().contains("required startup path"));
    }

    #[cfg(unix)]
    #[test]
    fn indeterminate_optional_socket_path_fails_planning() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "heimdall-indeterminate-socket-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("test dir created");
        let dangling = root.join("dangling-parent");
        symlink(root.join("absent"), &dangling).expect("dangling symlink created");
        let socket = dangling.join("agent.sock");

        let result = env_socket_path(Some(socket.as_os_str()));

        assert!(result.is_err());
        std::fs::remove_dir_all(&root).expect("test dir removed");
    }

    #[test]
    fn resolver_symlink_target_resolves_relative_links() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "heimdall-resolver-link-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        let etc = root.join("etc");
        let run = root.join("run/systemd/resolve");
        std::fs::create_dir_all(&etc).expect("etc dir created");
        std::fs::create_dir_all(&run).expect("run dir created");
        let target = run.join("stub-resolv.conf");
        std::fs::write(&target, "nameserver 127.0.0.53\n").expect("resolver target written");
        let link = etc.join("resolv.conf");
        symlink("../run/systemd/resolve/stub-resolv.conf", &link)
            .expect("resolver symlink created");

        let expected = target.canonicalize().expect("target canonicalizes");
        let resolved = BubblewrapArgBuilder::resolver_symlink_target(&link);
        std::fs::remove_dir_all(&root).expect("test dir removed");

        assert_eq!(resolved, Some(expected));
    }

    #[test]
    fn platform_defaults_include_system_roots() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let request = BubblewrapRequest {
            cwd: &cwd,
            argv: &["true".into()],
            network_mode: NetworkMode::Host,
            stdio_policy: "inherit",
            filesystem_policy: &FilesystemPolicy::default(),
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        };
        let plan = request
            .into_plan_with_bwrap(empty_materialized_policy(), existing_bwrap_path())
            .expect("plan builds");
        let args = plan
            .args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();

        for expected in [
            "/usr",
            "/opt",
            "/srv",
            "/etc",
            "/nix/store",
            "/run/current-system/sw",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
        ] {
            assert!(
                BubblewrapArgBuilder::platform_read_roots().contains(&PathBuf::from(expected)),
                "missing platform root {expected}"
            );
        }
        if Path::new("/etc").exists() {
            assert!(
                args.windows(3)
                    .any(|w| w[0] == "--ro-bind" && w[1] == "/etc" && w[2] == "/etc")
            );
        }
        assert!(
            !args
                .windows(3)
                .any(|w| w[0] == "--ro-bind-data" && w[2] == "/etc/passwd"),
            "no default virtual /etc/passwd"
        );
        assert!(
            !args
                .windows(3)
                .any(|w| w[0] == "--ro-bind-data" && w[2] == "/etc/group"),
            "no default virtual /etc/group"
        );
    }

    #[test]
    fn explicit_virtual_files_are_included() {
        let mut virtual_files = BTreeMap::new();
        virtual_files.insert(PathBuf::from("/etc/passwd"), "custom-passwd".to_string());
        let policy = FilesystemPolicy::new(Vec::new(), Vec::new(), virtual_files);
        let files = identity_virtual_files(&policy);

        assert_eq!(
            files.get(Path::new("/etc/passwd")),
            Some(&"custom-passwd".to_string())
        );
        assert_eq!(files.get(Path::new("/etc/group")), None);
    }

    #[test]
    fn plan_layers_readonly_writable_and_deny_mounts() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let denied = cwd.join("Cargo.toml");
        let policy = FilesystemPolicy::new(
            vec!["Cargo.toml".into()],
            vec![".".into()],
            Default::default(),
        );
        let request = BubblewrapRequest {
            cwd: &cwd,
            argv: &["true".into()],
            network_mode: NetworkMode::Host,
            stdio_policy: "inherit",
            filesystem_policy: &policy,
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        };
        let plan = request
            .into_plan_with_bwrap(
                MaterializedFilesystemPolicy::new(
                    BTreeSet::from([denied.clone()]),
                    BTreeSet::from([cwd.clone()]),
                    BTreeSet::new(),
                ),
                existing_bwrap_path(),
            )
            .expect("plan builds");
        let args = plan
            .args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();
        let ro_cwd = args
            .windows(3)
            .position(|w| w[0] == "--ro-bind" && w[2] == cwd.to_string_lossy())
            .expect("cwd ro-bind exists");
        let rw_cwd = args
            .windows(3)
            .position(|w| w[0] == "--bind" && w[2] == cwd.to_string_lossy())
            .expect("cwd bind exists");
        let deny = args
            .windows(3)
            .position(|w| w[0] == "--ro-bind" && w[2] == denied.to_string_lossy())
            .expect("deny mask exists");

        assert!(ro_cwd < rw_cwd);
        assert!(rw_cwd < deny);
    }

    #[test]
    fn denied_parent_stages_writable_child_mountpoint() {
        let root = std::env::temp_dir().join(format!(
            "heimdall-bwrap-specificity-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        let denied = root.join(".config");
        let writable = denied.join("nvim");
        std::fs::create_dir_all(&writable).expect("test dirs created");
        let policy = FilesystemPolicy::new(
            vec![denied.to_string_lossy().to_string()],
            vec![writable.to_string_lossy().to_string()],
            Default::default(),
        );
        let request = BubblewrapRequest {
            cwd: &root,
            argv: &["true".into()],
            network_mode: NetworkMode::Host,
            stdio_policy: "inherit",
            filesystem_policy: &policy,
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        };
        let plan = request
            .into_plan_with_bwrap(
                MaterializedFilesystemPolicy::new(
                    BTreeSet::from([denied.clone()]),
                    BTreeSet::from([writable.clone()]),
                    BTreeSet::new(),
                ),
                existing_bwrap_path(),
            )
            .expect("plan builds");
        std::fs::remove_dir_all(&root).expect("test dirs removed");
        let args = plan
            .args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();
        let tmpfs_parent = args
            .windows(2)
            .position(|w| w[0] == "--tmpfs" && w[1] == denied.to_string_lossy())
            .expect("denied parent is staged as tmpfs");
        let child_mountpoint = args
            .windows(2)
            .position(|w| w[0] == "--dir" && w[1] == writable.to_string_lossy())
            .expect("writable child mountpoint is created before parent is sealed");
        let seal_parent = args
            .windows(2)
            .position(|w| w[0] == "--remount-ro" && w[1] == denied.to_string_lossy())
            .expect("denied parent is remounted readonly");
        let bind_child = args
            .windows(3)
            .position(|w| w[0] == "--bind" && w[2] == writable.to_string_lossy())
            .expect("writable child bind exists");

        assert!(tmpfs_parent < child_mountpoint);
        assert!(child_mountpoint < seal_parent);
        assert!(seal_parent < bind_child);
    }
    #[test]
    fn missing_policy_paths_are_skipped_or_guarded_in_bubblewrap_plan() {
        let root = std::env::temp_dir().join(format!(
            "heimdall-bwrap-missing-policy-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        let writable = root.join("writable");
        std::fs::create_dir_all(&writable).expect("test dirs created");
        let missing_writable = root.join("missing-write");
        let missing_deny_outside = root.join("missing-deny-outside");
        let missing_deny_guard = writable.join("missing-deny-guard");
        let policy = FilesystemPolicy::new(
            vec![
                missing_deny_outside.to_string_lossy().to_string(),
                missing_deny_guard.to_string_lossy().to_string(),
            ],
            vec![
                writable.to_string_lossy().to_string(),
                missing_writable.to_string_lossy().to_string(),
            ],
            Default::default(),
        );
        let materialized = FilesystemPolicyMaterializer::new(&root, &policy)
            .materialize()
            .expect("policy materializes");
        let request = BubblewrapRequest {
            cwd: &root,
            argv: &["true".into()],
            network_mode: NetworkMode::Host,
            stdio_policy: "inherit",
            filesystem_policy: &policy,
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        };
        let plan = request
            .into_plan_with_bwrap(materialized, existing_bwrap_path())
            .expect("plan builds");
        let args = plan
            .args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();

        assert!(!args.windows(3).any(|w| {
            (w[0] == "--bind" || w[0] == "--ro-bind") && w[2] == missing_writable.to_string_lossy()
        }));
        assert!(!args.windows(3).any(|w| {
            (w[0] == "--bind" || w[0] == "--ro-bind")
                && w[2] == missing_deny_outside.to_string_lossy()
        }));
        let staged_guard = args
            .windows(3)
            .position(|w| w[0] == "--ro-bind" && w[2] == missing_deny_guard.to_string_lossy())
            .expect("missing deny guard is staged");
        let writable_bind = args
            .windows(3)
            .position(|w| w[0] == "--bind" && w[2] == writable.to_string_lossy())
            .expect("writable bind exists");
        assert!(staged_guard < writable_bind);
        assert!(
            args.windows(3)
                .skip(writable_bind + 1)
                .any(|w| { w[0] == "--ro-bind" && w[2] == missing_deny_guard.to_string_lossy() })
        );
        assert!(!missing_writable.exists());
        assert!(!missing_deny_outside.exists());
        assert!(!missing_deny_guard.exists());
        std::fs::remove_dir_all(&root).expect("test dirs removed");
    }

    #[test]
    fn existing_policy_paths_keep_bubblewrap_mounts() {
        let root = std::env::temp_dir().join(format!(
            "heimdall-bwrap-existing-policy-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        let writable = root.join("writable");
        let denied = root.join("denied");
        std::fs::create_dir_all(&writable).expect("writable dir created");
        std::fs::write(&denied, "secret").expect("denied file written");
        let policy = FilesystemPolicy::new(
            vec![denied.to_string_lossy().to_string()],
            vec![writable.to_string_lossy().to_string()],
            Default::default(),
        );
        let materialized = FilesystemPolicyMaterializer::new(&root, &policy)
            .materialize()
            .expect("policy materializes");
        let request = BubblewrapRequest {
            cwd: &root,
            argv: &["true".into()],
            network_mode: NetworkMode::Host,
            stdio_policy: "inherit",
            filesystem_policy: &policy,
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        };
        let plan = request
            .into_plan_with_bwrap(materialized, existing_bwrap_path())
            .expect("plan builds");
        let args = plan
            .args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();

        assert!(
            args.windows(3)
                .any(|w| { w[0] == "--bind" && w[2] == writable.to_string_lossy() })
        );
        assert!(
            args.windows(3)
                .any(|w| { w[0] == "--ro-bind" && w[2] == denied.to_string_lossy() })
        );
        std::fs::remove_dir_all(&root).expect("test dirs removed");
    }

    #[test]
    fn negated_absolute_deny_is_not_rendered_as_bubblewrap_mask() {
        let root = std::env::temp_dir().join(format!(
            "heimdall-bwrap-negated-deny-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        let denied = root.join("denied");
        std::fs::create_dir_all(&denied).expect("denied dir created");
        let policy = FilesystemPolicy::new(
            vec![
                denied.to_string_lossy().to_string(),
                format!("!{}", denied.display()),
            ],
            Vec::new(),
            Default::default(),
        );
        let materialized = FilesystemPolicyMaterializer::new(&root, &policy)
            .materialize()
            .expect("policy materializes");
        let request = BubblewrapRequest {
            cwd: &root,
            argv: &["true".into()],
            network_mode: NetworkMode::Host,
            stdio_policy: "inherit",
            filesystem_policy: &policy,
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        };
        let plan = request
            .into_plan_with_bwrap(materialized, existing_bwrap_path())
            .expect("plan builds");
        let args = plan
            .args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();

        assert!(!args.windows(3).any(|w| {
            (w[0] == "--ro-bind" || w[0] == "--bind") && w[2] == denied.to_string_lossy()
        }));
        std::fs::remove_dir_all(&root).expect("test dirs removed");
    }

    #[test]
    fn extract_mount_destinations_covers_mount_vocabulary() {
        let args: Vec<OsString> = [
            "--ro-bind",
            "/usr",
            "/usr",
            "--bind",
            "/src",
            "/dst",
            "--dev-bind",
            "/dev/null",
            "/dev/null",
            "--ro-bind-data",
            "7",
            "/etc/passwd",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/staged/child",
            "--perms",
            "1777",
            "--tmpfs",
            "/var/tmp",
            "--",
            "payload",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let mounts = extract_mount_destinations(&args);

        assert!(mounts.contains(&(PathBuf::from("/usr"), true)));
        assert!(mounts.contains(&(PathBuf::from("/dst"), true)));
        assert!(mounts.contains(&(PathBuf::from("/dev/null"), true)));
        assert!(mounts.contains(&(PathBuf::from("/etc/passwd"), false)));
        assert!(mounts.contains(&(PathBuf::from("/tmp"), false)));
        assert!(mounts.contains(&(PathBuf::from("/staged/child"), false)));
        assert!(mounts.contains(&(PathBuf::from("/var/tmp"), false)));
    }

    #[test]
    fn expand_universe_widens_siblings_and_reopens_only_restored_corridors() {
        let root = std::env::temp_dir().join(format!(
            "heimdall-universe-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        let home = root.join("home");
        for directory in [
            home.join(".ssh"),
            home.join(".config/mise"),
            home.join(".config/nvim"),
            home.join(".config/private"),
            home.join("projects/lib"),
        ] {
            std::fs::create_dir_all(&directory).expect("layout created");
        }
        std::fs::write(home.join(".gitconfig"), "[user]").expect("gitconfig written");
        std::fs::write(home.join(".ssh/id_ed25519"), "key").expect("key written");
        std::fs::write(home.join(".config/mise/config.toml"), "ok").expect("negated written");
        std::fs::write(home.join(".config/private/ledger"), "hush").expect("hidden written");

        let mounts = vec![(home.clone(), true)];
        let denied = BTreeSet::from([home.join(".ssh"), home.join(".config")]);
        let restored = BTreeSet::from([
            home.join(".config/mise/config.toml"),
            home.join(".config/nvim"),
        ]);
        let (universe, traverse) =
            expand_read_universe(&mounts, &denied, &BTreeSet::new(), &restored);

        // Ordinary neighbors stay readable without granting the enclosing tree.
        assert!(universe.contains(&home.join(".gitconfig")));
        assert!(universe.contains(&home.join("projects")));
        assert!(!universe.contains(&home));
        // Denied subtrees expose only their restored corridors.
        assert!(universe.contains(&home.join(".config/mise/config.toml")));
        assert!(traverse.contains(&home.join(".config/mise")));
        assert!(universe.contains(&home.join(".config/nvim")));
        assert!(!universe.contains(&home.join(".config/private")));
        assert!(!universe.contains(&home.join(".config")));
        assert!(
            !universe
                .iter()
                .any(|path| path.starts_with(home.join(".ssh")))
        );
        // The strict filesystem root remains an execute-only traversal node.
        assert!(traverse.contains(Path::new("/")));
        std::fs::remove_dir_all(&root).expect("layout removed");
    }

    #[test]
    fn landlock_enforcement_drops_masks_and_plans_read_grants() {
        let root = std::env::temp_dir().join(format!(
            "heimdall-bwrap-landlock-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        let denied = root.join(".secret");
        std::fs::create_dir_all(&denied).expect("denied dir created");
        let materialized = MaterializedFilesystemPolicy::new(
            BTreeSet::from([denied.clone()]),
            BTreeSet::new(),
            BTreeSet::new(),
        );
        let cwd = std::env::current_dir().expect("cwd exists");
        let request = BubblewrapRequest {
            cwd: &cwd,
            argv: &["true".into()],
            network_mode: NetworkMode::Host,
            stdio_policy: "inherit",
            filesystem_policy: &FilesystemPolicy::default(),
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        };
        let plan = request
            .into_plan_with_enforcement(
                materialized,
                existing_bwrap_path(),
                DenyEnforcement::LandlockReadRejection,
            )
            .expect("plan builds");
        std::fs::remove_dir_all(&root).expect("denied dir removed");
        let args = plan
            .args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();

        assert!(
            !args
                .windows(3)
                .any(|w| (w[0] == "--ro-bind" || w[0] == "--bind")
                    && w[2] == denied.to_string_lossy()),
            "mask mounts are replaced by landlock grants"
        );
        let grants: Vec<_> = args
            .windows(2)
            .filter_map(|w| {
                (w[0] == "--read-grant" || w[0] == "--read-traverse")
                    .then(|| w[1].to_string())
                    .or(None)
            })
            .collect();
        assert!(
            !grants.is_empty(),
            "landlock plans must carry read-grant roots"
        );
        assert!(
            !grants
                .iter()
                .any(|grant| Path::new(grant.as_str()) == denied),
            "denied paths never appear among grants"
        );
    }
}
