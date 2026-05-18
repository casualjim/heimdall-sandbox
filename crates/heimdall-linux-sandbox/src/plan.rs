use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::launcher::BubblewrapLauncher;
use crate::policy::{
    FilesystemPolicy, FilesystemPolicyMaterializer, MaterializedFilesystemPolicy, NetworkMode,
    ProcMode,
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
        BubblewrapPlanner::new(self).prepare_with_materialized(
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
        BubblewrapPlanner::new(self).prepare_with_materialized(materialized, launcher)
    }
}

struct BubblewrapPlanner<'a> {
    request: BubblewrapRequest<'a>,
}

impl<'a> BubblewrapPlanner<'a> {
    const fn new(request: BubblewrapRequest<'a>) -> Self {
        Self { request }
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
        Ok(DiscoveredBubblewrap { request, launcher })
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
        }
        .with_materialized(materialized)
        .prepare_resources()?
        .build()
    }
}

struct DiscoveredBubblewrap<'a> {
    request: BubblewrapRequest<'a>,
    launcher: BubblewrapLauncher,
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
        }
    }
}

struct MaterializedBubblewrap<'a> {
    request: BubblewrapRequest<'a>,
    launcher: BubblewrapLauncher,
    materialized: MaterializedFilesystemPolicy,
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
        })
    }
}

struct PreparedBubblewrap<'a> {
    request: BubblewrapRequest<'a>,
    launcher: BubblewrapLauncher,
    materialized: MaterializedFilesystemPolicy,
    resources: BubblewrapResources,
}

impl PreparedBubblewrap<'_> {
    fn build(self) -> Result<BubblewrapPlan> {
        let args = BubblewrapArgBuilder::new(
            &self.request,
            &self.materialized,
            &self.resources,
            &self.launcher,
        )
        .build()?;

        Ok(BubblewrapPlan {
            bwrap: self.launcher.path,
            args,
            resources: self.resources,
        })
    }
}

/// Prepared bubblewrap invocation and resources that must stay alive until spawn.
pub struct BubblewrapPlan {
    bwrap: PathBuf,
    args: Vec<OsString>,
    resources: BubblewrapResources,
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

    fn must_stage_mountpoint_for(&self, child: &Self) -> bool {
        self.is_directory_mask()
            && child.destination != self.destination
            && child.destination.starts_with(self.destination)
    }

    fn mountpoint_kind(&self) -> MountpointKind {
        match self.kind {
            PolicyMountKind::VirtualFile { .. } => MountpointKind::File,
            PolicyMountKind::Writable
            | PolicyMountKind::Readable
            | PolicyMountKind::Deny
            | PolicyMountKind::Protected => {
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
}

impl PolicyMountKind {
    const fn precedence(self) -> u8 {
        match self {
            Self::Writable => 0,
            Self::Readable => 1,
            Self::VirtualFile { .. } => 2,
            Self::Deny => 3,
            Self::Protected => 4,
        }
    }
}

struct BubblewrapArgBuilder<'a> {
    request: &'a BubblewrapRequest<'a>,
    materialized: &'a MaterializedFilesystemPolicy,
    resources: &'a BubblewrapResources,
    launcher: &'a BubblewrapLauncher,
    args: Vec<OsString>,
}

impl<'a> BubblewrapArgBuilder<'a> {
    fn new(
        request: &'a BubblewrapRequest<'a>,
        materialized: &'a MaterializedFilesystemPolicy,
        resources: &'a BubblewrapResources,
        launcher: &'a BubblewrapLauncher,
    ) -> Self {
        Self {
            request,
            materialized,
            resources,
            launcher,
            args: Vec::new(),
        }
    }

    fn build(mut self) -> Result<Vec<OsString>> {
        self.add_namespaces();
        self.add_readonly_base_filesystem();
        self.add_policy_mounts();
        self.add_inner_reentry()?;
        Ok(self.args)
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

    fn add_readonly_base_filesystem(&mut self) {
        for root in Self::platform_read_roots() {
            if root.exists() {
                self.ro_bind(&root, &root);
            }
        }
        if self.request.network_mode == NetworkMode::Host {
            self.add_host_network_runtime_paths();
        }
        if let Some(home) = dirs_home() {
            for alias in path_aliases(&home) {
                if alias.is_dir() {
                    self.ro_bind(&alias, &alias);
                }
            }
        }
    }

    fn add_policy_mounts(&mut self) {
        self.ro_bind(self.request.cwd, self.request.cwd);

        let empty_file = self.resources.empty_file();
        let empty_dir = self.resources.empty_dir();
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
        mounts.extend(self.materialized.deny_targets().iter().map(|path| {
            let source = if path.is_dir() {
                empty_dir.as_path()
            } else {
                empty_file.as_path()
            };
            PolicyMount::deny(source, path)
        }));
        mounts.extend(self.materialized.protected_targets().iter().map(|path| {
            let source = if path.exists() && !path.is_dir() {
                empty_file.as_path()
            } else {
                empty_dir.as_path()
            };
            PolicyMount::protected(source, path)
        }));
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

            self.add_policy_mount(mount);
        }
    }

    fn add_policy_mount(&mut self, mount: PolicyMount<'_>) {
        match mount.kind {
            PolicyMountKind::Writable => self.bind(mount.source, mount.destination),
            PolicyMountKind::Readable => self.ro_bind(mount.source, mount.destination),
            PolicyMountKind::VirtualFile { fd } => {
                self.args.push("--ro-bind-data".into());
                self.args.push(fd.to_string().into());
                self.args.push(mount.destination.as_os_str().to_os_string());
            }
            PolicyMountKind::Deny | PolicyMountKind::Protected => {
                self.ro_bind(mount.source, mount.destination);
            }
        }
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
        self.ro_bind(&current_exe, Path::new("/heimdall-inner"));
        for library in Self::runtime_libraries(&current_exe) {
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
        self.args.push("--".into());
        self.args
            .extend(self.request.argv.iter().map(OsString::from));
        Ok(())
    }

    fn runtime_libraries(executable: &Path) -> Vec<PathBuf> {
        let Some(parent) = executable.parent() else {
            return Vec::new();
        };
        ["libwebgpu_dawn.so"]
            .into_iter()
            .map(|name| parent.join(name))
            .filter(|path| path.is_file())
            .collect()
    }

    fn add_host_network_runtime_paths(&mut self) {
        self.add_resolver_symlink_target();
        self.add_runtime_socket(Path::new("/run/dbus/system_bus_socket"));
    }

    fn add_resolver_symlink_target(&mut self) {
        let Some(target) = Self::resolver_symlink_target(Path::new("/etc/resolv.conf")) else {
            return;
        };
        self.add_destination_parent_dirs(&target);
        self.ro_bind(&target, &target);
    }

    fn add_runtime_socket(&mut self, socket: &Path) {
        if !socket.exists() {
            return;
        }
        self.add_destination_parent_dirs(socket);
        self.bind(socket, socket);
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
        };
        let plan = request
            .into_plan_with_bwrap(empty_materialized_policy(), PathBuf::from("/usr/bin/bwrap"))
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
        };
        let plan = request
            .into_plan_with_bwrap(empty_materialized_policy(), PathBuf::from("/usr/bin/bwrap"))
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
        };
        let plan = request
            .into_plan_with_bwrap(empty_materialized_policy(), PathBuf::from("/usr/bin/bwrap"))
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
        };
        let plan = request
            .into_plan_with_launcher(
                empty_materialized_policy(),
                BubblewrapLauncher {
                    path: PathBuf::from("/usr/bin/bwrap"),
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
        };
        let plan = request
            .into_plan_with_launcher(
                empty_materialized_policy(),
                BubblewrapLauncher {
                    path: PathBuf::from("/usr/bin/bwrap"),
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
        };
        let plan = request
            .into_plan_with_bwrap(empty_materialized_policy(), PathBuf::from("/usr/bin/bwrap"))
            .expect("plan builds");

        assert!(!plan.args.iter().any(|arg| arg == "--proc"));
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

        let resolved = BubblewrapArgBuilder::resolver_symlink_target(&link);
        std::fs::remove_dir_all(&root).expect("test dir removed");

        assert_eq!(resolved, Some(target));
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
        };
        let plan = request
            .into_plan_with_bwrap(empty_materialized_policy(), PathBuf::from("/usr/bin/bwrap"))
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
        };
        let plan = request
            .into_plan_with_bwrap(
                MaterializedFilesystemPolicy::new(
                    BTreeSet::from([denied.clone()]),
                    BTreeSet::from([cwd.clone()]),
                    BTreeSet::new(),
                ),
                PathBuf::from("/usr/bin/bwrap"),
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
        };
        let plan = request
            .into_plan_with_bwrap(
                MaterializedFilesystemPolicy::new(
                    BTreeSet::from([denied.clone()]),
                    BTreeSet::from([writable.clone()]),
                    BTreeSet::new(),
                ),
                PathBuf::from("/usr/bin/bwrap"),
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
}
