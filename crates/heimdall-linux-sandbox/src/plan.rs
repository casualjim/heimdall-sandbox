use std::collections::BTreeSet;
use std::ffi::OsString;
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyMountKind {
    Writable,
    VirtualFile { fd: i32 },
    Deny,
    Protected,
}

impl PolicyMountKind {
    const fn precedence(self) -> u8 {
        match self {
            Self::Writable => 0,
            Self::VirtualFile { .. } => 1,
            Self::Deny => 2,
            Self::Protected => 3,
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
    }

    fn add_readonly_base_filesystem(&mut self) {
        for root in Self::platform_read_roots() {
            if root.exists() {
                self.ro_bind(&root, &root);
            }
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

        for mount in mounts {
            match mount.kind {
                PolicyMountKind::Writable => self.bind(mount.source, mount.destination),
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
    }

    fn add_inner_reentry(&mut self) -> Result<()> {
        let current_exe = std::env::current_exe().map_err(|error| {
            Error::sandbox_misconfiguration(format!(
                "failed to resolve current executable: {error}"
            ))
        })?;
        let inner_exe = Self::inner_executable(&current_exe);
        self.ro_bind(&inner_exe, Path::new("/heimdall-inner"));
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

    fn inner_executable(current_exe: &Path) -> PathBuf {
        let Some(parent) = current_exe.parent() else {
            return current_exe.to_path_buf();
        };
        let candidate = parent.join("heimdall-sandbox-inner");
        if candidate.is_file() {
            candidate
        } else {
            current_exe.to_path_buf()
        }
    }

    fn ro_bind(&mut self, source: &Path, destination: &Path) {
        self.mount("--ro-bind", source, destination);
    }

    fn bind(&mut self, source: &Path, destination: &Path) {
        self.mount("--bind", source, destination);
    }

    fn mount(&mut self, flag: &str, source: &Path, destination: &Path) {
        self.args.push(flag.into());
        self.args.push(source.as_os_str().to_os_string());
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
}
