//! Seatbelt policy text builder.

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use heimdall_sandbox_policy::{AgentPolicy, MaterializedFilesystemPolicy, NetworkMode};

use crate::paths::{
    darwin_user_cache_dir, darwin_user_temp_dir, dirs_home, env_socket_path, gpg_agent_info_socket,
    optional_path_exists, path_aliases, path_has_prefix, path_matcher, regex_escape_path,
};
use crate::plan::SeatbeltPolicy;
use crate::request::{AgentRuntimePaths, SeatbeltRequest};
use crate::{
    BASE_POLICY, Error, GPG_RUNTIME_SOCKET_NAMES, GPGCONF_SOCKET_KEYS, NETWORK_SUPPORT_POLICY,
    PLATFORM_DEFAULTS, Result,
};

struct DecomposedTargets {
    deny_targets: BTreeSet<PathBuf>,
    writable_targets: BTreeSet<PathBuf>,
    protected_targets: BTreeSet<PathBuf>,
    readable_targets: BTreeSet<PathBuf>,
    missing_deny_guards: BTreeSet<PathBuf>,
}

pub(crate) struct SeatbeltPolicyBuilder<'a> {
    request: &'a SeatbeltRequest<'a>,
    targets: DecomposedTargets,
    params: Vec<(String, PathBuf)>,
    next_param: usize,
    home_dir: Option<PathBuf>,
}

impl<'a> SeatbeltPolicyBuilder<'a> {
    pub(crate) fn new(
        request: &'a SeatbeltRequest<'a>,
        materialized: MaterializedFilesystemPolicy,
    ) -> Self {
        let readable_targets = materialized.readable_targets().clone();
        let missing_deny_guards = materialized.missing_deny_guards().clone();
        let (deny_targets, writable_targets, protected_targets) = materialized.into_parts();
        let targets = DecomposedTargets {
            deny_targets,
            writable_targets,
            protected_targets,
            readable_targets,
            missing_deny_guards,
        };
        let home_dir = dirs_home().and_then(|h| {
            let h = h.canonicalize().ok()?;
            (h.is_dir()).then_some(h)
        });
        Self {
            request,
            targets,
            params: Vec::new(),
            next_param: 0,
            home_dir,
        }
    }

    pub(crate) fn build(self) -> Result<SeatbeltPolicy> {
        let agent_runtime_paths = Self::agent_runtime_paths(self.request.agent_policy)?;
        self.build_with_agent_runtime_paths(&agent_runtime_paths)
    }

    pub(crate) fn build_with_agent_runtime_paths(
        mut self,
        agent_runtime_paths: &AgentRuntimePaths,
    ) -> Result<SeatbeltPolicy> {
        let mut text = String::new();
        text.push_str(BASE_POLICY);
        text.push('\n');
        text.push_str(PLATFORM_DEFAULTS);
        text.push('\n');
        let heimdall_wildcard = self.heimdall_wildcard_write_deny_policy();
        let write_exclusions = self.write_exclusions(agent_runtime_paths);
        let deny_exclusions = self.deny_exclusions(agent_runtime_paths);
        text.push_str(&self.read_policy(agent_runtime_paths)?);
        text.push_str(&self.write_policy(&write_exclusions));
        text.push_str(&self.platform_writable_policy()?);
        text.push_str(&self.deny_policy(&deny_exclusions, agent_runtime_paths));
        text.push_str(&self.virtual_write_deny_policy());
        text.push_str(&heimdall_wildcard);
        text.push_str(&self.agent_socket_policy(agent_runtime_paths));
        text.push_str(&self.network_policy()?);
        Ok(SeatbeltPolicy {
            text,
            params: self.params,
        })
    }

    fn read_policy(&mut self, agent_runtime_paths: &AgentRuntimePaths) -> Result<String> {
        let mut policy = String::from("; allow read-only file operations\n");
        self.push_readable_root_policy(&mut policy, "READABLE_ROOT", self.request.cwd);
        for root in Self::platform_read_roots()? {
            self.push_readable_root_policy(&mut policy, "PLATFORM_READ_ROOT", &root);
        }
        let readable_targets = std::mem::take(&mut self.targets.readable_targets);
        for readable in readable_targets {
            self.push_readable_root_policy(&mut policy, "READABLE_TARGET", &readable);
        }
        for readable in &agent_runtime_paths.readable_dirs {
            self.push_readable_root_policy(&mut policy, "AGENT_READABLE", readable);
        }
        if let Some(home) = self.home_dir.clone() {
            self.push_readable_root_policy(&mut policy, "HOME_DIR", &home);
        }
        Ok(policy)
    }

    fn push_readable_root_policy(&mut self, policy: &mut String, prefix: &str, root: &Path) {
        for alias in path_aliases(root) {
            let readable_root = self.path_param(prefix, &alias);
            policy.push_str(&format!(
                "(allow file-read* (subpath (param \"{readable_root}\")))\n"
            ));
        }
    }

    pub(crate) fn platform_read_roots() -> Result<Vec<PathBuf>> {
        let Some(path_var) = std::env::var_os("PATH") else {
            return Ok(Vec::new());
        };
        Self::platform_read_roots_from_path_var(
            &path_var,
            &[Path::new("/opt/homebrew"), Path::new("/usr/local")],
        )
    }

    pub(crate) fn platform_read_roots_from_path_var(
        path_var: &OsStr,
        supported_prefixes: &[&Path],
    ) -> Result<Vec<PathBuf>> {
        let mut roots = BTreeSet::new();
        for path_dir in std::env::split_paths(path_var).filter(|path| path.is_absolute()) {
            let Some(read_root) = Self::read_root_for_path_dir(&path_dir, supported_prefixes)
            else {
                continue;
            };
            match read_root.try_exists() {
                Ok(true) => {
                    roots.insert(read_root);
                }
                Ok(false) => {}
                Err(source) => {
                    return Err(Error::PlatformDirectory {
                        message: format!("failed to inspect {}: {source}", read_root.display()),
                    });
                }
            }
        }
        Ok(roots.into_iter().collect())
    }

    fn read_root_for_path_dir(path_dir: &Path, supported_prefixes: &[&Path]) -> Option<PathBuf> {
        for prefix in supported_prefixes {
            let prefix = *prefix;
            if path_dir.starts_with(prefix) {
                return Some(prefix.to_path_buf());
            }
        }
        None
    }

    fn write_policy(&mut self, exclusions: &BTreeSet<PathBuf>) -> String {
        if self.targets.writable_targets.is_empty() {
            return String::new();
        }
        let writable_targets = std::mem::take(&mut self.targets.writable_targets);
        let mut rules = String::new();
        for writable in writable_targets {
            for writable_alias in path_aliases(&writable) {
                let root_param = self.path_param("WRITABLE_ROOT", &writable_alias);
                let root_match = path_matcher(&writable_alias, &root_param);
                let mut require_parts = vec![root_match];
                for excluded in exclusions
                    .iter()
                    .filter(|excluded| path_has_prefix(excluded, &writable_alias))
                {
                    let excluded_param = self.path_param("WRITABLE_EXCLUDED", excluded);
                    require_parts.push(format!(
                        "(require-not (literal (param \"{excluded_param}\")))"
                    ));
                    require_parts.push(format!(
                        "(require-not (subpath (param \"{excluded_param}\")))"
                    ));
                }
                rules.push_str("(allow file-write*\n  (require-all ");
                rules.push_str(&require_parts.join(" "));
                rules.push_str("))\n");
            }
        }
        rules
    }

    fn write_exclusions(&self, agent_runtime_paths: &AgentRuntimePaths) -> BTreeSet<PathBuf> {
        let mut exclusions = BTreeSet::new();
        for denied in &self.targets.deny_targets {
            exclusions.extend(path_aliases(denied));
        }
        for guard in &self.targets.missing_deny_guards {
            exclusions.extend(path_aliases(guard));
        }
        for protected in &self.targets.protected_targets {
            exclusions.extend(path_aliases(protected));
        }
        for path in self.request.filesystem_policy.virtual_files().keys() {
            exclusions.extend(path_aliases(path));
        }
        Self::extend_agent_path_aliases(&mut exclusions, agent_runtime_paths);
        exclusions
    }

    fn deny_policy(
        &mut self,
        exclusions: &BTreeSet<PathBuf>,
        agent_runtime_paths: &AgentRuntimePaths,
    ) -> String {
        let mut rules = String::new();
        let deny_targets = std::mem::take(&mut self.targets.deny_targets);
        for denied in deny_targets {
            self.push_deny_policy(&mut rules, &denied, exclusions, agent_runtime_paths, false);
        }
        let missing_deny_guards = std::mem::take(&mut self.targets.missing_deny_guards);
        for guard in missing_deny_guards {
            self.push_deny_policy(&mut rules, &guard, exclusions, agent_runtime_paths, true);
        }
        let protected_targets = std::mem::take(&mut self.targets.protected_targets);
        for protected in protected_targets {
            for alias in path_aliases(&protected) {
                let param = self.path_param("PROTECTED", &alias);
                rules.push_str(&format!(
                    "(deny file-write* (literal (param \"{param}\")))\n"
                ));
                rules.push_str(&format!(
                    "(deny file-write* (subpath (param \"{param}\")))\n"
                ));
            }
        }
        rules
    }

    fn push_deny_policy(
        &mut self,
        rules: &mut String,
        denied: &Path,
        exclusions: &BTreeSet<PathBuf>,
        agent_runtime_paths: &AgentRuntimePaths,
        force_subpath_deny: bool,
    ) {
        for alias in path_aliases(denied) {
            if Self::agent_override_covers_path(&alias, agent_runtime_paths) {
                continue;
            }
            let param = self.path_param("DENY", &alias);
            rules.push_str(&format!(
                "(deny file-read* (literal (param \"{param}\")))\n"
            ));
            rules.push_str(&format!(
                "(deny file-write* (literal (param \"{param}\")))\n"
            ));
            if alias.is_dir() || force_subpath_deny {
                let subpath_match = format!("(subpath (param \"{param}\"))");
                let mut require_parts = vec![subpath_match];
                for excluded in exclusions
                    .iter()
                    .filter(|excluded| path_has_prefix(excluded, &alias) && *excluded != &alias)
                {
                    let excluded_param = self.path_param("DENY_EXCLUDED", excluded);
                    require_parts.push(format!(
                        "(require-not (literal (param \"{excluded_param}\")))"
                    ));
                    require_parts.push(format!(
                        "(require-not (subpath (param \"{excluded_param}\")))"
                    ));
                }
                rules.push_str("(deny file-read*\n  (require-all ");
                rules.push_str(&require_parts.join(" "));
                rules.push_str("))\n");
                rules.push_str("(deny file-write*\n  (require-all ");
                rules.push_str(&require_parts.join(" "));
                rules.push_str("))\n");
            }
        }
    }

    fn deny_exclusions(&self, agent_runtime_paths: &AgentRuntimePaths) -> BTreeSet<PathBuf> {
        let mut exclusions = BTreeSet::new();
        for writable in &self.targets.writable_targets {
            exclusions.extend(path_aliases(writable));
        }
        for readable in &self.targets.readable_targets {
            exclusions.extend(path_aliases(readable));
        }
        Self::extend_agent_path_aliases(&mut exclusions, agent_runtime_paths);
        exclusions
    }

    fn extend_agent_path_aliases(
        exclusions: &mut BTreeSet<PathBuf>,
        agent_runtime_paths: &AgentRuntimePaths,
    ) {
        for readable in &agent_runtime_paths.readable_dirs {
            exclusions.extend(path_aliases(readable));
        }
        for socket in &agent_runtime_paths.sockets {
            exclusions.extend(path_aliases(socket));
        }
    }

    fn agent_override_covers_path(path: &Path, agent_runtime_paths: &AgentRuntimePaths) -> bool {
        agent_runtime_paths
            .sockets
            .iter()
            .flat_map(|socket| path_aliases(socket).into_iter())
            .any(|socket| socket == path)
            || agent_runtime_paths
                .readable_dirs
                .iter()
                .flat_map(|readable| path_aliases(readable).into_iter())
                .any(|readable| path_has_prefix(path, &readable))
    }

    fn virtual_write_deny_policy(&mut self) -> String {
        let mut rules = String::new();
        for virtual_target in self
            .request
            .filesystem_policy
            .virtual_files()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
        {
            for alias in path_aliases(&virtual_target) {
                let param = self.path_param("VIRTUAL", &alias);
                rules.push_str(&format!(
                    "(deny file-write* (literal (param \"{param}\")))\n"
                ));
                rules.push_str(&format!(
                    "(deny file-write* (subpath (param \"{param}\")))\n"
                ));
            }
        }
        rules
    }

    fn heimdall_wildcard_write_deny_policy(&self) -> String {
        if !self
            .targets
            .writable_targets
            .iter()
            .any(|target| target == self.request.cwd)
        {
            return String::new();
        }
        path_aliases(self.request.cwd)
            .into_iter()
            .map(|root| {
                let regex = format!(r#"^{}/\.heimdall-[^/]*(/.*)?$"#, regex_escape_path(&root));
                format!(
                    r#"(deny file-write* (regex #"{regex}"))
"#
                )
            })
            .collect()
    }

    /// Platform-specific writable directories that should be accessible unconditionally.
    ///
    /// On macOS this includes the per-user temp directory (`DARWIN_USER_TEMP_DIR`) and the
    /// per-user cache directory (`DARWIN_USER_CACHE_DIR`), which are the macOS equivalents
    /// of Linux `/tmp` and `/var/cache`. These are needed by tools like `git`, `xcrun`,
    /// and Node.js/OpenSSL for cache and temp files under `/var/folders/...`.
    fn platform_writable_policy(&mut self) -> Result<String> {
        let mut policy = String::new();

        if let Ok(temp_dir) = darwin_user_temp_dir() {
            let param = self.path_param("PLATFORM_WRITABLE", &temp_dir);
            policy.push_str(&format!(
                "; per-user temp directory (DARWIN_USER_TEMP_DIR)\n\
                 (allow file-read* file-write* (subpath (param \"{}\")))\n",
                param
            ));
        }

        if let Ok(cache_dir) = darwin_user_cache_dir() {
            let param = self.path_param("PLATFORM_WRITABLE", &cache_dir);
            policy.push_str(&format!(
                "; per-user cache directory (DARWIN_USER_CACHE_DIR)\n\
                 (allow file-read* file-write* (subpath (param \"{}\")))\n",
                param
            ));
        }

        Ok(policy)
    }

    fn agent_socket_policy(&mut self, agent_runtime_paths: &AgentRuntimePaths) -> String {
        let mut policy = String::new();
        for socket in &agent_runtime_paths.sockets {
            for socket_alias in path_aliases(socket) {
                let socket_param = self.path_param("AGENT_SOCKET", &socket_alias);
                policy.push_str(&format!(
                    "; agent socket access\n\
                     (allow network-outbound (literal (param \"{socket_param}\")))\n\
                     (allow file-read* file-write* file-ioctl file-test-existence \
                     (literal (param \"{socket_param}\")))\n"
                ));
                if let Some(parent) = socket_alias.parent() {
                    let parent_param = self.path_param("AGENT_SOCKET_PARENT", parent);
                    policy.push_str(&format!(
                        "(allow file-read-metadata file-test-existence \
                         (literal (param \"{parent_param}\")))\n\
                         (allow file-read-metadata file-test-existence \
                         (subpath (param \"{parent_param}\")))\n"
                    ));
                }
            }
        }
        policy
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
                return Err(Error::AgentDiscovery {
                    message: format!("failed to run gpgconf --list-dirs: {error}"),
                });
            }
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::AgentDiscovery {
                message: format!("gpgconf --list-dirs failed: {stderr}"),
            });
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::insert_gpgconf_runtime_paths_from_list_dirs(paths, &stdout)
    }

    pub(crate) fn insert_gpgconf_runtime_paths_from_list_dirs(
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

    fn network_policy(&mut self) -> Result<String> {
        if self.request.network_mode == NetworkMode::None {
            return Ok(String::new());
        }
        Ok(format!(
            "(allow network-outbound)\n(allow network-inbound)\n{}\n",
            NETWORK_SUPPORT_POLICY
        ))
    }

    fn path_param(&mut self, prefix: &str, path: &Path) -> String {
        let key = format!("{prefix}_{}", self.next_param);
        self.next_param += 1;
        self.params.push((key.clone(), path.to_path_buf()));
        key
    }
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use super::{AgentRuntimePaths, SeatbeltPolicyBuilder};

    fn unique_test_dir(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "heimdall-seatbelt-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("test dir created");
        root
    }

    #[test]
    fn platform_read_roots_filter_supported_existing_and_missing_roots() {
        let root = std::env::temp_dir().join(format!(
            "heimdall-seatbelt-platform-roots-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        let supported = root.join("supported");
        let unsupported = root.join("unsupported");
        let missing = root.join("missing");
        std::fs::create_dir_all(supported.join("bin")).expect("supported bin created");
        std::fs::create_dir_all(unsupported.join("bin")).expect("unsupported bin created");
        let path_var = std::env::join_paths([
            supported.join("bin"),
            unsupported.join("bin"),
            missing.join("bin"),
        ])
        .expect("PATH value joins");

        let roots = SeatbeltPolicyBuilder::platform_read_roots_from_path_var(
            &path_var,
            &[supported.as_path(), missing.as_path()],
        )
        .expect("platform roots resolve");

        assert_eq!(roots, vec![supported]);
        std::fs::remove_dir_all(root).expect("test dir removed");
    }

    #[cfg(unix)]
    #[test]
    fn platform_read_roots_reject_indeterminate_supported_roots() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "heimdall-seatbelt-indeterminate-platform-root-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        let blocked = root.join("blocked");
        let supported = blocked.join("supported");
        std::fs::create_dir_all(&blocked).expect("blocked dir created");
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000))
            .expect("blocked permissions set");
        let path_var = std::env::join_paths([supported.join("bin")]).expect("PATH value joins");

        let result =
            SeatbeltPolicyBuilder::platform_read_roots_from_path_var(&path_var, &[&supported]);

        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700))
            .expect("blocked permissions restored");
        std::fs::remove_dir_all(root).expect("test dir removed");
        assert!(result.is_err());
    }

    #[test]
    fn gpgconf_list_dirs_discovers_keyboxd_and_dirmngr_sockets() {
        let root = unique_test_dir("gpgconf-sockets");
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

        SeatbeltPolicyBuilder::insert_gpgconf_runtime_paths_from_list_dirs(&mut paths, &list_dirs)
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
}
