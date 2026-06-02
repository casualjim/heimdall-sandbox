//! macOS Seatbelt sandbox planning.

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use heimdall_sandbox_policy::{
    AgentPolicy, ConcretePathState, FilesystemPolicy, FilesystemPolicyMaterializer,
    MaterializedFilesystemPolicy, NetworkMode, ProcMode, concrete_path_state,
};
use thiserror::Error as ThisError;

/// Absolute path to the macOS Seatbelt launcher.
pub const SEATBELT_EXECUTABLE: &str = "/usr/bin/sandbox-exec";

const BASE_POLICY: &str = include_str!("seatbelt_base_policy.sbpl");

const PLATFORM_DEFAULTS: &str = include_str!("restricted_read_only_platform_defaults.sbpl");

const NETWORK_SUPPORT_POLICY: &str = include_str!("seatbelt_network_policy.sbpl");

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

/// Result type for macOS sandbox operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by macOS sandbox planning.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Shared sandbox policy materialization failed.
    #[error(transparent)]
    Policy(#[from] heimdall_sandbox_policy::Error),
    /// A required platform directory path could not be resolved.
    #[error("failed to resolve platform directory: {message}")]
    PlatformDirectory {
        /// Description of the missing directory.
        message: String,
    },
    /// Agent socket discovery failed.
    #[error("failed to discover agent runtime paths: {message}")]
    AgentDiscovery {
        /// Discovery failure details.
        message: String,
    },
}

/// Structured input used to build a macOS Seatbelt invocation.
pub struct SeatbeltRequest<'a> {
    /// Child working directory and filesystem policy root.
    pub cwd: &'a Path,
    /// Child argv to pass to `sandbox-exec`.
    pub argv: &'a [String],
    /// Child network isolation policy.
    pub network_mode: NetworkMode,
    /// Child filesystem isolation policy.
    pub filesystem_policy: &'a FilesystemPolicy,
    /// Proc mount policy accepted for shared config compatibility.
    pub proc_mode: ProcMode,
    /// Host agent sockets explicitly enabled for access.
    pub agent_policy: AgentPolicy,
}

#[derive(Debug, Default)]
struct AgentRuntimePaths {
    sockets: BTreeSet<PathBuf>,
    readable_dirs: BTreeSet<PathBuf>,
}

impl SeatbeltRequest<'_> {
    /// Convert this request into a prepared Seatbelt invocation.
    ///
    /// # Errors
    ///
    /// Returns a sandbox misconfiguration when filesystem policy materialization fails.
    pub fn into_plan(self) -> Result<SeatbeltPlan> {
        let materialized =
            FilesystemPolicyMaterializer::new(self.cwd, self.filesystem_policy).materialize()?;
        self.into_plan_with_materialized(materialized)
    }

    fn into_plan_with_materialized(
        self,
        materialized: MaterializedFilesystemPolicy,
    ) -> Result<SeatbeltPlan> {
        let builder = SeatbeltPolicyBuilder::new(&self, materialized);
        let policy = builder.build()?;
        self.into_plan_with_policy(policy)
    }

    #[cfg(test)]
    fn into_plan_with_materialized_and_agent_runtime_paths(
        self,
        materialized: MaterializedFilesystemPolicy,
        agent_runtime_paths: AgentRuntimePaths,
    ) -> Result<SeatbeltPlan> {
        let builder = SeatbeltPolicyBuilder::new(&self, materialized);
        let policy = builder.build_with_agent_runtime_paths(&agent_runtime_paths)?;
        self.into_plan_with_policy(policy)
    }

    fn into_plan_with_policy(self, policy: SeatbeltPolicy) -> Result<SeatbeltPlan> {
        let mut args = Vec::with_capacity(4 + policy.params.len() + self.argv.len());
        args.push("-p".to_string());
        args.push(policy.text);
        args.extend(
            policy
                .params
                .into_iter()
                .map(|(key, value)| format!("-D{key}={}", value.to_string_lossy())),
        );
        args.push("--".to_string());
        args.extend(self.argv.iter().cloned());
        Ok(SeatbeltPlan {
            seatbelt: PathBuf::from(SEATBELT_EXECUTABLE),
            args,
        })
    }
}

/// Prepared Seatbelt invocation.
pub struct SeatbeltPlan {
    seatbelt: PathBuf,
    args: Vec<String>,
}

impl SeatbeltPlan {
    /// Convert this prepared Seatbelt invocation into a command.
    #[must_use]
    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.seatbelt);
        command.args(&self.args);
        command
    }

    /// Seatbelt executable path.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.seatbelt
    }

    /// Seatbelt command arguments.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }
}

struct SeatbeltPolicy {
    text: String,
    params: Vec<(String, PathBuf)>,
}

struct DecomposedTargets {
    deny_targets: BTreeSet<PathBuf>,
    writable_targets: BTreeSet<PathBuf>,
    protected_targets: BTreeSet<PathBuf>,
    readable_targets: BTreeSet<PathBuf>,
    missing_deny_guards: BTreeSet<PathBuf>,
}

struct SeatbeltPolicyBuilder<'a> {
    request: &'a SeatbeltRequest<'a>,
    targets: DecomposedTargets,
    params: Vec<(String, PathBuf)>,
    next_param: usize,
    home_dir: Option<PathBuf>,
}

impl<'a> SeatbeltPolicyBuilder<'a> {
    fn new(request: &'a SeatbeltRequest<'a>, materialized: MaterializedFilesystemPolicy) -> Self {
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

    fn build(self) -> Result<SeatbeltPolicy> {
        let agent_runtime_paths = Self::agent_runtime_paths(self.request.agent_policy)?;
        self.build_with_agent_runtime_paths(&agent_runtime_paths)
    }

    fn build_with_agent_runtime_paths(
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

    fn platform_read_roots() -> Result<Vec<PathBuf>> {
        let Some(path_var) = std::env::var_os("PATH") else {
            return Ok(Vec::new());
        };
        Self::platform_read_roots_from_path_var(
            &path_var,
            &[Path::new("/opt/homebrew"), Path::new("/usr/local")],
        )
    }

    fn platform_read_roots_from_path_var(
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
        .map(|state| matches!(state, ConcretePathState::Existing))
        .map_err(Into::into)
}

fn path_matcher(path: &Path, param: &str) -> String {
    if path.is_dir() {
        format!("(subpath (param \"{param}\"))")
    } else {
        format!("(literal (param \"{param}\"))")
    }
}

fn path_has_prefix(path: &Path, prefix: &Path) -> bool {
    path == prefix || path.starts_with(prefix)
}

fn path_aliases(path: &Path) -> BTreeSet<PathBuf> {
    let mut aliases = BTreeSet::from([path.to_path_buf()]);
    if let Some(canonical) = canonicalize_existing_prefix(path) {
        aliases.insert(canonical);
    }
    aliases
}

fn canonicalize_existing_prefix(path: &Path) -> Option<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Some(canonical);
    }
    let mut missing = Vec::new();
    let mut current = path;
    loop {
        if let Ok(canonical) = current.canonicalize() {
            let mut rebuilt = canonical;
            for component in missing.iter().rev() {
                rebuilt.push(component);
            }
            return Some(rebuilt);
        }
        let name = current.file_name()?.to_os_string();
        missing.push(name);
        current = current.parent()?;
    }
}

fn regex_escape_path(path: &Path) -> String {
    regex_escape(&path.to_string_lossy())
}

fn regex_escape(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        if matches!(
            ch,
            '.' | '+' | '*' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
        ) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn dirs_home() -> Option<PathBuf> {
    heimdall_sandbox_policy::home_dir()
}

#[cfg(target_os = "macos")]
fn darwin_user_cache_dir() -> Result<PathBuf> {
    confstr_path(libc::_CS_DARWIN_USER_CACHE_DIR, "_CS_DARWIN_USER_CACHE_DIR")
}

#[cfg(not(target_os = "macos"))]
fn darwin_user_cache_dir() -> Result<PathBuf> {
    Ok(std::env::temp_dir())
}

#[cfg(target_os = "macos")]
fn darwin_user_temp_dir() -> Result<PathBuf> {
    confstr_path(libc::_CS_DARWIN_USER_TEMP_DIR, "_CS_DARWIN_USER_TEMP_DIR")
}

#[cfg(not(target_os = "macos"))]
fn darwin_user_temp_dir() -> Result<PathBuf> {
    Ok(std::env::temp_dir())
}

#[cfg(target_os = "macos")]
fn confstr_path(cs_name: libc::c_int, label: &str) -> Result<PathBuf> {
    use std::ffi::CStr;

    let mut buffer = vec![0_i8; (libc::PATH_MAX as usize) + 1];
    // SAFETY: `buffer` points to writable memory with length `buffer.len()`.
    let len = unsafe { libc::confstr(cs_name, buffer.as_mut_ptr(), buffer.len()) };
    if len > 0 {
        // SAFETY: `confstr` writes a nul-terminated string when it returns a non-zero length.
        if let Ok(path) = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_str() {
            return Ok(PathBuf::from(path)
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from(path)));
        }
    }
    Err(Error::PlatformDirectory {
        message: format!("confstr({label}) returned empty path"),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use heimdall_sandbox_policy::MaterializedFilesystemPolicy;

    use super::*;

    fn request<'a>(
        cwd: &'a Path,
        argv: &'a [String],
        filesystem_policy: &'a FilesystemPolicy,
    ) -> SeatbeltRequest<'a> {
        SeatbeltRequest {
            cwd,
            argv,
            network_mode: NetworkMode::None,
            filesystem_policy,
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        }
    }

    fn empty_materialized_policy() -> MaterializedFilesystemPolicy {
        MaterializedFilesystemPolicy::empty()
    }

    fn policy_arg(args: &[String]) -> &str {
        let index = args
            .iter()
            .position(|arg| arg == "-p")
            .expect("seatbelt args include policy flag");
        &args[index + 1]
    }

    fn param_key_for_path<'a>(args: &'a [String], path: &Path) -> &'a str {
        param_key_for_path_with_prefix(args, path, "DENY")
    }

    fn param_key_for_path_with_prefix<'a>(
        args: &'a [String],
        path: &Path,
        prefix: &str,
    ) -> &'a str {
        let suffix = path.to_string_lossy();
        let expected_prefix = format!("-D{prefix}_");
        let param = args
            .iter()
            .find(|arg| arg.starts_with(&expected_prefix) && arg.ends_with(suffix.as_ref()))
            .expect("param for path exists");
        param
            .strip_prefix("-D")
            .and_then(|value| value.split_once('=').map(|(key, _)| key))
            .expect("param has key")
    }

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
    fn plan_uses_fixed_seatbelt_executable() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::default();
        let plan = request(&cwd, &argv, &filesystem_policy)
            .into_plan_with_materialized(empty_materialized_policy())
            .expect("plan builds");

        assert_eq!(plan.executable(), Path::new(SEATBELT_EXECUTABLE));
        assert!(plan.args().iter().any(|arg| arg == "--"));
    }

    #[test]
    fn base_policy_contains_runtime_defaults() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::default();
        let plan = request(&cwd, &argv, &filesystem_policy)
            .into_plan_with_materialized(empty_materialized_policy())
            .expect("plan builds");
        let policy = policy_arg(plan.args());

        assert!(policy.contains("(deny default)"));
        assert!(policy.contains("(allow process-exec)"));
        assert!(policy.contains("(allow pseudo-tty)"));
        assert!(!policy.contains("\n(allow sysctl-read)\n"));
        assert!(policy.contains("(sysctl-name \"hw.model\")"));
        assert!(policy.contains("(sysctl-name \"machdep.cpu.brand_string\")"));
        assert!(policy.contains("(subpath \"/usr/bin\")"));
        assert!(policy.contains("(subpath \"/System\")"));
        for platform_root in
            SeatbeltPolicyBuilder::platform_read_roots().expect("platform roots inspect")
        {
            assert!(
                plan.args()
                    .iter()
                    .any(|arg| arg.ends_with(&platform_root.to_string_lossy().to_string()))
            );
        }
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
    fn network_none_omits_general_network_access() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::default();
        let plan = request(&cwd, &argv, &filesystem_policy)
            .into_plan_with_materialized(empty_materialized_policy())
            .expect("plan builds");
        let policy = policy_arg(plan.args());

        assert!(!policy.contains("(allow network-outbound)\n(allow network-inbound)"));
    }

    #[test]
    fn default_agent_policy_emits_no_agent_socket_rules() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::default();
        let plan = request(&cwd, &argv, &filesystem_policy)
            .into_plan_with_materialized(empty_materialized_policy())
            .expect("plan builds");
        let policy = policy_arg(plan.args());

        assert!(!policy.contains("AGENT_SOCKET"));
        assert!(!policy.contains("AGENT_READABLE"));
    }

    #[test]
    fn agent_socket_policy_allows_literal_socket_without_general_network() {
        let root = unique_test_dir("agent-socket");
        let socket = root.join("agent.sock");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::default();
        let agent_runtime_paths = AgentRuntimePaths {
            sockets: BTreeSet::from([socket.clone()]),
            readable_dirs: BTreeSet::new(),
        };
        let request = SeatbeltRequest {
            agent_policy: AgentPolicy::new(true, false, false),
            ..request(&root, &argv, &filesystem_policy)
        };
        let plan = request
            .into_plan_with_materialized_and_agent_runtime_paths(
                empty_materialized_policy(),
                agent_runtime_paths,
            )
            .expect("plan builds");
        std::fs::remove_dir_all(&root).expect("test dir removed");
        let policy = policy_arg(plan.args());
        let socket_param = param_key_for_path_with_prefix(plan.args(), &socket, "AGENT_SOCKET");
        let parent_param =
            param_key_for_path_with_prefix(plan.args(), &root, "AGENT_SOCKET_PARENT");

        assert!(!policy.contains("(allow network-outbound)\n(allow network-inbound)"));
        assert!(policy.contains(&format!(
            "(allow network-outbound (literal (param \"{socket_param}\")))"
        )));
        assert!(policy.contains(&format!(
            "(allow file-read* file-write* file-ioctl file-test-existence \
                     (literal (param \"{socket_param}\")))"
        )));
        assert!(policy.contains(&format!(
            "(allow file-read-metadata file-test-existence \
                         (literal (param \"{parent_param}\")))"
        )));
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

    #[test]
    fn denied_parent_excludes_agent_readable_dir() {
        let root = unique_test_dir("agent-readable-deny");
        let agent_dir = root.join(".gnupg");
        std::fs::create_dir_all(&agent_dir).expect("agent dir created");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::new(
            vec![root.to_string_lossy().to_string()],
            Vec::new(),
            Default::default(),
        );
        let materialized = MaterializedFilesystemPolicy::new(
            BTreeSet::from([root.clone()]),
            BTreeSet::new(),
            BTreeSet::new(),
        );
        let agent_runtime_paths = AgentRuntimePaths {
            sockets: BTreeSet::new(),
            readable_dirs: BTreeSet::from([agent_dir.clone()]),
        };
        let request = SeatbeltRequest {
            agent_policy: AgentPolicy::new(false, true, false),
            ..request(&root, &argv, &filesystem_policy)
        };
        let plan = request
            .into_plan_with_materialized_and_agent_runtime_paths(materialized, agent_runtime_paths)
            .expect("plan builds");
        std::fs::remove_dir_all(&root).expect("test dir removed");
        let policy = policy_arg(plan.args());

        assert!(
            plan.args()
                .iter()
                .any(|arg| arg.starts_with("-DAGENT_READABLE_")
                    && arg.ends_with(agent_dir.to_string_lossy().as_ref()))
        );
        assert!(policy.contains("DENY_EXCLUDED_"));
    }

    #[test]
    fn exact_denied_agent_socket_is_not_rendered_as_seatbelt_deny() {
        let root = unique_test_dir("agent-exact-deny");
        let socket = root.join("agent.sock");
        std::fs::write(&socket, "placeholder").expect("socket placeholder written");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::new(
            vec![socket.to_string_lossy().to_string()],
            Vec::new(),
            Default::default(),
        );
        let materialized = MaterializedFilesystemPolicy::new(
            BTreeSet::from([socket.clone()]),
            BTreeSet::new(),
            BTreeSet::new(),
        );
        let agent_runtime_paths = AgentRuntimePaths {
            sockets: BTreeSet::from([socket.clone()]),
            readable_dirs: BTreeSet::new(),
        };
        let request = SeatbeltRequest {
            agent_policy: AgentPolicy::new(true, false, false),
            ..request(&root, &argv, &filesystem_policy)
        };
        let plan = request
            .into_plan_with_materialized_and_agent_runtime_paths(materialized, agent_runtime_paths)
            .expect("plan builds");
        std::fs::remove_dir_all(&root).expect("test dir removed");

        assert!(
            plan.args()
                .iter()
                .any(|arg| arg.starts_with("-DAGENT_SOCKET_")
                    && arg.ends_with(socket.to_string_lossy().as_ref()))
        );
        assert!(
            !plan.args().iter().any(|arg| arg.starts_with("-DDENY_")
                && arg.ends_with(socket.to_string_lossy().as_ref())),
            "exact agent socket deny must not override opt-in agent access"
        );
    }

    #[test]
    fn network_host_allows_general_network_and_support_services() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::default();
        let request = SeatbeltRequest {
            network_mode: NetworkMode::Host,
            ..request(&cwd, &argv, &filesystem_policy)
        };
        let plan = request
            .into_plan_with_materialized(empty_materialized_policy())
            .expect("plan builds");
        let policy = policy_arg(plan.args());

        assert!(policy.contains("(allow network-outbound)\n(allow network-inbound)"));
        assert!(policy.contains("com.apple.SecurityServer"));
    }

    #[test]
    fn platform_writable_dirs_are_unconditionally_accessible() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::default();
        let plan = request(&cwd, &argv, &filesystem_policy)
            .into_plan_with_materialized(empty_materialized_policy())
            .expect("plan builds");
        let policy = policy_arg(plan.args());

        // DARWIN_USER_CACHE_DIR and DARWIN_USER_TEMP_DIR must be writable
        // even without network access.
        assert!(policy.contains("PLATFORM_WRITABLE_"));
        assert!(
            plan.args()
                .iter()
                .any(|arg| arg.contains("PLATFORM_WRITABLE"))
        );
    }

    #[test]
    fn deny_and_writable_targets_are_rendered_with_deny_precedence() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let denied = cwd.join("Cargo.toml");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::new(
            vec!["Cargo.toml".into()],
            vec![".".into()],
            Default::default(),
        );
        let materialized = MaterializedFilesystemPolicy::new(
            BTreeSet::from([denied.clone()]),
            BTreeSet::from([cwd.clone()]),
            BTreeSet::new(),
        );
        let plan = request(&cwd, &argv, &filesystem_policy)
            .into_plan_with_materialized(materialized)
            .expect("plan builds");
        let policy = policy_arg(plan.args());

        assert!(policy.contains("(allow file-write*"));
        assert!(policy.contains("(deny file-read* (literal (param \"DENY_"));
        assert!(policy.contains("(deny file-write* (literal (param \"DENY_"));
        assert!(policy.contains("WRITABLE_EXCLUDED_"));
        assert!(
            plan.args()
                .iter()
                .any(|arg| arg.ends_with(&denied.to_string_lossy().to_string()))
        );
    }

    #[test]
    fn negated_absolute_deny_is_not_rendered_as_seatbelt_deny() {
        let root = unique_test_dir("negated-deny");
        let denied = root.join("aws");
        std::fs::create_dir_all(&denied).expect("denied dir created");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::new(
            vec![
                denied.to_string_lossy().to_string(),
                format!("!{}", denied.display()),
            ],
            Vec::new(),
            Default::default(),
        );
        let materialized = FilesystemPolicyMaterializer::new(&root, &filesystem_policy)
            .materialize()
            .expect("policy materializes");
        let plan = request(&root, &argv, &filesystem_policy)
            .into_plan_with_materialized(materialized)
            .expect("plan builds");
        let policy = policy_arg(plan.args());

        assert!(
            !plan.args().iter().any(|arg| {
                arg.starts_with("-DDENY_") && arg.ends_with(denied.to_string_lossy().as_ref())
            }),
            "negated deny must not create a Seatbelt deny parameter"
        );
        assert!(
            !policy.contains("(deny file-read* (literal (param \"DENY_"),
            "negated deny must not emit Seatbelt read-deny rules"
        );
        assert!(
            !policy.contains("(deny file-write* (literal (param \"DENY_"),
            "negated deny must not emit Seatbelt write-deny rules"
        );
        std::fs::remove_dir_all(&root).expect("test dir removed");
    }

    #[test]
    fn denied_parent_excludes_writable_child() {
        let root = std::env::temp_dir().join(format!(
            "heimdall-seatbelt-specificity-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        let denied = root.join("config");
        let writable = denied.join("nvim");
        std::fs::create_dir_all(&writable).expect("test dirs created");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::new(
            vec![denied.to_string_lossy().to_string()],
            vec![writable.to_string_lossy().to_string()],
            Default::default(),
        );
        let materialized = MaterializedFilesystemPolicy::new(
            BTreeSet::from([denied.clone()]),
            BTreeSet::from([writable.clone()]),
            BTreeSet::new(),
        );
        let plan = request(&root, &argv, &filesystem_policy)
            .into_plan_with_materialized(materialized)
            .expect("plan builds");
        std::fs::remove_dir_all(&root).expect("test dirs removed");
        let policy = policy_arg(plan.args());

        assert!(policy.contains("DENY_EXCLUDED_"));
        assert!(
            plan.args()
                .iter()
                .any(|arg| arg.ends_with(&writable.to_string_lossy().to_string()))
        );
    }

    #[test]
    fn missing_writable_and_outside_deny_paths_are_not_rendered() {
        let root = unique_test_dir("missing-skipped");
        let missing_writable = root.join("missing-write");
        let outside_deny = root.join("outside-deny");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::new(
            vec![outside_deny.to_string_lossy().to_string()],
            vec![missing_writable.to_string_lossy().to_string()],
            Default::default(),
        );
        let materialized = FilesystemPolicyMaterializer::new(&root, &filesystem_policy)
            .materialize()
            .expect("policy materializes");
        let plan = request(&root, &argv, &filesystem_policy)
            .into_plan_with_materialized(materialized)
            .expect("plan builds");
        std::fs::remove_dir_all(&root).expect("test dir removed");

        assert!(
            !plan
                .args()
                .iter()
                .any(|arg| arg.contains(missing_writable.to_string_lossy().as_ref()))
        );
        assert!(
            !plan
                .args()
                .iter()
                .any(|arg| arg.contains(outside_deny.to_string_lossy().as_ref()))
        );
        assert!(!missing_writable.exists());
        assert!(!outside_deny.exists());
    }

    #[test]
    fn tilde_existing_writable_and_missing_deny_guard_are_rendered() {
        let root = unique_test_dir("tilde-policy");
        let home = heimdall_sandbox_policy::home_dir().expect("home dir exists");
        let missing = home.join(format!(
            ".heimdall-seatbelt-missing-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        assert!(!missing.exists());
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::new(
            vec![format!(
                "~/{}",
                missing
                    .file_name()
                    .expect("missing file name")
                    .to_string_lossy()
            )],
            vec!["~".to_string()],
            Default::default(),
        );
        let materialized = FilesystemPolicyMaterializer::new(&root, &filesystem_policy)
            .materialize()
            .expect("policy materializes");
        let plan = request(&root, &argv, &filesystem_policy)
            .into_plan_with_materialized(materialized)
            .expect("plan builds");
        std::fs::remove_dir_all(&root).expect("test dir removed");
        let policy = policy_arg(plan.args());
        let param = param_key_for_path(plan.args(), &missing);

        assert!(
            plan.args()
                .iter()
                .any(|arg| arg.ends_with(&home.to_string_lossy().to_string()))
        );
        assert!(policy.contains(&format!("(deny file-read* (literal (param \"{param}\")))")));
        assert!(policy.contains(&format!("(deny file-write* (literal (param \"{param}\")))")));
        assert!(!missing.exists());
    }

    #[test]
    fn absolute_path_under_cwd_missing_deny_is_rendered_as_concrete_guard() {
        let root = unique_test_dir("absolute-under-cwd");
        let missing = root.join("missing-deny");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::new(
            vec![missing.to_string_lossy().to_string()],
            vec![".".to_string()],
            Default::default(),
        );
        let materialized = FilesystemPolicyMaterializer::new(&root, &filesystem_policy)
            .materialize()
            .expect("policy materializes");
        let plan = request(&root, &argv, &filesystem_policy)
            .into_plan_with_materialized(materialized)
            .expect("plan builds");
        std::fs::remove_dir_all(&root).expect("test dir removed");
        let policy = policy_arg(plan.args());
        let param = param_key_for_path(plan.args(), &missing);

        assert!(policy.contains(&format!("(deny file-read* (literal (param \"{param}\")))")));
        assert!(policy.contains(&format!("(deny file-write* (literal (param \"{param}\")))")));
        assert!(!missing.exists());
    }

    #[test]
    fn missing_deny_guard_emits_literal_and_subpath_denies() {
        let root = unique_test_dir("missing-deny");
        let writable = root.join("writable");
        std::fs::create_dir_all(&writable).expect("writable dir created");
        let missing = writable.join("missing-deny");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::new(
            vec![missing.to_string_lossy().to_string()],
            vec![writable.to_string_lossy().to_string()],
            Default::default(),
        );
        let materialized = FilesystemPolicyMaterializer::new(&root, &filesystem_policy)
            .materialize()
            .expect("policy materializes");
        let plan = request(&root, &argv, &filesystem_policy)
            .into_plan_with_materialized(materialized)
            .expect("plan builds");
        std::fs::remove_dir_all(&root).expect("test dirs removed");
        let policy = policy_arg(plan.args());
        let param = param_key_for_path(plan.args(), &missing);

        assert!(policy.contains(&format!("(deny file-read* (literal (param \"{param}\")))")));
        assert!(policy.contains(&format!("(deny file-write* (literal (param \"{param}\")))")));
        assert!(policy.contains(&format!(
            "(deny file-read*\n  (require-all (subpath (param \"{param}\"))"
        )));
        assert!(policy.contains(&format!(
            "(deny file-write*\n  (require-all (subpath (param \"{param}\"))"
        )));
        assert!(!missing.exists());
    }

    #[test]
    fn protected_targets_are_write_denied() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let protected = cwd.join(".git");
        let argv = ["true".to_string()];
        let filesystem_policy =
            FilesystemPolicy::new(Vec::new(), vec![".".into()], Default::default());
        let materialized = MaterializedFilesystemPolicy::new(
            BTreeSet::new(),
            BTreeSet::from([cwd.clone()]),
            BTreeSet::from([protected.clone()]),
        );
        let plan = request(&cwd, &argv, &filesystem_policy)
            .into_plan_with_materialized(materialized)
            .expect("plan builds");
        let policy = policy_arg(plan.args());

        assert!(policy.contains("(deny file-write* (literal (param \"PROTECTED_"));
        assert!(policy.contains(".heimdall-[^/]*"));
        assert!(
            plan.args()
                .iter()
                .any(|arg| arg.ends_with(&protected.to_string_lossy().to_string()))
        );
    }

    #[test]
    fn virtual_files_are_write_denied_without_read_deny() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::new(
            Vec::new(),
            vec![".".into()],
            [(PathBuf::from("/etc/passwd"), "synthetic".to_string())]
                .into_iter()
                .collect(),
        );
        let materialized = MaterializedFilesystemPolicy::new(
            BTreeSet::new(),
            BTreeSet::from([cwd]),
            BTreeSet::new(),
        );
        let plan = request(Path::new("/tmp"), &argv, &filesystem_policy)
            .into_plan_with_materialized(materialized)
            .expect("plan builds");
        let policy = policy_arg(plan.args());

        assert!(policy.contains("(deny file-write* (literal (param \"VIRTUAL_"));
        assert!(!policy.contains("(deny file-read* (literal (param \"VIRTUAL_"));
        assert!(plan.args().iter().any(|arg| arg.ends_with("/etc/passwd")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn virtual_target_write_deny_includes_canonical_alias() {
        let argv = ["true".to_string()];
        let requested = PathBuf::from("/etc/passwd");
        let canonical = requested
            .canonicalize()
            .expect("system passwd path canonicalizes");
        let filesystem_policy = FilesystemPolicy::new(
            Vec::new(),
            Vec::new(),
            [(requested.clone(), "synthetic".to_string())]
                .into_iter()
                .collect(),
        );
        let plan = request(Path::new("/tmp"), &argv, &filesystem_policy)
            .into_plan_with_materialized(empty_materialized_policy())
            .expect("plan builds");

        assert!(
            plan.args()
                .iter()
                .any(|arg| arg.ends_with(&requested.to_string_lossy().to_string()))
        );
        assert!(
            plan.args()
                .iter()
                .any(|arg| arg.ends_with(&canonical.to_string_lossy().to_string()))
        );
    }

    #[test]
    fn proc_mode_is_accepted_as_noop() {
        let cwd = std::env::current_dir().expect("cwd exists");
        let argv = ["true".to_string()];
        let filesystem_policy = FilesystemPolicy::default();
        let request = SeatbeltRequest {
            proc_mode: ProcMode::Disabled,
            ..request(&cwd, &argv, &filesystem_policy)
        };
        let plan = request
            .into_plan_with_materialized(empty_materialized_policy())
            .expect("plan builds");

        assert_eq!(plan.executable(), Path::new(SEATBELT_EXECUTABLE));
    }
}
