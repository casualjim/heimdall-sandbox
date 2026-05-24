//! macOS Seatbelt sandbox planning.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use heimdall_sandbox_policy::{
    FilesystemPolicy, FilesystemPolicyMaterializer, MaterializedFilesystemPolicy, NetworkMode,
    ProcMode,
};
use thiserror::Error as ThisError;

/// Absolute path to the macOS Seatbelt launcher.
pub const SEATBELT_EXECUTABLE: &str = "/usr/bin/sandbox-exec";

const BASE_POLICY: &str = include_str!("seatbelt_base_policy.sbpl");

const PLATFORM_DEFAULTS: &str = include_str!("restricted_read_only_platform_defaults.sbpl");

const NETWORK_SUPPORT_POLICY: &str = include_str!("seatbelt_network_policy.sbpl");

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

    fn build(mut self) -> Result<SeatbeltPolicy> {
        let mut text = String::new();
        text.push_str(BASE_POLICY);
        text.push('\n');
        text.push_str(PLATFORM_DEFAULTS);
        text.push('\n');
        let heimdall_wildcard = self.heimdall_wildcard_write_deny_policy();
        let write_exclusions = self.write_exclusions();
        let deny_exclusions = self.deny_exclusions();
        text.push_str(&self.read_policy()?);
        text.push_str(&self.write_policy(&write_exclusions));
        text.push_str(&self.platform_writable_policy()?);
        text.push_str(&self.deny_policy(&deny_exclusions));
        text.push_str(&self.virtual_write_deny_policy());
        text.push_str(&heimdall_wildcard);
        text.push_str(&self.network_policy()?);
        Ok(SeatbeltPolicy {
            text,
            params: self.params,
        })
    }

    fn read_policy(&mut self) -> Result<String> {
        let mut policy = String::from("; allow read-only file operations\n");
        self.push_readable_root_policy(&mut policy, "READABLE_ROOT", self.request.cwd);
        for root in Self::platform_read_roots()? {
            self.push_readable_root_policy(&mut policy, "PLATFORM_READ_ROOT", &root);
        }
        let readable_targets = std::mem::take(&mut self.targets.readable_targets);
        for readable in readable_targets {
            self.push_readable_root_policy(&mut policy, "READABLE_TARGET", &readable);
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

    fn write_exclusions(&self) -> BTreeSet<PathBuf> {
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
        exclusions
    }

    fn deny_policy(&mut self, exclusions: &BTreeSet<PathBuf>) -> String {
        let mut rules = String::new();
        let deny_targets = std::mem::take(&mut self.targets.deny_targets);
        for denied in deny_targets {
            self.push_deny_policy(&mut rules, &denied, exclusions, false);
        }
        let missing_deny_guards = std::mem::take(&mut self.targets.missing_deny_guards);
        for guard in missing_deny_guards {
            self.push_deny_policy(&mut rules, &guard, exclusions, true);
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
        force_subpath_deny: bool,
    ) {
        for alias in path_aliases(denied) {
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

    fn deny_exclusions(&self) -> BTreeSet<PathBuf> {
        let mut exclusions = BTreeSet::new();
        for writable in &self.targets.writable_targets {
            exclusions.extend(path_aliases(writable));
        }
        for readable in &self.targets.readable_targets {
            exclusions.extend(path_aliases(readable));
        }
        exclusions
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
        let suffix = path.to_string_lossy();
        let param = args
            .iter()
            .find(|arg| arg.starts_with("-DDENY_") && arg.ends_with(suffix.as_ref()))
            .expect("deny param for path exists");
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
