//! macOS Seatbelt sandbox planning.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use heimdall_sandbox_policy::{
    FilesystemPolicy, FilesystemPolicyMaterializer, MaterializedFilesystemPolicy, NetworkMode,
    ProcMode,
};
use thiserror::Error as ThisError;

/// Absolute path to the macOS Seatbelt launcher.
pub const SEATBELT_EXECUTABLE: &str = "/usr/bin/sandbox-exec";

const BASE_POLICY: &str = r#"(version 1)

(deny default)

(allow process-exec)
(allow process-fork)
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))

(allow file-write-data
  (require-all
    (path "/dev/null")
    (vnode-type CHARACTER-DEVICE)))

(allow sysctl-read
  (sysctl-name "hw.activecpu")
  (sysctl-name "hw.byteorder")
  (sysctl-name "hw.cpufamily")
  (sysctl-name "hw.cputype")
  (sysctl-name "hw.logicalcpu")
  (sysctl-name "hw.logicalcpu_max")
  (sysctl-name "hw.machine")
  (sysctl-name "hw.memsize")
  (sysctl-name "hw.model")
  (sysctl-name "hw.ncpu")
  (sysctl-name "hw.pagesize")
  (sysctl-name "hw.physicalcpu")
  (sysctl-name "hw.physicalcpu_max")
  (sysctl-name "kern.argmax")
  (sysctl-name "kern.hostname")
  (sysctl-name "kern.maxfilesperproc")
  (sysctl-name "kern.maxproc")
  (sysctl-name "kern.osproductversion")
  (sysctl-name "kern.osrelease")
  (sysctl-name "kern.ostype")
  (sysctl-name "kern.osvariant_status")
  (sysctl-name "kern.osversion")
  (sysctl-name "kern.secure_kernel")
  (sysctl-name "kern.usrstack64")
  (sysctl-name "kern.version")
  (sysctl-name "machdep.cpu.brand_string")
  (sysctl-name "vm.loadavg")
  (sysctl-name-prefix "hw.optional.arm.")
  (sysctl-name-prefix "hw.optional.armv8_")
  (sysctl-name-prefix "hw.perflevel")
  (sysctl-name-prefix "kern.proc.pgrp.")
  (sysctl-name-prefix "kern.proc.pid.")
  (sysctl-name-prefix "net.routetable."))
(allow sysctl-write (sysctl-name "kern.grade_cputype"))

(allow iokit-open
  (iokit-registry-entry-class "RootDomainUserClient"))

(allow mach-lookup
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.PowerManagement.control"))

(allow ipc-posix-sem)
(allow ipc-posix-shm-read-data
  ipc-posix-shm-write-create
  ipc-posix-shm-write-unlink
  (ipc-posix-name-regex #"^/__KMP_REGISTERED_LIB_[0-9]+$"))

(allow pseudo-tty)
(allow file-read* file-write* file-ioctl (literal "/dev/ptmx"))
(allow file-read* file-write*
  (require-all
    (regex #"^/dev/ttys[0-9]+")
    (extension "com.apple.sandbox.pty")))
(allow file-ioctl (regex #"^/dev/ttys[0-9]+"))

(allow ipc-posix-shm-read* (ipc-posix-name-prefix "apple.cfprefs."))
(allow mach-lookup
  (global-name "com.apple.cfprefsd.daemon")
  (global-name "com.apple.cfprefsd.agent")
  (local-name "com.apple.cfprefsd.agent"))
(allow user-preference-read)
"#;

const PLATFORM_DEFAULTS: &str = r#"
; macOS restricted read-only platform defaults.
(allow file-read* file-test-existence
  (subpath "/Library/Apple")
  (subpath "/Library/Filesystems/NetFSPlugins")
  (subpath "/Library/Preferences")
  (subpath "/Library/Preferences/Logging")
  (subpath "/private/var/db")
  (subpath "/private/var/db/timezone")
  (subpath "/usr/lib")
  (subpath "/usr/share"))

(allow file-map-executable
  (subpath "/Library/Apple/System/Library/Frameworks")
  (subpath "/Library/Apple/System/Library/PrivateFrameworks")
  (subpath "/Library/Apple/usr/lib")
  (subpath "/System/Library/Extensions")
  (subpath "/System/Library/Frameworks")
  (subpath "/System/Library/PrivateFrameworks")
  (subpath "/System/Library/SubFrameworks")
  (subpath "/usr/lib"))

(allow file-read* file-test-existence
  (subpath "/Library/Apple/System/Library/Frameworks")
  (subpath "/Library/Apple/System/Library/PrivateFrameworks")
  (subpath "/Library/Apple/usr/lib")
  (subpath "/System/Library/Frameworks")
  (subpath "/System/Library/PrivateFrameworks")
  (subpath "/System/Library/SubFrameworks")
  (subpath "/usr/lib"))

(allow system-mac-syscall (mac-policy-name "vnguard"))
(allow system-mac-syscall
  (require-all
    (mac-policy-name "Sandbox")
    (mac-syscall-number 67)))

(allow file-read-metadata file-test-existence
  (literal "/etc")
  (literal "/tmp")
  (literal "/var")
  (literal "/private/etc/localtime"))
(allow file-read-metadata file-test-existence
  (path-ancestors "/System/Volumes/Data/private"))
(allow file-read* file-test-existence (literal "/"))
(allow system-fsctl (fsctl-command FSIOC_CAS_BSDFLAGS))

(allow file-read* file-test-existence
  (literal "/dev/autofs_nowait")
  (literal "/dev/random")
  (literal "/dev/urandom")
  (literal "/private/etc/protocols")
  (literal "/private/etc/services"))
(allow file-read* file-test-existence file-write-data
  (literal "/dev/null")
  (literal "/dev/zero"))
(allow file-read-data file-test-existence file-write-data
  (subpath "/dev/fd"))

(allow file-read* file-test-existence (subpath "/tmp"))
(allow file-read* file-test-existence (subpath "/private/tmp"))
(allow file-read* file-test-existence (subpath "/var/tmp"))
(allow file-read* file-test-existence (subpath "/private/var/tmp"))

(allow file-read* (subpath "/etc"))
(allow file-read* (subpath "/private/etc"))

(allow file-read* file-test-existence
  (literal "/System/Library/CoreServices")
  (literal "/System/Library/CoreServices/.SystemVersionPlatform.plist")
  (literal "/System/Library/CoreServices/SystemVersion.plist"))

(allow file-read-metadata (subpath "/var"))
(allow file-read-metadata (subpath "/private/var"))

(allow mach-lookup
  (global-name "com.apple.analyticsd")
  (global-name "com.apple.bsd.dirhelper")
  (global-name "com.apple.cfprefsd.agent")
  (global-name "com.apple.cfprefsd.daemon")
  (global-name "com.apple.logd")
  (global-name "com.apple.secinitd")
  (global-name "com.apple.system.DirectoryService.libinfo_v1")
  (global-name "com.apple.system.logger")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.trustd")
  (global-name "com.apple.trustd.agent")
  (local-name "com.apple.cfprefsd.agent"))

(allow network-outbound (literal "/private/var/run/syslog"))
(allow ipc-posix-shm-read* (ipc-posix-name "apple.shm.notification_center"))

(allow file-read-data (subpath "/bin"))
(allow file-read-metadata (subpath "/bin"))
(allow file-read-data (subpath "/sbin"))
(allow file-read-metadata (subpath "/sbin"))
(allow file-read-data (subpath "/usr/bin"))
(allow file-read-metadata (subpath "/usr/bin"))
(allow file-read-data (subpath "/usr/sbin"))
(allow file-read-metadata (subpath "/usr/sbin"))
(allow file-read-data (subpath "/usr/libexec"))
(allow file-read-metadata (subpath "/usr/libexec"))

(allow file-read* (subpath "/opt/homebrew/lib"))
(allow file-read* (subpath "/usr/local/lib"))
(allow file-read* (subpath "/Applications"))

(allow file-read* (regex #"^/dev/fd/(0|1|2)$"))
(allow file-write* (regex #"^/dev/fd/(1|2)$"))
(allow file-read* file-write* (literal "/dev/null"))
(allow file-read* file-write* (literal "/dev/tty"))
(allow file-read-metadata (literal "/dev"))
(allow file-read-metadata (regex #"^/dev/.*$"))
(allow file-read-metadata (literal "/dev/stdin"))
(allow file-read-metadata (literal "/dev/stdout"))
(allow file-read-metadata (literal "/dev/stderr"))
(allow file-read* file-write* (regex #"^/dev/ttys[0-9]+$"))
(allow file-read* file-write* (literal "/dev/ptmx"))
(allow file-ioctl (regex #"^/dev/ttys[0-9]+$"))

(allow file-read-metadata (literal "/System/Volumes") (vnode-type DIRECTORY))
(allow file-read-metadata (literal "/System/Volumes/Data") (vnode-type DIRECTORY))
(allow file-read-metadata (literal "/System/Volumes/Data/Users") (vnode-type DIRECTORY))
"#;

const NETWORK_SUPPORT_POLICY: &str = r#"
(allow system-socket
  (require-all
    (socket-domain AF_SYSTEM)
    (socket-protocol 2)))

(allow mach-lookup
  (global-name "com.apple.bsd.dirhelper")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.networkd")
  (global-name "com.apple.ocspd")
  (global-name "com.apple.trustd.agent")
  (global-name "com.apple.SystemConfiguration.DNSConfiguration")
  (global-name "com.apple.SystemConfiguration.configd"))

(allow sysctl-read (sysctl-name-regex #"^net.routetable"))
(allow file-write* (subpath (param "DARWIN_USER_CACHE_DIR")))
"#;

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
}

struct SeatbeltPolicyBuilder<'a> {
    request: &'a SeatbeltRequest<'a>,
    targets: DecomposedTargets,
    params: Vec<(String, PathBuf)>,
    next_param: usize,
}

impl<'a> SeatbeltPolicyBuilder<'a> {
    fn new(request: &'a SeatbeltRequest<'a>, materialized: MaterializedFilesystemPolicy) -> Self {
        let (deny_targets, writable_targets, protected_targets) = materialized.into_parts();
        let targets = DecomposedTargets {
            deny_targets,
            writable_targets,
            protected_targets,
        };
        Self {
            request,
            targets,
            params: Vec::new(),
            next_param: 0,
        }
    }

    fn build(mut self) -> Result<SeatbeltPolicy> {
        let mut text = String::new();
        text.push_str(BASE_POLICY);
        text.push('\n');
        text.push_str(PLATFORM_DEFAULTS);
        text.push('\n');
        text.push_str(&self.read_policy());
        let heimdall_wildcard = self.heimdall_wildcard_write_deny_policy();
        let exclusions = self.write_exclusions();
        text.push_str(&self.write_policy(&exclusions));
        text.push_str(&self.deny_policy());
        text.push_str(&self.virtual_write_deny_policy());
        text.push_str(&heimdall_wildcard);
        text.push_str(&self.network_policy()?);
        Ok(SeatbeltPolicy {
            text,
            params: self.params,
        })
    }

    fn read_policy(&mut self) -> String {
        let mut policy = String::from("; allow read-only file operations\n");
        for root in path_aliases(self.request.cwd) {
            let readable_root = self.path_param("READABLE_ROOT", &root);
            policy.push_str(&format!(
                "(allow file-read* (subpath (param \"{readable_root}\")))\n"
            ));
        }
        policy
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
        for protected in &self.targets.protected_targets {
            exclusions.extend(path_aliases(protected));
        }
        for path in self.request.filesystem_policy.virtual_files().keys() {
            exclusions.extend(path_aliases(path));
        }
        exclusions
    }

    fn deny_policy(&mut self) -> String {
        let mut rules = String::new();
        let deny_targets = std::mem::take(&mut self.targets.deny_targets);
        for denied in deny_targets {
            for alias in path_aliases(&denied) {
                let param = self.path_param("DENY", &alias);
                rules.push_str(&format!(
                    "(deny file-read* (literal (param \"{param}\")))\n"
                ));
                rules.push_str(&format!(
                    "(deny file-write* (literal (param \"{param}\")))\n"
                ));
                if alias.is_dir() {
                    rules.push_str(&format!(
                        "(deny file-read* (subpath (param \"{param}\")))\n"
                    ));
                    rules.push_str(&format!(
                        "(deny file-write* (subpath (param \"{param}\")))\n"
                    ));
                }
            }
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

    fn network_policy(&mut self) -> Result<String> {
        if self.request.network_mode == NetworkMode::None {
            return Ok(String::new());
        }
        self.params.push((
            "DARWIN_USER_CACHE_DIR".to_string(),
            darwin_user_cache_dir()?,
        ));
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

#[cfg(target_os = "macos")]
fn darwin_user_cache_dir() -> Result<PathBuf> {
    use std::ffi::CStr;

    let mut buffer = vec![0_i8; (libc::PATH_MAX as usize) + 1];
    // SAFETY: `buffer` points to writable memory with length `buffer.len()`.
    let len = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_CACHE_DIR,
            buffer.as_mut_ptr(),
            buffer.len(),
        )
    };
    if len > 0 {
        // SAFETY: `confstr` writes a nul-terminated string when it returns a non-zero length.
        if let Ok(path) = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_str() {
            return Ok(PathBuf::from(path)
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from(path)));
        }
    }
    Err(Error::PlatformDirectory {
        message: "confstr(_CS_DARWIN_USER_CACHE_DIR) returned empty path".to_string(),
    })
}

#[cfg(not(target_os = "macos"))]
fn darwin_user_cache_dir() -> Result<PathBuf> {
    Ok(std::env::temp_dir())
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
        assert!(policy.contains("(subpath \"/System/Library/Frameworks\")"));
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
        assert!(policy.contains("DARWIN_USER_CACHE_DIR"));
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
