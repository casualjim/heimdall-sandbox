//! Structured input for building a macOS Seatbelt invocation.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use heimdall_sandbox_policy::{
    AgentPolicy, FilesystemPolicy, FilesystemPolicyMaterializer, MaterializedFilesystemPolicy,
    NetworkMode, ProcMode,
};

use crate::builder::SeatbeltPolicyBuilder;
use crate::plan::{SeatbeltPlan, SeatbeltPolicy};
use crate::{Result, SEATBELT_EXECUTABLE};

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

/// Resolved host agent socket paths and readable directories.
#[derive(Debug, Default)]
pub(crate) struct AgentRuntimePaths {
    pub(crate) sockets: BTreeSet<PathBuf>,
    pub(crate) readable_dirs: BTreeSet<PathBuf>,
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use heimdall_sandbox_policy::{
        AgentPolicy, FilesystemPolicy, FilesystemPolicyMaterializer, MaterializedFilesystemPolicy,
        NetworkMode, ProcMode, home_dir,
    };

    use super::{AgentRuntimePaths, SeatbeltRequest};
    use crate::SEATBELT_EXECUTABLE;

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
        for platform_root in crate::builder::SeatbeltPolicyBuilder::platform_read_roots()
            .expect("platform roots inspect")
        {
            assert!(
                plan.args()
                    .iter()
                    .any(|arg| arg.ends_with(&platform_root.to_string_lossy().to_string()))
            );
        }
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
        let home = home_dir().expect("home dir exists");
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
