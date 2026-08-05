use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use boxlite::runtime::options::VolumeSpec;
use boxlite::{
    AdvancedBoxOptions, BoxCommand, BoxOptions, BoxliteRuntime, ExecStderr, ExecStdout, LiteBox,
    NetworkSpec, RootfsSpec, Secret,
};
use futures::StreamExt;
use heimdall_sandbox_policy::{
    AgentPolicy, FilesystemPolicy, FilesystemPolicyMaterializer, MicrovmPolicy, MicrovmSecret,
    NetworkMode, ProcMode, RlimitResource, SecretHostPattern,
};

use crate::environment::utf8_environment;
use crate::filesystem::{FilesystemPlan, GUEST_WORKDIR, plan_filesystem};
use crate::naming::sandbox_name;
use crate::{Error, Result};

/// Structured input used to run a command in a boxlite microVM.
pub struct MicrovmRequest<'a> {
    /// Host working directory mounted into the guest.
    pub cwd: &'a Path,
    /// Child argv to run inside the guest.
    pub argv: &'a [String],
    /// Boxlite rootfs image reference (OCI image). Required for the `microvm`
    /// runtime; boxlite has no snapshot-pinning knob, so a policy
    /// `image.snapshot` is rejected.
    pub image: Option<&'a str>,
    /// Child environment after Heimdall filtering/hardening.
    pub environment: &'a [(OsString, OsString)],
    /// Child network isolation policy.
    pub network_mode: NetworkMode,
    /// Child filesystem isolation policy.
    pub filesystem_policy: &'a FilesystemPolicy,
    /// Proc mount policy.
    pub proc_mode: ProcMode,
    /// Host agent sockets explicitly enabled for access.
    pub agent_policy: AgentPolicy,
    /// MicroVM-only resource, lifecycle, guest, secret, and image policy.
    pub microvm_policy: &'a MicrovmPolicy,
}

impl MicrovmRequest<'_> {
    /// Execute this request in an ephemeral attached boxlite box.
    ///
    /// # Errors
    ///
    /// Returns a sandbox misconfiguration when policy cannot be represented by
    /// the boxlite backend, boxlite runtime creation/start/exec/stop fails, or
    /// output forwarding fails.
    pub fn execute(&self) -> Result<i32> {
        self.validate_policy()?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(Error::Runtime)?;
        runtime.block_on(self.execute_async())
    }

    /// Reject every `MicrovmPolicy`/filesystem/proc/agent surface that boxlite
    /// has no native knob for. Fail closed — never silently drop a field.
    fn validate_policy(&self) -> Result<()> {
        let policy = self.microvm_policy;

        if self.image.map(str::is_empty).unwrap_or(true) {
            return Err(Error::unsupported_policy(
                "microvm runtime requires non-empty policy image",
            ));
        }
        if policy.resources().upper_size_mib().is_some() {
            return Err(Error::unsupported_policy(
                "microvm runtime does not support resources.upperSize on boxlite",
            ));
        }
        if policy.lifecycle().idle_timeout_secs().is_some() {
            return Err(Error::unsupported_policy(
                "microvm runtime does not support lifecycle.idleTimeout on boxlite",
            ));
        }
        if !self.filesystem_policy.virtual_files().is_empty() {
            return Err(Error::unsupported_policy(
                "microvm runtime does not yet materialize filesystem.virtual files on boxlite",
            ));
        }
        if self.proc_mode != ProcMode::Default {
            return Err(Error::unsupported_policy(
                "microvm runtime does not yet support proc=none parity on boxlite",
            ));
        }
        if !self.agent_policy.is_empty() {
            return Err(Error::unsupported_policy(
                "microvm runtime does not yet support agent socket parity on boxlite",
            ));
        }
        Ok(())
    }

    async fn execute_async(&self) -> Result<i32> {
        let cwd = std::fs::canonicalize(self.cwd).map_err(|source| Error::Cwd {
            path: self.cwd.to_path_buf(),
            source,
        })?;
        let materialized = FilesystemPolicyMaterializer::new(&cwd, self.filesystem_policy)
            .materialize()
            .map_err(Error::from)?;
        let plan = plan_filesystem(&cwd, &materialized, self.filesystem_policy.virtual_files())?;
        let environment = utf8_environment(self.environment)?;

        let runtime = BoxliteRuntime::with_defaults().map_err(Error::from)?;
        let litebox = runtime
            .create(self.build_box_options(&plan)?, Some(sandbox_name()?))
            .await
            .map_err(Error::from)?;
        let exec_result = self.execute_command(&litebox, &environment).await;
        let stop_result = litebox.stop().await.map_err(Error::from);
        match (exec_result, stop_result) {
            (Ok(exit_code), Ok(_)) => Ok(exit_code),
            (Err(error), Ok(_)) | (Err(error), Err(_)) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    /// Translate the validated policy + filesystem plan into a boxlite
    /// [`BoxOptions`]. Only boxlite-native knobs are set; everything rejected
    /// by `validate_policy` is absent here.
    fn build_box_options(&self, plan: &FilesystemPlan) -> Result<BoxOptions> {
        let policy = self.microvm_policy;
        let resources = policy.resources();
        let image = self
            .image
            .filter(|image| !image.is_empty())
            .ok_or_else(|| {
                Error::unsupported_policy("microvm runtime requires non-empty policy image")
            })?;
        let volumes: Vec<VolumeSpec> = plan
            .volumes
            .iter()
            .map(|volume| VolumeSpec {
                host_path: volume.host.to_string_lossy().into_owned(),
                guest_path: volume.guest.clone(),
                read_only: volume.readonly,
            })
            .collect();
        let network = match self.network_mode {
            NetworkMode::Host => NetworkSpec::Enabled {
                allow_net: Vec::new(),
            },
            NetworkMode::None => NetworkSpec::Disabled,
        };
        Ok(BoxOptions {
            rootfs: RootfsSpec::Image(image.to_string()),
            working_dir: Some(GUEST_WORKDIR.to_string()),
            env: Vec::new(),
            volumes,
            network,
            auto_remove: true,
            detach: false,
            cpus: resources.cpus(),
            memory_mib: resources.memory_mib(),
            entrypoint: policy
                .guest()
                .entrypoint()
                .map(|entrypoint| entrypoint.to_vec()),
            user: policy.guest().user().map(String::from),
            secrets: policy.secrets().iter().map(map_secret).collect(),
            advanced: self.build_advanced()?,
            ..Default::default()
        })
    }

    /// Build boxlite advanced options: resource limits (the 5 boxlite-native
    /// rlimits) on top of boxlite's secure default [`AdvancedBoxOptions`].
    /// `security_profile` has no separate boxlite knob — boxlite's default
    /// `SecurityOptions` is the fully-enabled (jail) profile, which satisfies
    /// both Heimdall `Default` and `Restricted`; the finer `no_new_privs` /
    /// `CAP_SYS_ADMIN` distinction is not expressible and left to boxlite's
    /// secure default.
    fn build_advanced(&self) -> Result<AdvancedBoxOptions> {
        let policy = self.microvm_policy;
        let mut advanced = AdvancedBoxOptions::default();
        let rlimits = policy.resources().rlimits();
        if !rlimits.is_empty() {
            let mut limits = advanced.security.resource_limits.clone();
            for spec in rlimits {
                match spec.resource() {
                    RlimitResource::Nofile => limits.max_open_files = Some(spec.soft()),
                    RlimitResource::Fsize => limits.max_file_size = Some(spec.soft()),
                    RlimitResource::Nproc => limits.max_processes = Some(spec.soft()),
                    RlimitResource::As => limits.max_memory = Some(spec.soft()),
                    RlimitResource::Cpu => limits.max_cpu_time = Some(spec.soft()),
                }
            }
            advanced.security.resource_limits = limits;
        }
        Ok(advanced)
    }

    async fn execute_command(
        &self,
        litebox: &LiteBox,
        environment: &[(String, String)],
    ) -> Result<i32> {
        let (program, args) = self
            .argv
            .split_first()
            .ok_or_else(|| Error::unsupported_policy("microvm runtime requires command argv"))?;
        let mut command = BoxCommand::new(program.as_str())
            .args(args.iter().cloned())
            .working_dir(GUEST_WORKDIR);
        for (key, value) in environment {
            command = command.env(key.as_str(), value.as_str());
        }
        if let Some(secs) = self.microvm_policy.lifecycle().max_duration_secs() {
            command = command.timeout(Duration::from_secs(secs));
        }

        let mut execution = litebox.exec(command).await.map_err(Error::from)?;
        let mut stdout = execution.stdout();
        let mut stderr = execution.stderr();
        let (stdout_res, stderr_res, wait_res) = futures::join!(
            drain_stdout(stdout.as_mut()),
            drain_stderr(stderr.as_mut()),
            execution.wait(),
        );
        stdout_res?;
        stderr_res?;
        let result = wait_res.map_err(Error::from)?;
        Ok(map_exit_code(result.exit_code))
    }
}

/// Forward boxlite stdout chunks to the host stdout stream.
async fn drain_stdout(stream: Option<&mut ExecStdout>) -> Result<()> {
    let Some(stream) = stream else {
        return Ok(());
    };
    while let Some(chunk) = stream.next().await {
        std::io::stdout()
            .write_all(chunk.as_bytes())
            .map_err(Error::Output)?;
    }
    Ok(())
}

/// Forward boxlite stderr chunks to the host stderr stream.
async fn drain_stderr(stream: Option<&mut ExecStderr>) -> Result<()> {
    let Some(stream) = stream else {
        return Ok(());
    };
    while let Some(chunk) = stream.next().await {
        std::io::stderr()
            .write_all(chunk.as_bytes())
            .map_err(Error::Output)?;
    }
    Ok(())
}

/// Map a Heimdall [`MicrovmSecret`] to a `boxlite::Secret`.
///
/// `SecretHostPattern` flattens to plain host strings: boxlite performs its
/// own exact + `*.wildcard` matching (R5). `SecretHostPattern::Any` is
/// rejected at the schema layer and never reaches here (V44).
fn map_secret(secret: &MicrovmSecret) -> Secret {
    Secret {
        name: secret.name().to_string(),
        hosts: secret
            .hosts()
            .iter()
            .map(|pattern| match pattern {
                SecretHostPattern::Exact(host) => host.clone(),
                SecretHostPattern::Wildcard(pattern) => pattern.clone(),
            })
            .collect(),
        placeholder: secret.placeholder().to_string(),
        value: secret.value().to_string(),
    }
}

/// Map a boxlite exit code to a Heimdall exit code.
///
/// boxlite reports a process killed by Unix signal `n` as a negative exit code
/// (`-n`). Heimdall preserves normal exit codes and maps signal termination to
/// `128 + n` (V10).
fn map_exit_code(code: i32) -> i32 {
    if code < 0 { 128 + (-code) } else { code }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use heimdall_sandbox_policy::{
        MicrovmGuest, MicrovmLifecycle, MicrovmResources, MicrovmSecret, RlimitResource,
        RlimitSpec, SecretHostPattern,
    };

    /// Run `validate_policy` for the given varying inputs. Common fields use
    /// safe defaults; the argv/cwd stay local so no borrow escapes.
    fn validate(
        image: Option<&str>,
        microvm_policy: &MicrovmPolicy,
        filesystem_policy: &FilesystemPolicy,
        proc_mode: ProcMode,
        agent_policy: AgentPolicy,
    ) -> Result<()> {
        let argv = ["true".to_string()];
        let request = MicrovmRequest {
            cwd: Path::new("."),
            argv: &argv,
            image,
            environment: &[],
            network_mode: NetworkMode::Host,
            filesystem_policy,
            proc_mode,
            agent_policy,
            microvm_policy,
        };
        request.validate_policy()
    }

    #[test]
    fn rejects_empty_image() {
        let error = validate(
            None,
            &MicrovmPolicy::default(),
            &FilesystemPolicy::default(),
            ProcMode::Default,
            AgentPolicy::default(),
        )
        .expect_err("empty image rejects");

        assert!(error.to_string().contains("non-empty policy image"));
    }

    #[test]
    fn rejects_upper_size() {
        let policy = MicrovmPolicy::new(
            MicrovmResources::new(None, None, Some(256), Vec::new()),
            MicrovmLifecycle::default(),
            MicrovmGuest::default(),
            Vec::new(),
            None,
        );
        let error = validate(
            Some("alpine"),
            &policy,
            &FilesystemPolicy::default(),
            ProcMode::Default,
            AgentPolicy::default(),
        )
        .expect_err("upper size rejects");

        assert!(error.to_string().contains("resources.upperSize"));
    }

    #[test]
    fn accepts_supported_rlimit() {
        let policy = MicrovmPolicy::new(
            MicrovmResources::new(
                None,
                None,
                None,
                vec![RlimitSpec::new(RlimitResource::Nofile, 1024, 1024)],
            ),
            MicrovmLifecycle::default(),
            MicrovmGuest::default(),
            Vec::new(),
            None,
        );
        validate(
            Some("alpine"),
            &policy,
            &FilesystemPolicy::default(),
            ProcMode::Default,
            AgentPolicy::default(),
        )
        .expect("supported rlimit validates");
    }

    #[test]
    fn rejects_idle_timeout() {
        let policy = MicrovmPolicy::new(
            MicrovmResources::default(),
            MicrovmLifecycle::new(None, Some(60)),
            MicrovmGuest::default(),
            Vec::new(),
            None,
        );
        let error = validate(
            Some("alpine"),
            &policy,
            &FilesystemPolicy::default(),
            ProcMode::Default,
            AgentPolicy::default(),
        )
        .expect_err("idle timeout rejects");

        assert!(error.to_string().contains("lifecycle.idleTimeout"));
    }

    #[test]
    fn accepts_secrets() {
        let secret = MicrovmSecret::new(
            "openai_api_key".to_string(),
            "<BOXLITE_SECRET:openai>".to_string(),
            "sk-...".to_string(),
            vec![SecretHostPattern::Exact("api.openai.com".to_string())],
        );
        let policy = MicrovmPolicy::new(
            MicrovmResources::default(),
            MicrovmLifecycle::default(),
            MicrovmGuest::default(),
            vec![secret],
            None,
        );
        validate(
            Some("alpine"),
            &policy,
            &FilesystemPolicy::default(),
            ProcMode::Default,
            AgentPolicy::default(),
        )
        .expect("secrets validate and map to boxlite Secret");
    }

    #[test]
    fn maps_secret_to_boxlite() {
        let secret = MicrovmSecret::new(
            "openai_api_key".to_string(),
            "<BOXLITE_SECRET:openai>".to_string(),
            "sk-...".to_string(),
            vec![
                SecretHostPattern::Exact("api.openai.com".to_string()),
                SecretHostPattern::Wildcard("*.openai.com".to_string()),
            ],
        );
        let mapped = map_secret(&secret);
        assert_eq!(mapped.name, "openai_api_key");
        assert_eq!(mapped.placeholder, "<BOXLITE_SECRET:openai>");
        assert_eq!(mapped.value, "sk-...");
        assert_eq!(mapped.hosts, vec!["api.openai.com", "*.openai.com"]);
    }

    #[test]
    fn rejects_virtual_files() {
        let mut virtual_files = BTreeMap::new();
        virtual_files.insert(
            PathBuf::from("/etc/heimdall-virtual"),
            "redacted".to_string(),
        );
        let filesystem_policy = FilesystemPolicy::new(Vec::new(), Vec::new(), virtual_files);
        let error = validate(
            Some("alpine"),
            &MicrovmPolicy::default(),
            &filesystem_policy,
            ProcMode::Default,
            AgentPolicy::default(),
        )
        .expect_err("virtual files reject");

        assert!(error.to_string().contains("filesystem.virtual"));
    }

    #[test]
    fn rejects_proc_none() {
        let error = validate(
            Some("alpine"),
            &MicrovmPolicy::default(),
            &FilesystemPolicy::default(),
            ProcMode::Disabled,
            AgentPolicy::default(),
        )
        .expect_err("proc none rejects");

        assert!(error.to_string().contains("proc=none"));
    }

    #[test]
    fn rejects_agent_policy() {
        let error = validate(
            Some("alpine"),
            &MicrovmPolicy::default(),
            &FilesystemPolicy::default(),
            ProcMode::Default,
            AgentPolicy::new(true, false, false),
        )
        .expect_err("agent policy rejects");

        assert!(error.to_string().contains("agent socket"));
    }

    #[test]
    fn maps_signal_exit_code() {
        assert_eq!(map_exit_code(0), 0);
        assert_eq!(map_exit_code(42), 42);
        // SIGTERM (15) -> 128 + 15.
        assert_eq!(map_exit_code(-15), 143);
    }
}
