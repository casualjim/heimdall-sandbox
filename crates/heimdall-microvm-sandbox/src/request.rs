use std::ffi::OsString;
use std::io::Write;
use std::path::Path;

use heimdall_sandbox_policy::{
    AgentPolicy, FilesystemPolicy, FilesystemPolicyMaterializer, NetworkMode, ProcMode,
};
use microsandbox::{ExecEvent, Sandbox};

use crate::environment::utf8_environment;
use crate::filesystem::{FilesystemPlan, GUEST_WORKDIR, plan_filesystem};
use crate::naming::sandbox_name;
use crate::preflight::preflight_host;
use crate::{Error, Result};

/// Structured input used to run a command in a microsandbox microVM.
pub struct MicrovmRequest<'a> {
    /// Host working directory mounted into the guest.
    pub cwd: &'a Path,
    /// Child argv to run inside the guest.
    pub argv: &'a [String],
    /// Microsandbox root filesystem image or local rootfs path.
    pub image: &'a str,
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
}

impl MicrovmRequest<'_> {
    /// Execute this request in an ephemeral attached microsandbox.
    ///
    /// # Errors
    ///
    /// Returns a sandbox misconfiguration when host preflight fails, policy cannot be represented,
    /// microsandbox startup/exec/stop fails, or output forwarding fails.
    pub fn execute(&self) -> Result<i32> {
        self.validate_policy()?;
        preflight_host()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(Error::Runtime)?;
        runtime.block_on(self.execute_async())
    }

    fn validate_policy(&self) -> Result<()> {
        if self.image.is_empty() {
            return Err(Error::unsupported_policy(
                "microvm runtime requires non-empty policy image",
            ));
        }
        if self.proc_mode != ProcMode::Default {
            return Err(Error::unsupported_policy(
                "microvm runtime does not yet support proc=none parity",
            ));
        }
        if !self.agent_policy.is_empty() {
            return Err(Error::unsupported_policy(
                "microvm runtime does not yet support agent socket parity",
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
        let builder = Sandbox::builder(sandbox_name()?)
            .image(self.image)
            .ephemeral(true);
        // Add filesystem mounts before setting the workdir: the workdir points at
        // /workspace, which the workspace bind mount creates in the guest. The
        // SDK validates the workdir exists after start, so the mount must be in
        // the config first (mirrors `msb run --mount-dir ... -w /workspace`).
        let builder = Self::apply_filesystem_plan(builder, &plan);
        let mut builder = builder.workdir(GUEST_WORKDIR).envs(environment);
        if self.network_mode == NetworkMode::None {
            builder = builder.disable_network();
        }

        let sandbox = builder.create().await?;
        let exec_result = self.execute_command(&sandbox).await;
        let stop_result = sandbox.stop_and_wait().await.map_err(Error::from);
        match (exec_result, stop_result) {
            (Ok(exit_code), Ok(_)) => Ok(exit_code),
            (Err(error), Ok(_)) | (Err(error), Err(_)) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn apply_filesystem_plan(
        mut builder: microsandbox::sandbox::SandboxBuilder,
        plan: &FilesystemPlan,
    ) -> microsandbox::sandbox::SandboxBuilder {
        for volume in &plan.volumes {
            let host = volume.host.clone();
            let readonly = volume.readonly;
            builder = builder.volume(volume.guest.clone(), move |mount| {
                let mount = mount.bind(host);
                if readonly { mount.readonly() } else { mount }
            });
        }
        if !plan.virtual_files.is_empty() {
            builder = builder.patch(|mut patches| {
                for file in &plan.virtual_files {
                    patches = patches.text(file.guest.clone(), file.content.clone(), None, true);
                }
                patches
            });
        }
        builder
    }

    async fn execute_command(&self, sandbox: &Sandbox) -> Result<i32> {
        let (program, args) = self
            .argv
            .split_first()
            .ok_or_else(|| Error::unsupported_policy("microvm runtime requires command argv"))?;
        let mut handle = sandbox.exec_stream(program, args.iter().cloned()).await?;
        while let Some(event) = handle.recv().await {
            match event {
                ExecEvent::Started { pid: _ } => {}
                ExecEvent::Stdout(bytes) => {
                    std::io::stdout().write_all(&bytes).map_err(Error::Output)?;
                }
                ExecEvent::Stderr(bytes) => {
                    std::io::stderr().write_all(&bytes).map_err(Error::Output)?;
                }
                ExecEvent::Exited { code } => return Ok(code),
                ExecEvent::Failed(payload) => {
                    return Err(microsandbox::MicrosandboxError::ExecFailed(payload).into());
                }
                ExecEvent::StdinError(_) => {}
            }
        }
        Err(Error::platform("microvm exec ended without exit event"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_image() {
        let policy = FilesystemPolicy::default();
        let request = MicrovmRequest {
            cwd: Path::new("."),
            argv: &["true".to_string()],
            image: "",
            environment: &[],
            network_mode: NetworkMode::Host,
            filesystem_policy: &policy,
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        };

        let error = request.validate_policy().expect_err("empty image rejects");

        assert!(error.to_string().contains("non-empty policy image"));
    }

    #[test]
    fn rejects_proc_none() {
        let policy = FilesystemPolicy::default();
        let request = MicrovmRequest {
            cwd: Path::new("."),
            argv: &["true".to_string()],
            image: "alpine",
            environment: &[],
            network_mode: NetworkMode::Host,
            filesystem_policy: &policy,
            proc_mode: ProcMode::Disabled,
            agent_policy: AgentPolicy::default(),
        };

        let error = request.validate_policy().expect_err("proc none rejects");

        assert!(error.to_string().contains("proc=none parity"));
    }
}
