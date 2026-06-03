use std::ffi::OsString;
use std::io::Write;
use std::path::Path;

use heimdall_sandbox_policy::{AgentPolicy, FilesystemPolicy, NetworkMode, ProcMode};
use microsandbox::{ExecEvent, Sandbox};

use crate::environment::utf8_environment;
use crate::naming::sandbox_name;
use crate::preflight::preflight_host;
use crate::{Error, Result};

const GUEST_WORKDIR: &str = "/workspace";

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
        if !self.filesystem_policy.is_empty() {
            return Err(Error::unsupported_policy(
                "microvm runtime does not yet support filesystem policy parity",
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
        let environment = utf8_environment(self.environment)?;
        let mut builder = Sandbox::builder(sandbox_name()?)
            .image(self.image)
            .workdir(GUEST_WORKDIR)
            .volume(GUEST_WORKDIR, |mount| mount.bind(cwd))
            .envs(environment);
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
    fn rejects_filesystem_policy() {
        let policy =
            FilesystemPolicy::new(vec!["secret".to_string()], Vec::new(), Default::default());
        let request = MicrovmRequest {
            cwd: Path::new("."),
            argv: &["true".to_string()],
            image: "alpine",
            environment: &[],
            network_mode: NetworkMode::Host,
            filesystem_policy: &policy,
            proc_mode: ProcMode::Default,
            agent_policy: AgentPolicy::default(),
        };

        let error = request
            .validate_policy()
            .expect_err("filesystem policy rejects");

        assert!(error.to_string().contains("filesystem policy parity"));
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
