use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;

use crate::child::ChildGuard;
use crate::environment::{build_child_environment, strip_dangerous_environment};
use crate::outcome::child_outcome;
use crate::request::{EnvPolicy, ExecRequest, StdioPolicy, validate_cwd};
use crate::{Error, Result};

#[cfg(target_os = "linux")]
use heimdall_linux_sandbox::BubblewrapRequest;

/// Executes sandbox requests.
pub struct Executor;

impl Executor {
    /// Execute a sandbox request and return the child process exit code.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, hardening, spawning, signal setup, or wait fails.
    pub fn execute(&self, request: &ExecRequest) -> Result<i32> {
        self.execute_with_hardener(request, heimdall_process_hardening::apply_child_hardening)
    }

    fn execute_with_hardener(
        &self,
        request: &ExecRequest,
        hardener: impl FnOnce() -> std::io::Result<()> + Send + Sync + 'static,
    ) -> Result<i32> {
        if request.needs_isolation() {
            #[cfg(target_os = "linux")]
            {
                return self.execute_with_bubblewrap(request);
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(Error::sandbox_misconfiguration(
                    "filesystem/network isolation is only supported on Linux",
                ));
            }
        }

        self.execute_direct_with_hardener(request, hardener)
    }

    fn execute_direct_with_hardener(
        &self,
        request: &ExecRequest,
        hardener: impl FnOnce() -> std::io::Result<()> + Send + Sync + 'static,
    ) -> Result<i32> {
        validate_cwd(request.cwd())?;
        let child_environment = self.child_environment(request);

        let mut command = Command::new(&request.argv()[0]);
        command
            .args(&request.argv()[1..])
            .current_dir(request.cwd())
            .env_clear()
            .envs(child_environment);
        Self::configure_stdio(&mut command, request.stdio_policy());

        #[cfg(unix)]
        install_child_setup(&mut command, hardener);

        #[cfg(not(unix))]
        hardener().map_err(Error::Hardening)?;

        self.execute_command(command, request.stdio_policy())
    }

    fn child_environment(
        &self,
        request: &ExecRequest,
    ) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
        let parent_environment = std::env::vars_os().collect::<Vec<_>>();
        let child_environment = build_child_environment(
            parent_environment,
            request.allowed_env(),
            request.denied_env(),
            request.env_policy() == EnvPolicy::Blocklist,
        );
        strip_dangerous_environment(child_environment)
    }

    fn execute_command(&self, command: Command, stdio_policy: StdioPolicy) -> Result<i32> {
        self.execute_command_with_signal_target(command, stdio_policy, false)
    }

    fn execute_command_with_signal_target(
        &self,
        mut command: Command,
        stdio_policy: StdioPolicy,
        target_process_group: bool,
    ) -> Result<i32> {
        #[cfg(unix)]
        let forwarding = if target_process_group {
            crate::signal::SignalForwarding::install_for_process_group()?
        } else {
            crate::signal::SignalForwarding::install()?
        };

        let mut child = command.spawn().map_err(Error::Spawn)?;
        let output_forwarding = OutputForwarding::start(&mut child, stdio_policy);
        let mut child = ChildGuard::new(child);

        #[cfg(unix)]
        forwarding.set_child(child.id());

        let status = child.wait()?;
        output_forwarding.join();

        #[cfg(unix)]
        drop(forwarding);

        Ok(child_outcome(status).exit_code())
    }

    #[cfg(target_os = "linux")]
    fn execute_with_bubblewrap(&self, request: &ExecRequest) -> Result<i32> {
        validate_cwd(request.cwd())?;
        let plan = BubblewrapRequest {
            cwd: request.cwd(),
            argv: request.argv(),
            network_mode: request.network_mode(),
            stdio_policy: match request.stdio_policy() {
                StdioPolicy::Inherit => "inherit",
                StdioPolicy::Piped => "piped",
            },
            filesystem_policy: request.filesystem_policy(),
            proc_mode: request.proc_mode(),
        }
        .into_plan()
        .map_err(|error| Error::sandbox_misconfiguration(error.to_string()))?;
        let mut command = plan.command();
        command
            .current_dir(request.cwd())
            .env_clear()
            .envs(self.child_environment(request));
        Self::configure_stdio(&mut command, request.stdio_policy());
        install_bubblewrap_child_setup(&mut command);
        self.execute_command_with_signal_target(command, request.stdio_policy(), true)
    }

    fn configure_stdio(command: &mut Command, stdio_policy: StdioPolicy) {
        match stdio_policy {
            StdioPolicy::Inherit => {
                command
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit());
            }
            StdioPolicy::Piped => {
                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
            }
        }
    }
}

struct OutputForwarding {
    stdout: Option<thread::JoinHandle<std::io::Result<()>>>,
    stderr: Option<thread::JoinHandle<std::io::Result<()>>>,
}

impl OutputForwarding {
    fn start(child: &mut std::process::Child, stdio_policy: StdioPolicy) -> Self {
        if stdio_policy != StdioPolicy::Piped {
            return Self {
                stdout: None,
                stderr: None,
            };
        }

        let stdout = child.stdout.take().map(|mut stream| {
            thread::spawn(move || {
                let mut output = std::io::stdout().lock();
                copy_stream(&mut stream, &mut output)
            })
        });
        let stderr = child.stderr.take().map(|mut stream| {
            thread::spawn(move || {
                let mut output = std::io::stderr().lock();
                copy_stream(&mut stream, &mut output)
            })
        });

        Self { stdout, stderr }
    }

    fn join(self) {
        if let Some(stdout) = self.stdout {
            let _ = stdout.join();
        }
        if let Some(stderr) = self.stderr {
            let _ = stderr.join();
        }
    }
}

fn copy_stream(reader: &mut impl Read, writer: &mut impl Write) -> std::io::Result<()> {
    std::io::copy(reader, writer)?;
    writer.flush()
}

#[cfg(unix)]
fn install_child_setup(
    command: &mut Command,
    hardener: impl FnOnce() -> std::io::Result<()> + Send + Sync + 'static,
) {
    use std::os::unix::process::CommandExt;

    #[cfg(target_os = "linux")]
    // SAFETY: `getpid` has no preconditions.
    let parent_pid = unsafe { libc::getpid() };
    let mut hardener = Some(hardener);

    // SAFETY: the closure only calls libc/setup routines intended to run after fork and before
    // exec, and propagates `std::io::Error` values directly to `Command::spawn`.
    unsafe {
        command.pre_exec(move || {
            #[cfg(target_os = "linux")]
            heimdall_process_hardening::terminate_with_parent(parent_pid)?;

            let hardener = hardener.take().ok_or_else(|| {
                std::io::Error::other("child hardening callback was already consumed")
            })?;
            hardener()
        });
    }
}

#[cfg(target_os = "linux")]
fn install_bubblewrap_child_setup(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    #[cfg(target_os = "linux")]
    // SAFETY: `getpid` has no preconditions.
    let parent_pid = unsafe { libc::getpid() };

    // SAFETY: the closure only calls libc/setup routines intended to run after fork and before
    // exec, and propagates `std::io::Error` values directly to `Command::spawn`.
    unsafe {
        command.pre_exec(move || {
            // SAFETY: `setpgid(0, 0)` places the child in a fresh process group before exec.
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            heimdall_process_hardening::terminate_with_parent(parent_pid)
        });
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn hardening_failure_maps_to_misconfiguration_exit_code() {
        let request = ExecRequest::new(
            std::env::current_dir().expect("current dir exists"),
            vec!["true".to_string()],
            Vec::new(),
        )
        .expect("request is valid");

        let error = Executor
            .execute_with_hardener(&request, || Err(io::Error::other("hardening failed")))
            .expect_err("hardening failure is fatal");

        assert_eq!(error.exit_code(), crate::SANDBOX_MISCONFIGURATION_EXIT_CODE);
    }

    #[test]
    fn hardening_failure_does_not_execute_child_command() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after Unix epoch")
            .as_nanos();
        let marker = std::env::temp_dir().join(format!("heimdall-hardening-{stamp}"));
        let script = format!("touch {}", marker.display());
        let request = ExecRequest::new(
            std::env::current_dir().expect("current dir exists"),
            vec!["sh".to_string(), "-c".to_string(), script],
            Vec::new(),
        )
        .expect("request is valid");

        let error = Executor
            .execute_with_hardener(&request, || Err(io::Error::other("hardening failed")))
            .expect_err("hardening failure is fatal");

        assert_eq!(error.exit_code(), crate::SANDBOX_MISCONFIGURATION_EXIT_CODE);
        assert!(!marker.exists());
    }
}
