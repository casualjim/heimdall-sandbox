use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;

use crate::policy::ProcMode;
use crate::{Error, Result};

const PROBE_OUTPUT_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct BubblewrapLauncher {
    pub(crate) path: PathBuf,
    pub(crate) supports_argv0: bool,
}

impl BubblewrapLauncher {
    pub(crate) fn discover() -> Result<Self> {
        let path = std::env::var_os("PATH").ok_or_else(|| {
            Error::sandbox_misconfiguration("bubblewrap executable not found in PATH")
        })?;
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("bwrap");
            if candidate.is_file() && Self::executable(&candidate)? {
                return Ok(Self {
                    supports_argv0: Self::supports_argv0(&candidate)?,
                    path: candidate,
                });
            }
        }
        Err(Error::sandbox_misconfiguration(
            "bubblewrap executable not found in PATH",
        ))
    }

    fn executable(path: &Path) -> Result<bool> {
        let metadata = std::fs::metadata(path).map_err(|error| {
            Error::sandbox_misconfiguration(format!(
                "failed to inspect {}: {error}",
                path.display()
            ))
        })?;
        Ok(metadata.permissions().mode() & 0o111 != 0)
    }

    fn supports_argv0(bwrap: &Path) -> Result<bool> {
        let output = limited_output(
            Command::new(bwrap).arg("--help"),
            "probe bubblewrap argv0 support",
        )?;
        Ok(String::from_utf8_lossy(&output.stdout).contains("--argv0")
            || String::from_utf8_lossy(&output.stderr).contains("--argv0"))
    }

    pub(crate) fn effective_proc_mode(&self, proc_mode: ProcMode) -> Result<ProcMode> {
        if proc_mode == ProcMode::Disabled || self.proc_preflight_succeeds()? {
            Ok(proc_mode)
        } else {
            Ok(ProcMode::Disabled)
        }
    }

    fn proc_preflight_succeeds(&self) -> Result<bool> {
        let output = limited_output(
            Command::new(&self.path).args([
                "--die-with-parent",
                "--unshare-user",
                "--unshare-pid",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--ro-bind",
                "/usr",
                "/usr",
                "--",
                "/usr/bin/env",
                "true",
            ]),
            "run bubblewrap proc preflight",
        )?;
        if output.status.success() {
            return Ok(true);
        }
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        Ok(!(stderr.contains("proc")
            && (stderr.contains("permission")
                || stderr.contains("operation not permitted")
                || stderr.contains("invalid argument"))))
    }
}

struct LimitedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn limited_output(command: &mut Command, operation: &str) -> Result<LimitedOutput> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            Error::sandbox_misconfiguration(format!("failed to {operation}: {error}"))
        })?;

    let stdout = child.stdout.take().ok_or_else(|| {
        Error::sandbox_misconfiguration(format!(
            "failed to capture stdout while attempting to {operation}"
        ))
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        Error::sandbox_misconfiguration(format!(
            "failed to capture stderr while attempting to {operation}"
        ))
    })?;
    let stdout = thread::spawn(move || read_limited(stdout, PROBE_OUTPUT_LIMIT));
    let stderr = thread::spawn(move || read_limited(stderr, PROBE_OUTPUT_LIMIT));
    let status = child.wait().map_err(|error| {
        Error::sandbox_misconfiguration(format!(
            "failed to wait while attempting to {operation}: {error}"
        ))
    })?;
    let stdout = stdout.join().map_err(|_| {
        Error::sandbox_misconfiguration(format!(
            "stdout reader panicked while attempting to {operation}"
        ))
    })??;
    let stderr = stderr.join().map_err(|_| {
        Error::sandbox_misconfiguration(format!(
            "stderr reader panicked while attempting to {operation}"
        ))
    })??;

    Ok(LimitedOutput {
        status,
        stdout,
        stderr,
    })
}

fn read_limited(mut reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            Error::sandbox_misconfiguration(format!("failed to read child output: {error}"))
        })?;
        if read == 0 {
            return Ok(output);
        }
        if output.len() + read > limit {
            return Err(Error::sandbox_misconfiguration(format!(
                "child output exceeded {} byte limit",
                limit
            )));
        }
        output.extend_from_slice(&buffer[..read]);
    }
}
