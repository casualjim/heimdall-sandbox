//! Parent-death signal wiring for Linux child processes.

/// Arrange for a Linux child process to receive `SIGTERM` if its parent dies.
///
/// # Race window
///
/// After `prctl(PR_SET_PDEATHSIG)` succeeds, this function checks whether the
/// parent PID has already changed. There is an inherent TOCTOU race: the
/// original parent could die and a new process could reuse the PID between the
/// kernel registering the death signal and this userspace check. In practice
/// this is extremely unlikely because PID recycling requires the PID allocator
/// to wrap, but callers should be aware of the theoretical gap.
///
/// # Errors
///
/// Returns the underlying OS error when `prctl(PR_SET_PDEATHSIG)` fails.
#[cfg(target_os = "linux")]
pub fn terminate_with_parent(parent_pid: libc::pid_t) -> std::io::Result<()> {
    // SAFETY: `prctl` is called with `PR_SET_PDEATHSIG` and a valid signal number.
    let result = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: `getppid` has no preconditions.
    if unsafe { libc::getppid() } != parent_pid {
        // SAFETY: `SIGTERM` is a valid signal for the current process.
        unsafe {
            libc::raise(libc::SIGTERM);
        }
    }

    Ok(())
}
