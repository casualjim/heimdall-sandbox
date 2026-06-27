//! Process hardening for the current process and sandboxed children.

/// Apply process hardening to the current process.
///
/// # Errors
///
/// Returns the underlying OS error when a required hardening operation fails.
pub fn apply_process_hardening() -> std::io::Result<()> {
    apply_platform_hardening()?;
    crate::environment::remove_dangerous_environment_variables();
    Ok(())
}

/// Apply process hardening to a child process before it executes the requested command.
///
/// # Errors
///
/// Returns the underlying OS error when a required hardening operation fails.
pub fn apply_child_hardening() -> std::io::Result<()> {
    apply_platform_hardening()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn apply_platform_hardening() -> std::io::Result<()> {
    disable_debug_attach()?;
    set_core_file_size_limit_to_zero()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn apply_platform_hardening() -> std::io::Result<()> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn set_core_file_size_limit_to_zero() -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    // SAFETY: `limit` points to a valid rlimit value for `RLIMIT_CORE`.
    let result = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn disable_debug_attach() -> std::io::Result<()> {
    // SAFETY: `prctl` is called with `PR_SET_DUMPABLE` and integer arguments as required by Linux.
    let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn disable_debug_attach() -> std::io::Result<()> {
    // SAFETY: `ptrace` is called with `PT_DENY_ATTACH` and null address/data as required by macOS.
    let result = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
