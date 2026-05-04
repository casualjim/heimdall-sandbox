//! Process hardening helpers shared by Heimdall sandbox runtime crates.

#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

/// Apply process hardening to the current process.
///
/// # Errors
///
/// Returns the underlying OS error when a required hardening operation fails.
pub fn apply_process_hardening() -> std::io::Result<()> {
    apply_platform_hardening()?;
    remove_dangerous_environment_variables();
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

/// Arrange for a Linux child process to receive `SIGTERM` if its parent dies.
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

/// Return whether an environment key can subvert platform loader or allocator behavior.
#[cfg(unix)]
#[must_use]
pub fn is_dangerous_environment_key(key: &OsStr) -> bool {
    let key = key.as_bytes();
    is_platform_loader_key(key) || is_macos_allocator_logging_key(key)
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd"
))]
fn is_platform_loader_key(key: &[u8]) -> bool {
    key.starts_with(b"LD_")
}

#[cfg(target_os = "macos")]
fn is_platform_loader_key(key: &[u8]) -> bool {
    key.starts_with(b"DYLD_")
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "macos"
)))]
fn is_platform_loader_key(_key: &[u8]) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn is_macos_allocator_logging_key(key: &[u8]) -> bool {
    key.starts_with(b"MallocStackLogging") || key.starts_with(b"MallocLogFile")
}

#[cfg(not(target_os = "macos"))]
fn is_macos_allocator_logging_key(_key: &[u8]) -> bool {
    false
}

#[cfg(unix)]
fn remove_dangerous_environment_variables() {
    let keys = std::env::vars_os()
        .filter_map(|(key, _)| is_dangerous_environment_key(&key).then_some(key))
        .collect::<Vec<_>>();

    for key in keys {
        // SAFETY: callers run process hardening during sandbox startup before Heimdall starts
        // background threads or exposes the environment to child process construction.
        unsafe {
            std::env::remove_var(key);
        }
    }
}

#[cfg(not(unix))]
fn remove_dangerous_environment_variables() {}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    #[cfg(unix)]
    #[test]
    fn dangerous_environment_keys_match_platform_loader_prefixes() {
        #[cfg(target_os = "linux")]
        {
            assert!(is_dangerous_environment_key(&OsString::from("LD_PRELOAD")));
            assert!(!is_dangerous_environment_key(&OsString::from(
                "DYLD_INSERT_LIBRARIES"
            )));
        }

        #[cfg(target_os = "macos")]
        {
            assert!(is_dangerous_environment_key(&OsString::from(
                "DYLD_INSERT_LIBRARIES"
            )));
            assert!(is_dangerous_environment_key(&OsString::from(
                "MallocStackLogging"
            )));
            assert!(is_dangerous_environment_key(&OsString::from(
                "MallocLogFile"
            )));
            assert!(!is_dangerous_environment_key(&OsString::from("LD_PRELOAD")));
        }
    }

    #[cfg(all(unix, target_os = "linux"))]
    #[test]
    fn dangerous_environment_keys_handle_non_utf8_entries() {
        use std::os::unix::ffi::OsStringExt;

        let key = OsString::from_vec(vec![b'L', b'D', b'_', 0xf0]);

        assert!(is_dangerous_environment_key(&key));
    }
}
