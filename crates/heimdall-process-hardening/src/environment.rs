//! Dangerous environment variable detection and removal.

#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

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
pub(crate) fn remove_dangerous_environment_variables() {
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
pub(crate) fn remove_dangerous_environment_variables() {}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::is_dangerous_environment_key;

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
