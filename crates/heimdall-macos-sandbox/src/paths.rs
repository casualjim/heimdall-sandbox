//! Host path and environment socket helpers for Seatbelt policy planning.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use heimdall_sandbox_policy::{ConcretePathState, concrete_path_state};

use crate::Result;

pub(crate) fn env_socket_path(value: Option<&OsStr>) -> Result<Option<PathBuf>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    if path.is_absolute() && optional_path_exists(&path)? {
        Ok(Some(path))
    } else {
        Ok(None)
    }
}

pub(crate) fn gpg_agent_info_socket(value: Option<&OsStr>) -> Result<Option<PathBuf>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.to_string_lossy();
    let Some(path) = value.split(':').next() else {
        return Ok(None);
    };
    env_socket_path(Some(OsStr::new(path)))
}

pub(crate) fn optional_path_exists(path: &Path) -> Result<bool> {
    concrete_path_state(path)
        .map(|state| matches!(state, ConcretePathState::Existing))
        .map_err(Into::into)
}

pub(crate) fn path_matcher(path: &Path, param: &str) -> String {
    if path.is_dir() {
        format!("(subpath (param \"{param}\"))")
    } else {
        format!("(literal (param \"{param}\"))")
    }
}

pub(crate) fn path_has_prefix(path: &Path, prefix: &Path) -> bool {
    path == prefix || path.starts_with(prefix)
}

pub(crate) fn path_aliases(path: &Path) -> BTreeSet<PathBuf> {
    let mut aliases = BTreeSet::from([path.to_path_buf()]);
    if let Some(canonical) = canonicalize_existing_prefix(path) {
        aliases.insert(canonical);
    }
    aliases
}

pub(crate) fn canonicalize_existing_prefix(path: &Path) -> Option<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Some(canonical);
    }
    let mut missing = Vec::new();
    let mut current = path;
    loop {
        if let Ok(canonical) = current.canonicalize() {
            let mut rebuilt = canonical;
            for component in missing.iter().rev() {
                rebuilt.push(component);
            }
            return Some(rebuilt);
        }
        let name = current.file_name()?.to_os_string();
        missing.push(name);
        current = current.parent()?;
    }
}

pub(crate) fn regex_escape_path(path: &Path) -> String {
    regex_escape(&path.to_string_lossy())
}

pub(crate) fn regex_escape(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        if matches!(
            ch,
            '.' | '+' | '*' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
        ) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

pub(crate) fn dirs_home() -> Option<PathBuf> {
    heimdall_sandbox_policy::home_dir()
}

#[cfg(target_os = "macos")]
pub(crate) fn darwin_user_cache_dir() -> Result<PathBuf> {
    confstr_path(libc::_CS_DARWIN_USER_CACHE_DIR, "_CS_DARWIN_USER_CACHE_DIR")
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn darwin_user_cache_dir() -> Result<PathBuf> {
    Ok(std::env::temp_dir())
}

#[cfg(target_os = "macos")]
pub(crate) fn darwin_user_temp_dir() -> Result<PathBuf> {
    confstr_path(libc::_CS_DARWIN_USER_TEMP_DIR, "_CS_DARWIN_USER_TEMP_DIR")
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn darwin_user_temp_dir() -> Result<PathBuf> {
    Ok(std::env::temp_dir())
}

#[cfg(target_os = "macos")]
fn confstr_path(cs_name: libc::c_int, label: &str) -> Result<PathBuf> {
    use std::ffi::CStr;

    let mut buffer = vec![0_i8; (libc::PATH_MAX as usize) + 1];
    // SAFETY: `buffer` points to writable memory with length `buffer.len()`.
    let len = unsafe { libc::confstr(cs_name, buffer.as_mut_ptr(), buffer.len()) };
    if len > 0 {
        // SAFETY: `confstr` writes a nul-terminated string when it returns a non-zero length.
        if let Ok(path) = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_str() {
            return Ok(PathBuf::from(path)
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from(path)));
        }
    }
    Err(Error::PlatformDirectory {
        message: format!("confstr({label}) returned empty path"),
    })
}
