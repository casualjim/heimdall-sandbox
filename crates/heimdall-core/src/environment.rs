use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};

pub(crate) fn build_child_environment<P, K, V, A, N, D, M>(
    parent: P,
    allowed: A,
    denied: D,
    inherit: bool,
) -> Vec<(OsString, OsString)>
where
    P: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: Into<OsString>,
    A: IntoIterator<Item = N>,
    N: AsRef<str>,
    D: IntoIterator<Item = M>,
    M: AsRef<str>,
{
    let allowed = allowed
        .into_iter()
        .map(|key| OsString::from(key.as_ref()))
        .collect::<BTreeSet<_>>();
    let denied = denied
        .into_iter()
        .map(|key| OsString::from(key.as_ref()))
        .collect::<BTreeSet<_>>();

    parent
        .into_iter()
        .filter_map(|(key, value)| {
            let key = key.as_ref();
            let keep = if inherit {
                !denied.contains(key)
            } else {
                allowed.contains(key) && !denied.contains(key)
            };
            keep.then(|| (key.to_os_string(), value.into()))
        })
        .collect()
}

pub(crate) fn strip_dangerous_environment(
    environment: Vec<(OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    environment
        .into_iter()
        .filter(|(key, _)| !dangerous_environment_key(key))
        .collect()
}

#[cfg(unix)]
fn dangerous_environment_key(key: &OsStr) -> bool {
    heimdall_process_hardening::is_dangerous_environment_key(key)
}

#[cfg(not(unix))]
fn dangerous_environment_key(_key: &OsStr) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn allowed_environment_values_are_preserved() {
        let parent = vec![
            (OsString::from("PATH"), OsString::from("/bin")),
            (OsString::from("SECRET"), OsString::from("token")),
        ];
        let allowed = BTreeSet::from(["PATH".to_owned()]);

        let filtered = build_child_environment(parent, allowed.iter(), Vec::<String>::new(), false);

        assert!(filtered.contains(&(OsString::from("PATH"), OsString::from("/bin"))));
        assert!(!filtered.iter().any(|(key, _)| key == "SECRET"));
    }

    #[test]
    fn denied_environment_values_are_removed_when_inheriting() {
        let parent = vec![
            (OsString::from("PATH"), OsString::from("/bin")),
            (OsString::from("SECRET"), OsString::from("token")),
        ];
        let denied = BTreeSet::from(["SECRET".to_owned()]);

        let filtered = build_child_environment(parent, Vec::<String>::new(), denied.iter(), true);

        assert!(filtered.contains(&(OsString::from("PATH"), OsString::from("/bin"))));
        assert!(!filtered.iter().any(|(key, _)| key == "SECRET"));
    }

    #[test]
    fn dangerous_environment_prefixes_are_removed() {
        let environment = vec![
            (OsString::from("LD_PRELOAD"), OsString::from("evil.so")),
            (
                OsString::from("DYLD_INSERT_LIBRARIES"),
                OsString::from("evil.dylib"),
            ),
            (OsString::from("MallocStackLogging"), OsString::from("1")),
            (
                OsString::from("MallocLogFile"),
                OsString::from("/tmp/malloc.log"),
            ),
            (OsString::from("PATH"), OsString::from("/bin")),
        ];

        let stripped = strip_dangerous_environment(environment);

        assert!(stripped.contains(&(OsString::from("PATH"), OsString::from("/bin"))));
        #[cfg(target_os = "linux")]
        {
            assert!(!stripped.iter().any(|(key, _)| key == "LD_PRELOAD"));
            assert!(
                stripped
                    .iter()
                    .any(|(key, _)| key == "DYLD_INSERT_LIBRARIES")
            );
            assert!(stripped.iter().any(|(key, _)| key == "MallocStackLogging"));
            assert!(stripped.iter().any(|(key, _)| key == "MallocLogFile"));
        }
        #[cfg(target_os = "macos")]
        {
            assert!(stripped.iter().any(|(key, _)| key == "LD_PRELOAD"));
            assert!(
                !stripped
                    .iter()
                    .any(|(key, _)| key == "DYLD_INSERT_LIBRARIES")
            );
            assert!(!stripped.iter().any(|(key, _)| key == "MallocStackLogging"));
            assert!(!stripped.iter().any(|(key, _)| key == "MallocLogFile"));
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            assert!(stripped.iter().any(|(key, _)| key == "LD_PRELOAD"));
            assert!(
                stripped
                    .iter()
                    .any(|(key, _)| key == "DYLD_INSERT_LIBRARIES")
            );
            assert!(stripped.iter().any(|(key, _)| key == "MallocStackLogging"));
            assert!(stripped.iter().any(|(key, _)| key == "MallocLogFile"));
        }
    }
}
