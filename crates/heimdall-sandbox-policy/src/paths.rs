//! Concrete host path classification and filesystem policy path helpers.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use crate::{DENY_FRAGMENT, Error, Result, WRITE_FRAGMENT};

/// Existence state for a concrete host path after literal expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcretePathState {
    /// The final directory entry exists, including dangling final symlinks.
    Existing,
    /// The final entry or an ancestor is confirmed absent.
    Missing,
}

impl ConcretePathState {
    pub(crate) const fn is_existing(self) -> bool {
        matches!(self, Self::Existing)
    }

    pub(crate) const fn is_missing(self) -> bool {
        matches!(self, Self::Missing)
    }
}

/// Classify a concrete absolute host path without following the final component.
///
/// # Errors
///
/// Returns an indeterminate-path error for permission, traversal, or other non-not-found failures.
pub fn concrete_path_state(path: &Path) -> Result<ConcretePathState> {
    let mut current = PathBuf::new();
    let components = path.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        match std::fs::symlink_metadata(&current) {
            Ok(_) if index + 1 == components.len() => return Ok(ConcretePathState::Existing),
            Ok(metadata) if metadata.file_type().is_symlink() => match current.canonicalize() {
                Ok(canonical) => current = canonical,
                Err(source) => {
                    return Err(Error::IndeterminatePath {
                        path: current,
                        source,
                    });
                }
            },
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ConcretePathState::Missing);
            }
            Err(source) => {
                return Err(Error::IndeterminatePath {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(ConcretePathState::Existing)
}

/// Return the current user's home directory.
///
/// Uses the `dirs` crate for platform-correct resolution.
#[must_use]
pub fn home_dir() -> Option<PathBuf> {
    dirs::home_dir()
}

pub(crate) fn expand_home_pattern(pattern: &str) -> String {
    let Some(body) = pattern.strip_prefix('!') else {
        return shellexpand::tilde(pattern).into_owned();
    };
    format!("!{}", shellexpand::tilde(body))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiteralPathRule {
    pub(crate) path: PathBuf,
    pub(crate) selected: bool,
    pub(crate) order: usize,
}

impl LiteralPathRule {
    pub(crate) fn matches(&self, path: &Path) -> bool {
        path == self.path || (self.path.is_dir() && path.starts_with(&self.path))
    }

    pub(crate) fn specificity(&self) -> usize {
        self.path
            .components()
            .filter(|component| !matches!(component, Component::RootDir | Component::Prefix(_)))
            .count()
    }
}

pub(crate) fn literal_path_decision<'a>(
    path: &Path,
    rules: &'a [LiteralPathRule],
) -> Option<&'a LiteralPathRule> {
    rules
        .iter()
        .filter(|rule| rule.matches(path))
        .max_by_key(|rule| (rule.specificity(), rule.order))
}

pub(crate) fn literal_path_is_selected(path: &Path, rules: &[LiteralPathRule]) -> bool {
    literal_path_decision(path, rules).is_some_and(|rule| rule.selected)
}

pub(crate) fn contains_pattern_metacharacter(pattern: &str) -> bool {
    pattern
        .chars()
        .any(|ch| matches!(ch, '*' | '?' | '[' | ']'))
}

pub(crate) fn path_has_prefix(path: &Path, prefix: &Path) -> bool {
    path == prefix || path.starts_with(prefix)
}

pub(crate) fn has_denied_directory_ancestor(path: &Path, deny_targets: &BTreeSet<PathBuf>) -> bool {
    path.ancestors()
        .skip(1)
        .any(|ancestor| deny_targets.contains(ancestor) && ancestor.is_dir())
}

pub(crate) fn protected_control_candidate_paths(cwd: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut paths = [".git", ".agents", ".pi", DENY_FRAGMENT, WRITE_FRAGMENT]
        .into_iter()
        .map(|name| cwd.join(name))
        .collect::<BTreeSet<_>>();
    if cwd.is_dir() {
        for entry in std::fs::read_dir(cwd).map_err(|source| Error::ReadDir {
            cwd: cwd.to_path_buf(),
            source,
        })? {
            let entry = entry.map_err(|source| Error::ReadEntry {
                cwd: cwd.to_path_buf(),
                source,
            })?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with(".heimdall-") {
                paths.insert(entry.path());
            }
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{ConcretePathState, concrete_path_state, home_dir};
    use crate::Error;

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "heimdall-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        std::fs::create_dir(&dir).expect("temp dir is created");
        dir
    }

    #[test]
    fn concrete_classifier_handles_absolute_missing_existing_and_tilde_inputs() {
        let cwd = unique_dir("concrete-classifier");
        let existing = cwd.join("exists");
        std::fs::write(&existing, "data").expect("file written");
        let missing = cwd.join("missing");

        assert_eq!(
            concrete_path_state(&existing).expect("existing path classifies"),
            ConcretePathState::Existing
        );
        assert_eq!(
            concrete_path_state(&missing).expect("missing path classifies"),
            ConcretePathState::Missing
        );
        if let Some(home) = home_dir() {
            assert_eq!(
                concrete_path_state(&home).expect("home path classifies"),
                ConcretePathState::Existing
            );
        }
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }

    #[cfg(unix)]
    #[test]
    fn final_component_symlinks_are_existing_even_when_dangling() {
        use std::os::unix::fs::symlink;

        let cwd = unique_dir("concrete-symlink");
        let target = cwd.join("target");
        let link = cwd.join("link");
        let dangling = cwd.join("dangling");
        std::fs::write(&target, "data").expect("target written");
        symlink(&target, &link).expect("symlink created");
        symlink(cwd.join("absent"), &dangling).expect("dangling symlink created");

        assert_eq!(
            concrete_path_state(&link).expect("link classifies"),
            ConcretePathState::Existing
        );
        assert_eq!(
            concrete_path_state(&dangling).expect("dangling link classifies"),
            ConcretePathState::Existing
        );
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }

    #[test]
    fn missing_ancestor_classifies_requested_path_as_missing() {
        let cwd = unique_dir("missing-ancestor");
        let requested = cwd.join("absent").join("child");

        assert_eq!(
            concrete_path_state(&requested).expect("path classifies"),
            ConcretePathState::Missing
        );
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_ancestor_canonicalization_failure_is_indeterminate() {
        use std::os::unix::fs::symlink;

        let cwd = unique_dir("indeterminate-ancestor");
        let dangling = cwd.join("dangling-parent");
        symlink(cwd.join("absent"), &dangling).expect("dangling symlink created");
        let requested = dangling.join("child");

        assert!(matches!(
            concrete_path_state(&requested),
            Err(Error::IndeterminatePath { .. })
        ));
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }
}
