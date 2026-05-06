use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use ignore::gitignore::{Gitignore, GitignoreBuilder};

use crate::{Error, Result};

pub(crate) const DENY_FRAGMENT: &str = ".heimdall-deny";
pub(crate) const WRITE_FRAGMENT: &str = ".heimdall-write";

/// Child network isolation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Preserve host networking.
    Host,
    /// Isolate host networking.
    None,
}

/// Child proc filesystem mount policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcMode {
    /// Mount `/proc` when host preflight allows it.
    Default,
    /// Do not mount `/proc` inside bubblewrap.
    Disabled,
}

/// Filesystem sandbox policy expressed as cwd-relative gitignore-style pattern lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilesystemPolicy {
    deny: Vec<String>,
    writable: Vec<String>,
    virtual_files: BTreeMap<PathBuf, String>,
}

impl FilesystemPolicy {
    /// Create a filesystem policy from deny patterns, writable patterns, and virtual files.
    #[must_use]
    pub fn new(
        deny: Vec<String>,
        writable: Vec<String>,
        virtual_files: BTreeMap<PathBuf, String>,
    ) -> Self {
        Self {
            deny,
            writable,
            virtual_files,
        }
    }

    /// Return true when no filesystem controls are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.deny.is_empty() && self.writable.is_empty() && self.virtual_files.is_empty()
    }

    /// Deny matcher pattern lines.
    #[must_use]
    pub fn deny(&self) -> &[String] {
        &self.deny
    }

    /// Writable matcher pattern lines.
    #[must_use]
    pub fn writable(&self) -> &[String] {
        &self.writable
    }

    /// Readonly virtual file contents keyed by absolute sandbox path.
    #[must_use]
    pub fn virtual_files(&self) -> &BTreeMap<PathBuf, String> {
        &self.virtual_files
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MaterializedFilesystemPolicy {
    pub(crate) deny_targets: BTreeSet<PathBuf>,
    pub(crate) writable_targets: BTreeSet<PathBuf>,
    pub(crate) protected_targets: BTreeSet<PathBuf>,
}

pub(crate) struct FilesystemPolicyMaterializer<'a> {
    cwd: &'a Path,
    policy: &'a FilesystemPolicy,
}

impl<'a> FilesystemPolicyMaterializer<'a> {
    pub(crate) const fn new(cwd: &'a Path, policy: &'a FilesystemPolicy) -> Self {
        Self { cwd, policy }
    }

    pub(crate) fn materialize(self) -> Result<MaterializedFilesystemPolicy> {
        let deny = self.build_matcher(self.policy.deny(), DENY_FRAGMENT)?;
        let writable = self.build_matcher(self.policy.writable(), WRITE_FRAGMENT)?;
        let paths = self.walk_existing()?;

        let mut deny_targets = BTreeSet::new();
        let mut writable_targets = BTreeSet::new();
        let cwd_is_broadly_writable = broadly_grants_cwd(self.policy.writable());
        for path in &paths {
            let is_dir = path.is_dir();
            if self.selected(path, is_dir, &deny)? {
                deny_targets.insert(path.clone());
            } else if self.selected(path, is_dir, &writable)?
                || (path == self.cwd && cwd_is_broadly_writable)
            {
                writable_targets.insert(path.clone());
            }
        }

        let protected_targets = self.protected_control_targets(&writable, &deny)?;

        Ok(MaterializedFilesystemPolicy {
            deny_targets,
            writable_targets,
            protected_targets,
        })
    }

    fn build_matcher(&self, patterns: &[String], fragment: &str) -> Result<Gitignore> {
        let mut builder = GitignoreBuilder::new(self.cwd);
        for pattern in patterns {
            builder.add_line(None, pattern).map_err(|error| {
                Error::sandbox_misconfiguration(format!(
                    "invalid filesystem pattern {pattern:?}: {error}"
                ))
            })?;
        }

        let fragment_path = self.cwd.join(fragment);
        if fragment_path.exists() {
            builder.add(&fragment_path);
        }

        builder.build().map_err(|error| {
            Error::sandbox_misconfiguration(format!(
                "invalid filesystem matcher for {fragment}: {error}"
            ))
        })
    }

    fn walk_existing(&self) -> Result<BTreeSet<PathBuf>> {
        let mut paths = BTreeSet::new();
        for entry in WalkBuilder::new(self.cwd)
            .hidden(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .parents(false)
            .build()
        {
            let entry = entry.map_err(|error| {
                Error::sandbox_misconfiguration(format!(
                    "failed to walk {}: {error}",
                    self.cwd.display()
                ))
            })?;
            paths.insert(entry.path().to_path_buf());
        }
        Ok(paths)
    }

    fn selected(&self, path: &Path, is_dir: bool, matcher: &Gitignore) -> Result<bool> {
        let relative = path.strip_prefix(self.cwd).map_err(|error| {
            Error::sandbox_misconfiguration(format!(
                "failed to relativize {} against {}: {error}",
                path.display(),
                self.cwd.display()
            ))
        })?;
        Ok(matcher.matched(relative, is_dir).is_ignore())
    }

    fn protected_control_targets(
        &self,
        writable: &Gitignore,
        deny: &Gitignore,
    ) -> Result<BTreeSet<PathBuf>> {
        let mut protected = BTreeSet::new();
        let cwd_is_writable =
            self.selected(self.cwd, true, writable)? || broadly_grants_cwd(self.policy.writable());
        for path in protected_control_candidate_paths(self.cwd)? {
            let writable_selected = self.selected(&path, path.is_dir(), writable)?;
            let deny_selected = self.selected(&path, path.is_dir(), deny)?;
            let existing_control_path_needs_readonly =
                path.exists() && (cwd_is_writable || !writable_selected || deny_selected);
            let missing_control_path_needs_readonly = cwd_is_writable;
            if existing_control_path_needs_readonly || missing_control_path_needs_readonly {
                protected.insert(path);
            }
        }
        Ok(protected)
    }
}

/// Validate filesystem pattern syntax and absolute virtual file targets.
///
/// # Errors
///
/// Returns a sandbox misconfiguration when any pattern is invalid or a virtual target is relative.
pub fn validate_filesystem_policy(policy: &FilesystemPolicy) -> Result<()> {
    validate_patterns(policy.deny())?;
    validate_patterns(policy.writable())?;
    for path in policy.virtual_files().keys() {
        if !path.is_absolute() {
            return Err(Error::sandbox_misconfiguration(format!(
                "filesystem.virtual target {} must be absolute",
                path.display()
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_patterns(patterns: &[String]) -> Result<()> {
    let temp = std::env::temp_dir();
    let mut builder = GitignoreBuilder::new(&temp);
    for pattern in patterns {
        builder.add_line(None, pattern).map_err(|error| {
            Error::sandbox_misconfiguration(format!(
                "invalid filesystem pattern {pattern:?}: {error}"
            ))
        })?;
    }
    builder.build().map_err(|error| {
        Error::sandbox_misconfiguration(format!("invalid filesystem patterns: {error}"))
    })?;
    Ok(())
}

pub(crate) fn broadly_grants_cwd(patterns: &[String]) -> bool {
    patterns
        .iter()
        .map(String::as_str)
        .any(|pattern| matches!(pattern, "." | "./" | "*" | "**" | "**/*"))
}

fn protected_control_candidate_paths(cwd: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut paths = [".git", ".agents", ".pi", DENY_FRAGMENT, WRITE_FRAGMENT]
        .into_iter()
        .map(|name| cwd.join(name))
        .collect::<BTreeSet<_>>();
    if cwd.is_dir() {
        for entry in std::fs::read_dir(cwd).map_err(|error| {
            Error::sandbox_misconfiguration(format!("failed to read {}: {error}", cwd.display()))
        })? {
            let entry = entry.map_err(|error| {
                Error::sandbox_misconfiguration(format!(
                    "failed to read {}: {error}",
                    cwd.display()
                ))
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

    use super::*;

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
    fn deny_patterns_support_ordered_negation() {
        let cwd = unique_dir("deny-negation");
        std::fs::write(cwd.join(".env"), "secret").expect("file written");
        std::fs::write(cwd.join(".env.example"), "example").expect("file written");
        let policy = FilesystemPolicy::new(
            vec![".env*".to_string(), "!.env.example".to_string()],
            Vec::new(),
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(materialized.deny_targets.contains(&cwd.join(".env")));
        assert!(
            !materialized
                .deny_targets
                .contains(&cwd.join(".env.example"))
        );
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }

    #[test]
    fn fragments_are_appended_after_json_patterns() {
        let cwd = unique_dir("fragment-order");
        std::fs::write(cwd.join("secret.txt"), "secret").expect("file written");
        std::fs::write(cwd.join(DENY_FRAGMENT), "!secret.txt\n").expect("fragment written");
        let policy = FilesystemPolicy::new(
            vec!["secret.txt".to_string()],
            Vec::new(),
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(!materialized.deny_targets.contains(&cwd.join("secret.txt")));
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }

    #[test]
    fn broad_writable_grants_protect_control_paths() {
        let cwd = unique_dir("protected-existing");
        std::fs::create_dir(cwd.join(".git")).expect("control dir created");
        std::fs::write(cwd.join(".heimdall-local"), "control").expect("control file written");
        let policy = FilesystemPolicy::new(Vec::new(), vec![".".to_string()], Default::default());

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(materialized.protected_targets.contains(&cwd.join(".git")));
        assert!(
            materialized
                .protected_targets
                .contains(&cwd.join(".heimdall-local"))
        );
        assert!(
            materialized
                .protected_targets
                .contains(&cwd.join(DENY_FRAGMENT))
        );
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }

    #[test]
    fn deny_wins_over_writable() {
        let cwd = unique_dir("deny-wins");
        std::fs::write(cwd.join("data.txt"), "data").expect("file written");
        let policy = FilesystemPolicy::new(
            vec!["data.txt".to_string()],
            vec!["data.txt".to_string()],
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(materialized.deny_targets.contains(&cwd.join("data.txt")));
        assert!(
            !materialized
                .writable_targets
                .contains(&cwd.join("data.txt"))
        );
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }
}
