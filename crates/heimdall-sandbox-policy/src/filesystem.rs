//! Filesystem sandbox policy types, validation, and materialized decisions.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ignore::gitignore::GitignoreBuilder;

use crate::{Error, Result};

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

/// Concrete filesystem decisions materialized from cwd-relative policy patterns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedFilesystemPolicy {
    pub(crate) deny_targets: std::collections::BTreeSet<PathBuf>,
    pub(crate) writable_targets: std::collections::BTreeSet<PathBuf>,
    pub(crate) protected_targets: std::collections::BTreeSet<PathBuf>,
    pub(crate) readable_targets: std::collections::BTreeSet<PathBuf>,
    pub(crate) missing_deny_guards: std::collections::BTreeSet<PathBuf>,
}

impl MaterializedFilesystemPolicy {
    /// Create a materialized policy from the given target sets.
    ///
    /// Backend planners are responsible for ordering targets so the most specific path rule wins.
    #[must_use]
    pub fn new(
        deny_targets: std::collections::BTreeSet<PathBuf>,
        writable_targets: std::collections::BTreeSet<PathBuf>,
        protected_targets: std::collections::BTreeSet<PathBuf>,
    ) -> Self {
        Self {
            deny_targets,
            writable_targets,
            protected_targets,
            readable_targets: std::collections::BTreeSet::new(),
            missing_deny_guards: std::collections::BTreeSet::new(),
        }
    }

    /// Create an empty materialized policy with no targets.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            deny_targets: std::collections::BTreeSet::new(),
            writable_targets: std::collections::BTreeSet::new(),
            protected_targets: std::collections::BTreeSet::new(),
            readable_targets: std::collections::BTreeSet::new(),
            missing_deny_guards: std::collections::BTreeSet::new(),
        }
    }

    /// Existing paths selected by deny policy.
    #[must_use]
    pub fn deny_targets(&self) -> &std::collections::BTreeSet<PathBuf> {
        &self.deny_targets
    }

    /// Existing paths selected by writable policy after deny precedence.
    #[must_use]
    pub fn writable_targets(&self) -> &std::collections::BTreeSet<PathBuf> {
        &self.writable_targets
    }

    /// Protected control paths that must not become writable.
    #[must_use]
    pub fn protected_targets(&self) -> &std::collections::BTreeSet<PathBuf> {
        &self.protected_targets
    }

    /// Existing paths explicitly restored by deny-policy negation rules.
    #[must_use]
    pub fn readable_targets(&self) -> &std::collections::BTreeSet<PathBuf> {
        &self.readable_targets
    }

    /// Confirmed-missing denied paths that remain creatable through writable directory targets.
    #[must_use]
    pub fn missing_deny_guards(&self) -> &std::collections::BTreeSet<PathBuf> {
        &self.missing_deny_guards
    }

    /// Decompose into owned target sets.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        std::collections::BTreeSet<PathBuf>,
        std::collections::BTreeSet<PathBuf>,
        std::collections::BTreeSet<PathBuf>,
    ) {
        (
            self.deny_targets,
            self.writable_targets,
            self.protected_targets,
        )
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
            return Err(Error::RelativeVirtualTarget {
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}

/// Validate gitignore-style filesystem pattern syntax.
///
/// # Errors
///
/// Returns a sandbox misconfiguration when any pattern is invalid.
pub fn validate_patterns(patterns: &[String]) -> Result<()> {
    let temp = std::env::temp_dir();
    let mut builder = GitignoreBuilder::new(&temp);
    for pattern in patterns {
        builder
            .add_line(None, pattern)
            .map_err(|source| Error::InvalidPattern {
                pattern: pattern.clone(),
                source,
            })?;
    }
    builder.build().map_err(|source| Error::InvalidMatcher {
        fragment: "inline patterns".to_string(),
        source,
    })?;
    Ok(())
}

/// Return whether pattern lines broadly grant the policy cwd.
#[must_use]
pub fn broadly_grants_cwd(patterns: &[String]) -> bool {
    patterns
        .iter()
        .map(String::as_str)
        .any(|pattern| matches!(pattern, "." | "./" | "*" | "**" | "**/*"))
}
