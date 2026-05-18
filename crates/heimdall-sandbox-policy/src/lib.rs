//! Shared sandbox policy types and filesystem policy materialization.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use ignore::WalkBuilder;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use thiserror::Error as ThisError;

/// Cwd-local deny fragment filename.
pub const DENY_FRAGMENT: &str = ".heimdall-deny";
/// Cwd-local writable fragment filename.
pub const WRITE_FRAGMENT: &str = ".heimdall-write";

/// Result type for sandbox policy operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by shared sandbox policy operations.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Filesystem pattern syntax is invalid.
    #[error("invalid filesystem pattern {pattern:?}: {source}")]
    InvalidPattern {
        /// Invalid pattern line.
        pattern: String,
        /// Underlying gitignore parser error.
        #[source]
        source: ignore::Error,
    },
    /// Filesystem fragment existence could not be checked.
    #[error("failed to inspect filesystem fragment {}: {source}", path.display())]
    FragmentStatus {
        /// Fragment path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Filesystem fragment could not be read or parsed.
    #[error("invalid filesystem fragment {}: {source}", path.display())]
    InvalidFragment {
        /// Fragment path.
        path: PathBuf,
        /// Underlying gitignore parser or I/O error.
        #[source]
        source: ignore::Error,
    },
    /// Filesystem matcher could not be built.
    #[error("invalid filesystem matcher for {fragment}: {source}")]
    InvalidMatcher {
        /// Fragment kind used for the matcher.
        fragment: String,
        /// Underlying gitignore matcher error.
        #[source]
        source: ignore::Error,
    },
    /// Policy cwd walk failed.
    #[error("failed to walk {}: {source}", cwd.display())]
    Walk {
        /// Policy cwd.
        cwd: PathBuf,
        /// Underlying walk error.
        #[source]
        source: ignore::Error,
    },
    /// Policy path could not be relativized against cwd.
    #[error("failed to relativize {} against {}: {source}", path.display(), cwd.display())]
    Relativize {
        /// Path being matched.
        path: PathBuf,
        /// Policy cwd.
        cwd: PathBuf,
        /// Underlying strip-prefix error.
        #[source]
        source: std::path::StripPrefixError,
    },
    /// Virtual file target is not absolute.
    #[error("filesystem.virtual target {} must be absolute", path.display())]
    RelativeVirtualTarget {
        /// Invalid virtual target.
        path: PathBuf,
    },
    /// Cwd directory could not be read while discovering protected paths.
    #[error("failed to read {}: {source}", cwd.display())]
    ReadDir {
        /// Policy cwd.
        cwd: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Cwd directory entry could not be read while discovering protected paths.
    #[error("failed to read entry in {}: {source}", cwd.display())]
    ReadEntry {
        /// Policy cwd.
        cwd: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Child network isolation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Preserve host networking.
    Host,
    /// Isolate host networking.
    None,
}

impl std::fmt::Display for NetworkMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Host => formatter.write_str("host"),
            Self::None => formatter.write_str("none"),
        }
    }
}

/// Child proc filesystem mount policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcMode {
    /// Mount `/proc` when host preflight allows it.
    Default,
    /// Do not mount `/proc` inside the sandbox.
    Disabled,
}

impl std::fmt::Display for ProcMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => formatter.write_str("default"),
            Self::Disabled => formatter.write_str("disabled"),
        }
    }
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

/// Concrete filesystem decisions materialized from cwd-relative policy patterns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedFilesystemPolicy {
    deny_targets: BTreeSet<PathBuf>,
    writable_targets: BTreeSet<PathBuf>,
    protected_targets: BTreeSet<PathBuf>,
    readable_targets: BTreeSet<PathBuf>,
}

impl MaterializedFilesystemPolicy {
    /// Create a materialized policy from the given target sets.
    ///
    /// Backend planners are responsible for ordering targets so the most specific path rule wins.
    #[must_use]
    pub fn new(
        deny_targets: BTreeSet<PathBuf>,
        writable_targets: BTreeSet<PathBuf>,
        protected_targets: BTreeSet<PathBuf>,
    ) -> Self {
        Self {
            deny_targets,
            writable_targets,
            protected_targets,
            readable_targets: BTreeSet::new(),
        }
    }

    /// Create an empty materialized policy with no targets.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            deny_targets: BTreeSet::new(),
            writable_targets: BTreeSet::new(),
            protected_targets: BTreeSet::new(),
            readable_targets: BTreeSet::new(),
        }
    }

    /// Existing paths selected by deny policy.
    #[must_use]
    pub fn deny_targets(&self) -> &BTreeSet<PathBuf> {
        &self.deny_targets
    }

    /// Existing paths selected by writable policy after deny precedence.
    #[must_use]
    pub fn writable_targets(&self) -> &BTreeSet<PathBuf> {
        &self.writable_targets
    }

    /// Protected control paths that must not become writable.
    #[must_use]
    pub fn protected_targets(&self) -> &BTreeSet<PathBuf> {
        &self.protected_targets
    }

    /// Existing paths explicitly restored by deny-policy negation rules.
    #[must_use]
    pub fn readable_targets(&self) -> &BTreeSet<PathBuf> {
        &self.readable_targets
    }

    /// Decompose into owned target sets.
    #[must_use]
    pub fn into_parts(self) -> (BTreeSet<PathBuf>, BTreeSet<PathBuf>, BTreeSet<PathBuf>) {
        (
            self.deny_targets,
            self.writable_targets,
            self.protected_targets,
        )
    }
}

/// Materializes cwd-relative gitignore-style filesystem policy into concrete paths.
pub struct FilesystemPolicyMaterializer<'a> {
    cwd: &'a Path,
    policy: &'a FilesystemPolicy,
}

impl<'a> FilesystemPolicyMaterializer<'a> {
    /// Create a filesystem policy materializer.
    #[must_use]
    pub const fn new(cwd: &'a Path, policy: &'a FilesystemPolicy) -> Self {
        Self { cwd, policy }
    }

    /// Materialize policy into concrete deny, writable, and protected targets.
    ///
    /// # Errors
    ///
    /// Returns a sandbox misconfiguration when policy patterns are invalid or cwd cannot be walked.
    pub fn materialize(self) -> Result<MaterializedFilesystemPolicy> {
        // Expand ~ in all patterns and split into CWD-relative (gitignore) vs
        // external-absolute (direct target) groups.
        let cwd_relative_deny = self.expand_and_split(self.policy.deny());
        let cwd_relative_writable = self.expand_and_split(self.policy.writable());

        let deny = self.build_matcher(&cwd_relative_deny, DENY_FRAGMENT)?;
        let writable = self.build_matcher(&cwd_relative_writable, WRITE_FRAGMENT)?;
        let paths = self.walk_existing()?;

        let mut deny_targets = BTreeSet::new();
        let mut writable_targets = BTreeSet::new();
        let cwd_is_covered =
            broadly_grants_cwd(self.policy.writable()) || self.cwd_covered_by_writable_ancestor();
        for path in &paths {
            let is_dir = path.is_dir();
            if self.selected(path, is_dir, &deny)? {
                deny_targets.insert(path.clone());
            } else if self.selected(path, is_dir, &writable)?
                || (path == self.cwd && cwd_is_covered)
            {
                writable_targets.insert(path.clone());
            }
        }

        // Add external absolute paths directly as targets.
        self.add_external_targets(self.policy.deny(), &mut deny_targets);
        self.add_external_targets(self.policy.writable(), &mut writable_targets);

        self.apply_literal_specificity(&mut deny_targets, &mut writable_targets);
        let readable_targets = self.readable_targets(&deny_targets);
        self.prune_redundant_deny_targets(&mut deny_targets);

        let protected_targets = self.protected_control_targets(&writable, &deny)?;

        Ok(MaterializedFilesystemPolicy {
            deny_targets,
            writable_targets,
            protected_targets,
            readable_targets,
        })
    }

    /// Expand `~` in patterns and split into two groups:
    /// - CWD-relative patterns (including glob patterns like `*.txt`)
    /// - External absolute paths that exist on disk outside CWD
    ///
    /// External absolute paths are removed from the returned patterns and tracked
    /// separately so they can be added as direct targets without gitignore matching.
    fn expand_and_split(&self, patterns: &[String]) -> Vec<String> {
        let home = home_dir();
        let mut result = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            let expanded = match &home {
                Some(h) => pattern.replace('~', &h.to_string_lossy()),
                None => pattern.clone(),
            };
            result.push(self.matcher_pattern(&expanded));
        }
        result
    }

    fn matcher_pattern(&self, pattern: &str) -> String {
        let Some(body) = pattern.strip_prefix('!') else {
            return self
                .cwd_relative_absolute_pattern(pattern)
                .unwrap_or_else(|| pattern.to_string());
        };
        self.cwd_relative_absolute_pattern(body)
            .map(|relative| format!("!{relative}"))
            .unwrap_or_else(|| pattern.to_string())
    }

    fn cwd_relative_absolute_pattern(&self, pattern: &str) -> Option<String> {
        let path = Path::new(pattern);
        if !path.is_absolute() || !path.starts_with(self.cwd) {
            return None;
        }
        let relative = path.strip_prefix(self.cwd).ok()?;
        if relative.as_os_str().is_empty() {
            return Some(".".to_string());
        }
        Some(relative.to_string_lossy().to_string())
    }

    /// Add external absolute patterns directly as targets.
    ///
    /// External paths are absolute paths that exist on disk and are not under CWD.
    /// They bypass gitignore matching entirely because the CWD walk cannot discover them.
    fn add_external_targets(&self, patterns: &[String], targets: &mut BTreeSet<PathBuf>) {
        let home = home_dir();
        for pattern in patterns {
            let expanded = match &home {
                Some(h) => pattern.replace('~', &h.to_string_lossy()),
                None => pattern.clone(),
            };
            let path = Path::new(&expanded);
            if path.is_absolute() && !path.starts_with(self.cwd) && path.exists() {
                targets.insert(path.to_path_buf());
            }
        }
    }

    fn build_matcher(&self, patterns: &[String], fragment: &str) -> Result<Gitignore> {
        let mut builder = GitignoreBuilder::new(self.cwd);
        for pattern in patterns {
            builder
                .add_line(None, pattern)
                .map_err(|source| Error::InvalidPattern {
                    pattern: pattern.clone(),
                    source,
                })?;
        }

        let fragment_path = self.cwd.join(fragment);
        if fragment_path
            .try_exists()
            .map_err(|source| Error::FragmentStatus {
                path: fragment_path.clone(),
                source,
            })?
            && let Some(source) = builder.add(&fragment_path)
        {
            return Err(Error::InvalidFragment {
                path: fragment_path,
                source,
            });
        }

        builder.build().map_err(|source| Error::InvalidMatcher {
            fragment: fragment.to_string(),
            source,
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
            let entry = entry.map_err(|source| Error::Walk {
                cwd: self.cwd.to_path_buf(),
                source,
            })?;
            paths.insert(entry.path().to_path_buf());
        }
        Ok(paths)
    }

    fn selected(&self, path: &Path, is_dir: bool, matcher: &Gitignore) -> Result<bool> {
        let relative = path
            .strip_prefix(self.cwd)
            .map_err(|source| Error::Relativize {
                path: path.to_path_buf(),
                cwd: self.cwd.to_path_buf(),
                source,
            })?;
        Ok(matcher.matched(relative, is_dir).is_ignore())
    }

    /// Returns true when any writable pattern resolves to an absolute path that is an
    /// ancestor of CWD, meaning CWD and its contents are implicitly writable.
    fn cwd_covered_by_writable_ancestor(&self) -> bool {
        let home = home_dir();
        self.policy.writable().iter().any(|pattern| {
            let expanded = match &home {
                Some(h) => pattern.replace('~', &h.to_string_lossy()),
                None => pattern.clone(),
            };
            let path = Path::new(&expanded);
            path.is_absolute() && path.is_dir() && self.cwd.starts_with(path)
        })
    }

    fn apply_literal_specificity(
        &self,
        deny_targets: &mut BTreeSet<PathBuf>,
        writable_targets: &mut BTreeSet<PathBuf>,
    ) {
        let rules = self.literal_rules();
        if rules.is_empty() {
            return;
        }

        let paths = deny_targets
            .union(writable_targets)
            .cloned()
            .collect::<Vec<_>>();
        for path in paths {
            let Some(rule) = rules
                .iter()
                .filter(|rule| rule.matches(&path))
                .max_by_key(|rule| (rule.specificity(), rule.kind.precedence()))
            else {
                continue;
            };

            match rule.kind {
                LiteralRuleKind::Deny => {
                    writable_targets.remove(&path);
                    deny_targets.insert(path);
                }
                LiteralRuleKind::Writable => {
                    deny_targets.remove(&path);
                    writable_targets.insert(path);
                }
            }
        }
    }

    fn literal_rules(&self) -> Vec<LiteralRule> {
        self.policy
            .deny()
            .iter()
            .filter_map(|pattern| self.literal_rule(pattern, LiteralRuleKind::Deny))
            .chain(
                self.policy
                    .writable()
                    .iter()
                    .filter_map(|pattern| self.literal_rule(pattern, LiteralRuleKind::Writable)),
            )
            .collect()
    }

    fn literal_rule(&self, pattern: &str, kind: LiteralRuleKind) -> Option<LiteralRule> {
        if is_non_literal_pattern(pattern) {
            return None;
        }
        self.literal_path(pattern)
            .map(|path| LiteralRule { path, kind })
    }

    fn readable_targets(&self, deny_targets: &BTreeSet<PathBuf>) -> BTreeSet<PathBuf> {
        self.policy
            .deny()
            .iter()
            .filter_map(|pattern| pattern.strip_prefix('!'))
            .filter(|pattern| !is_non_literal_pattern(pattern))
            .filter_map(|pattern| self.literal_path(pattern))
            .filter(|path| path.exists() && has_denied_directory_ancestor(path, deny_targets))
            .collect()
    }

    fn prune_redundant_deny_targets(&self, deny_targets: &mut BTreeSet<PathBuf>) {
        let original = deny_targets.clone();
        deny_targets.retain(|target| !has_denied_directory_ancestor(target, &original));
    }

    fn literal_path(&self, pattern: &str) -> Option<PathBuf> {
        let home = home_dir();
        let expanded = match &home {
            Some(h) => pattern.replace('~', &h.to_string_lossy()),
            None => pattern.to_string(),
        };
        let path = PathBuf::from(expanded);
        Some(if path.is_absolute() {
            path
        } else {
            self.cwd.join(path)
        })
    }

    fn protected_control_targets(
        &self,
        writable: &Gitignore,
        deny: &Gitignore,
    ) -> Result<BTreeSet<PathBuf>> {
        // When a writable ancestor covers CWD, the user trusts the entire tree.
        // Do not protect any control paths — they are explicitly writable.
        if self.cwd_covered_by_writable_ancestor() {
            return Ok(BTreeSet::new());
        }

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

/// Return the current user's home directory.
///
/// Uses the `dirs` crate for platform-correct resolution.
#[must_use]
pub fn home_dir() -> Option<PathBuf> {
    dirs::home_dir()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiteralRuleKind {
    Deny,
    Writable,
}

impl LiteralRuleKind {
    const fn precedence(self) -> u8 {
        match self {
            Self::Writable => 0,
            Self::Deny => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiteralRule {
    path: PathBuf,
    kind: LiteralRuleKind,
}

impl LiteralRule {
    fn matches(&self, path: &Path) -> bool {
        path == self.path || (self.path.is_dir() && path.starts_with(&self.path))
    }

    fn specificity(&self) -> usize {
        self.path
            .components()
            .filter(|component| !matches!(component, Component::RootDir | Component::Prefix(_)))
            .count()
    }
}

fn is_non_literal_pattern(pattern: &str) -> bool {
    pattern.starts_with('!')
        || pattern
            .chars()
            .any(|ch| matches!(ch, '*' | '?' | '[' | ']'))
}

fn has_denied_directory_ancestor(path: &Path, deny_targets: &BTreeSet<PathBuf>) -> bool {
    path.ancestors()
        .skip(1)
        .any(|ancestor| deny_targets.contains(ancestor) && ancestor.is_dir())
}

fn protected_control_candidate_paths(cwd: &Path) -> Result<BTreeSet<PathBuf>> {
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

        assert!(materialized.deny_targets().contains(&cwd.join(".env")));
        assert!(
            !materialized
                .deny_targets()
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

        assert!(
            !materialized
                .deny_targets()
                .contains(&cwd.join("secret.txt"))
        );
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }

    #[test]
    fn invalid_fragments_are_rejected() {
        let cwd = unique_dir("invalid-fragment");
        std::fs::create_dir(cwd.join(DENY_FRAGMENT)).expect("fragment directory created");
        let policy = FilesystemPolicy::default();

        let error = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect_err("invalid fragment is rejected");
        std::fs::remove_dir_all(cwd).expect("temp dir removed");

        assert!(matches!(error, Error::InvalidFragment { .. }));
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

        assert!(materialized.protected_targets().contains(&cwd.join(".git")));
        assert!(
            materialized
                .protected_targets()
                .contains(&cwd.join(".heimdall-local"))
        );
        assert!(
            materialized
                .protected_targets()
                .contains(&cwd.join(DENY_FRAGMENT))
        );
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }

    #[test]
    fn writable_ancestor_makes_cwd_and_control_paths_writable() {
        // Create a structure: parent/cwd/.git where parent is the writable ancestor.
        let parent = unique_dir("writable-ancestor");
        let cwd = parent.join("sub");
        std::fs::create_dir(&cwd).expect("sub dir created");
        std::fs::create_dir(cwd.join(".git")).expect("control dir created");
        std::fs::write(cwd.join(".heimdall-local"), "control").expect("control file written");

        let policy = FilesystemPolicy::new(
            Vec::new(),
            vec![parent.to_string_lossy().to_string()],
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        // CWD must be in writable_targets (covered by ancestor).
        assert!(materialized.writable_targets().contains(&cwd));
        // Control paths must NOT be protected when CWD is covered by a writable ancestor.
        assert!(!materialized.protected_targets().contains(&cwd.join(".git")));
        assert!(
            !materialized
                .protected_targets()
                .contains(&cwd.join(".heimdall-local"))
        );
        std::fs::remove_dir_all(parent).expect("temp dir removed");
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

        assert!(materialized.deny_targets().contains(&cwd.join("data.txt")));
        assert!(
            !materialized
                .writable_targets()
                .contains(&cwd.join("data.txt"))
        );
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }

    #[test]
    fn external_absolute_writable_paths_are_added_directly() {
        let cwd = unique_dir("external-writable");
        // Create an external dir that exists outside CWD.
        let external = std::env::temp_dir().join("heimdall-external-writable-target");
        std::fs::create_dir_all(&external).expect("external dir created");

        let policy = FilesystemPolicy::new(
            Vec::new(),
            vec![external.to_string_lossy().to_string()],
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(
            materialized.writable_targets().contains(&external),
            "external absolute writable path should be added as a writable target"
        );
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
        std::fs::remove_dir_all(&external).expect("external dir removed");
    }

    #[test]
    fn external_absolute_deny_paths_are_added_directly() {
        let cwd = unique_dir("external-deny");
        // Create an external dir that exists outside CWD.
        let external = std::env::temp_dir().join("heimdall-external-deny-target");
        std::fs::create_dir_all(&external).expect("external dir created");

        let policy = FilesystemPolicy::new(
            vec![external.to_string_lossy().to_string()],
            Vec::new(),
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(
            materialized.deny_targets().contains(&external),
            "external absolute deny path should be added as a deny target"
        );
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
        std::fs::remove_dir_all(&external).expect("external dir removed");
    }

    #[test]
    fn longer_writable_path_wins_over_denied_parent() {
        let cwd = unique_dir("writable-wins-external");
        let external = std::env::temp_dir().join("heimdall-external-writable-wins-parent");
        let writable = external.join("writable");
        std::fs::create_dir_all(&writable).expect("external dirs created");

        let policy = FilesystemPolicy::new(
            vec![external.to_string_lossy().to_string()],
            vec![writable.to_string_lossy().to_string()],
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(materialized.deny_targets().contains(&external));
        assert!(materialized.writable_targets().contains(&writable));
        assert!(!materialized.deny_targets().contains(&writable));
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
        std::fs::remove_dir_all(&external).expect("external dir removed");
    }

    #[test]
    fn longer_deny_path_wins_over_writable_parent() {
        let cwd = unique_dir("deny-wins-external");
        let external = std::env::temp_dir().join("heimdall-external-deny-wins-parent");
        let secret = external.join("secret");
        std::fs::create_dir_all(&secret).expect("external dirs created");

        let policy = FilesystemPolicy::new(
            vec![secret.to_string_lossy().to_string()],
            vec![external.to_string_lossy().to_string()],
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(materialized.deny_targets().contains(&secret));
        assert!(materialized.writable_targets().contains(&external));
        assert!(!materialized.writable_targets().contains(&secret));
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
        std::fs::remove_dir_all(&external).expect("external dir removed");
    }

    #[test]
    fn tilde_patterns_expand_to_home_dir() {
        let cwd = unique_dir("tilde-expand");
        let home = home_dir().expect("home dir exists");
        // Use ~/something as a writable pattern.
        // We test against a real directory under home.
        let target = home.join(".config");
        if !target.is_dir() {
            // Skip if ~/.config doesn't exist on this system.
            std::fs::remove_dir_all(cwd).expect("temp dir removed");
            return;
        }

        let policy = FilesystemPolicy::new(
            Vec::new(),
            vec!["~/.config".to_string()],
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(
            materialized.writable_targets().contains(&target),
            "~/.config should expand and be added as a writable target"
        );
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }
}
