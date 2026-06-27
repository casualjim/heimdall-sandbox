//! Materializes cwd-relative gitignore-style filesystem policy into concrete paths.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use ignore::gitignore::{Gitignore, GitignoreBuilder};

use crate::filesystem::{FilesystemPolicy, MaterializedFilesystemPolicy, broadly_grants_cwd};
use crate::paths::{
    ConcretePathState, LiteralPathRule, concrete_path_state, contains_pattern_metacharacter,
    expand_home_pattern, has_denied_directory_ancestor, literal_path_decision,
    literal_path_is_selected, path_has_prefix, protected_control_candidate_paths,
};
use crate::{DENY_FRAGMENT, Error, Result, WRITE_FRAGMENT};

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
        let cwd_is_covered = broadly_grants_cwd(self.policy.writable())
            || self.cwd_covered_by_writable_ancestor()?;
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

        let deny_literal_patterns =
            self.patterns_with_readable_fragment(self.policy.deny(), DENY_FRAGMENT);
        let writable_literal_patterns =
            self.patterns_with_readable_fragment(self.policy.writable(), WRITE_FRAGMENT);
        let classified_deny = self.classified_selected_literal_paths(&deny_literal_patterns)?;
        let classified_writable =
            self.classified_selected_literal_paths(&writable_literal_patterns)?;

        // Add external absolute paths directly as targets.
        self.add_external_targets(&classified_deny, &mut deny_targets);
        self.add_external_targets(&classified_writable, &mut writable_targets);

        self.apply_literal_specificity(
            &mut deny_targets,
            &mut writable_targets,
            &deny_literal_patterns,
            &writable_literal_patterns,
        );
        let readable_targets = self.readable_targets(&deny_targets, &deny_literal_patterns)?;
        self.prune_redundant_deny_targets(&mut deny_targets);

        let protected_targets = self.protected_control_targets(&writable, &deny)?;

        let missing_deny_guards = self.missing_deny_guards(&classified_deny, &writable_targets);

        Ok(MaterializedFilesystemPolicy {
            deny_targets,
            writable_targets,
            protected_targets,
            readable_targets,
            missing_deny_guards,
        })
    }

    fn patterns_with_readable_fragment(&self, patterns: &[String], fragment: &str) -> Vec<String> {
        let mut result = patterns.to_vec();
        let fragment_path = self.cwd.join(fragment);
        if let Ok(contents) = std::fs::read_to_string(fragment_path) {
            result.extend(contents.lines().map(str::to_string));
        }
        result
    }

    /// Expand `~` in patterns and split into two groups:
    /// - CWD-relative patterns (including glob patterns like `*.txt`)
    /// - External absolute paths that exist on disk outside CWD
    ///
    /// External absolute paths are removed from the returned patterns and tracked
    /// separately so they can be added as direct targets without gitignore matching.
    fn expand_and_split(&self, patterns: &[String]) -> Vec<String> {
        let mut result = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            let expanded = expand_home_pattern(pattern);
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

    /// Add concrete literal absolute patterns directly as targets when the host entry exists.
    /// Missing ordinary host-backed paths are skipped here; missing deny paths that would be
    /// creatable through a writable directory are recorded later as missing deny guards.
    fn add_external_targets(
        &self,
        classified_paths: &[(PathBuf, ConcretePathState)],
        targets: &mut BTreeSet<PathBuf>,
    ) {
        for (path, state) in classified_paths {
            if state.is_existing() {
                targets.insert(path.clone());
            }
        }
    }

    fn missing_deny_guards(
        &self,
        classified_deny: &[(PathBuf, ConcretePathState)],
        writable_targets: &BTreeSet<PathBuf>,
    ) -> BTreeSet<PathBuf> {
        let writable_dirs = writable_targets
            .iter()
            .filter(|target| target.is_dir())
            .collect::<Vec<_>>();
        let mut guards = BTreeSet::new();
        for (path, state) in classified_deny {
            if state.is_missing()
                && writable_dirs
                    .iter()
                    .any(|writable| path_has_prefix(path, writable))
            {
                guards.insert(path.clone());
            }
        }
        guards
    }

    fn classified_selected_literal_paths(
        &self,
        patterns: &[String],
    ) -> Result<Vec<(PathBuf, ConcretePathState)>> {
        let rules = self.literal_path_rules(patterns);
        let mut paths = Vec::new();
        let mut seen = BTreeSet::new();
        for rule in rules.iter().filter(|rule| rule.selected) {
            if seen.insert(rule.path.clone()) && literal_path_is_selected(&rule.path, &rules) {
                let state = concrete_path_state(&rule.path)?;
                paths.push((rule.path.clone(), state));
            }
        }
        Ok(paths)
    }

    fn literal_path_rules(&self, patterns: &[String]) -> Vec<LiteralPathRule> {
        patterns
            .iter()
            .enumerate()
            .filter_map(|(order, pattern)| self.literal_path_rule(pattern, order))
            .collect()
    }

    fn literal_path_rule(&self, pattern: &str, order: usize) -> Option<LiteralPathRule> {
        let (selected, body) = match pattern.strip_prefix('!') {
            Some(body) => (false, body),
            None => (true, pattern),
        };
        if contains_pattern_metacharacter(body) {
            return None;
        }
        let path = PathBuf::from(shellexpand::tilde(body).into_owned());
        path.is_absolute().then_some(LiteralPathRule {
            path,
            selected,
            order,
        })
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
    fn cwd_covered_by_writable_ancestor(&self) -> Result<bool> {
        for pattern in self.policy.writable() {
            let expanded = expand_home_pattern(pattern);
            let path = Path::new(&expanded);
            if path.is_absolute()
                && self.cwd.starts_with(path)
                && concrete_path_state(path)?.is_existing()
                && path.is_dir()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn apply_literal_specificity(
        &self,
        deny_targets: &mut BTreeSet<PathBuf>,
        writable_targets: &mut BTreeSet<PathBuf>,
        deny_patterns: &[String],
        writable_patterns: &[String],
    ) {
        let deny_rules = self.literal_path_rules(deny_patterns);
        let writable_rules = self.literal_path_rules(writable_patterns);
        if deny_rules.is_empty() && writable_rules.is_empty() {
            return;
        }

        enum LiteralAccess {
            Deny,
            Writable,
            Neither,
        }

        let paths = deny_targets
            .union(writable_targets)
            .cloned()
            .collect::<Vec<_>>();
        for path in paths {
            let deny = literal_path_decision(&path, &deny_rules);
            let writable = literal_path_decision(&path, &writable_rules);
            let access = match (deny, writable) {
                (Some(deny), Some(writable)) => match (deny.selected, writable.selected) {
                    (true, true) if writable.specificity() > deny.specificity() => {
                        LiteralAccess::Writable
                    }
                    (true, _) => LiteralAccess::Deny,
                    (false, true) => LiteralAccess::Writable,
                    (false, false) => LiteralAccess::Neither,
                },
                (Some(deny), None) if deny.selected => LiteralAccess::Deny,
                (Some(_), None) => LiteralAccess::Neither,
                (None, Some(writable)) if writable.selected => LiteralAccess::Writable,
                (None, Some(_)) => LiteralAccess::Neither,
                (None, None) => continue,
            };

            match access {
                LiteralAccess::Deny => {
                    writable_targets.remove(&path);
                    deny_targets.insert(path);
                }
                LiteralAccess::Writable => {
                    deny_targets.remove(&path);
                    writable_targets.insert(path);
                }
                LiteralAccess::Neither => {
                    deny_targets.remove(&path);
                    writable_targets.remove(&path);
                }
            }
        }
    }

    fn readable_targets(
        &self,
        deny_targets: &BTreeSet<PathBuf>,
        deny_patterns: &[String],
    ) -> Result<BTreeSet<PathBuf>> {
        let mut targets = BTreeSet::new();
        for pattern in deny_patterns {
            let Some(restored) = pattern.strip_prefix('!') else {
                continue;
            };
            if contains_pattern_metacharacter(restored) {
                continue;
            }
            let Some(path) = self.literal_path(restored) else {
                continue;
            };
            if concrete_path_state(&path)?.is_existing()
                && has_denied_directory_ancestor(&path, deny_targets)
            {
                targets.insert(path);
            }
        }
        Ok(targets)
    }

    fn prune_redundant_deny_targets(&self, deny_targets: &mut BTreeSet<PathBuf>) {
        let original = deny_targets.clone();
        deny_targets.retain(|target| !has_denied_directory_ancestor(target, &original));
    }

    fn literal_path(&self, pattern: &str) -> Option<PathBuf> {
        let path = PathBuf::from(expand_home_pattern(pattern));
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
        if self.cwd_covered_by_writable_ancestor()? {
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{DENY_FRAGMENT, FilesystemPolicyMaterializer};
    use crate::Error;
    use crate::filesystem::FilesystemPolicy;
    use crate::paths::home_dir;

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
    fn later_absolute_deny_negation_removes_external_deny_target() {
        let cwd = unique_dir("external-deny-negation");
        let external = unique_dir("external-deny-negated-target");
        let policy = FilesystemPolicy::new(
            vec![
                external.to_string_lossy().to_string(),
                format!("!{}", external.display()),
            ],
            Vec::new(),
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(!materialized.deny_targets().contains(&external));
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
        std::fs::remove_dir_all(external).expect("external dir removed");
    }

    #[test]
    fn later_absolute_deny_negation_suppresses_missing_guard() {
        let cwd = unique_dir("missing-deny-negation");
        let writable = cwd.join("writable");
        std::fs::create_dir(&writable).expect("writable dir created");
        let missing = writable.join("missing-deny");
        let policy = FilesystemPolicy::new(
            vec![
                missing.to_string_lossy().to_string(),
                format!("!{}", missing.display()),
            ],
            vec![writable.to_string_lossy().to_string()],
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(!materialized.deny_targets().contains(&missing));
        assert!(!materialized.missing_deny_guards().contains(&missing));
        assert!(!missing.exists());
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }

    #[test]
    fn later_absolute_deny_negation_does_not_override_writable_target() {
        let cwd = unique_dir("deny-negation-writable");
        let external = unique_dir("deny-negation-writable-target");
        let policy = FilesystemPolicy::new(
            vec![
                external.to_string_lossy().to_string(),
                format!("!{}", external.display()),
            ],
            vec![external.to_string_lossy().to_string()],
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(!materialized.deny_targets().contains(&external));
        assert!(materialized.writable_targets().contains(&external));
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
        std::fs::remove_dir_all(external).expect("external dir removed");
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

    #[test]
    fn missing_literal_writable_and_readable_targets_are_skipped() {
        let cwd = unique_dir("missing-writable-readable");
        let missing_writable = cwd.join("missing-write");
        let missing_readable = cwd.join("missing-read");
        let policy = FilesystemPolicy::new(
            vec![format!("!{}", missing_readable.display())],
            vec![missing_writable.to_string_lossy().to_string()],
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(!materialized.writable_targets().contains(&missing_writable));
        assert!(!materialized.readable_targets().contains(&missing_readable));
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }

    #[cfg(unix)]
    #[test]
    fn indeterminate_restored_readonly_target_fails_materialization() {
        use std::os::unix::fs::symlink;

        let cwd = unique_dir("indeterminate-readable");
        let dangling = cwd.join("dangling-parent");
        symlink(cwd.join("absent"), &dangling).expect("dangling symlink created");
        let restored = dangling.join("child");
        let policy = FilesystemPolicy::new(
            vec![
                cwd.to_string_lossy().to_string(),
                format!("!{}", restored.display()),
            ],
            Vec::new(),
            Default::default(),
        );

        let result = FilesystemPolicyMaterializer::new(&cwd, &policy).materialize();

        assert!(matches!(result, Err(Error::IndeterminatePath { .. })));
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }

    #[test]
    fn missing_denies_are_skipped_unless_covered_by_existing_writable_directory() {
        let cwd = unique_dir("missing-deny-guards");
        let writable = cwd.join("writable");
        std::fs::create_dir(&writable).expect("writable dir created");
        let guarded = writable.join("missing");
        let skipped = cwd.join("outside-missing");
        let policy = FilesystemPolicy::new(
            vec![
                guarded.to_string_lossy().to_string(),
                skipped.to_string_lossy().to_string(),
            ],
            vec![writable.to_string_lossy().to_string()],
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(materialized.writable_targets().contains(&writable));
        assert!(!materialized.deny_targets().contains(&guarded));
        assert!(!materialized.deny_targets().contains(&skipped));
        assert!(materialized.missing_deny_guards().contains(&guarded));
        assert!(!materialized.missing_deny_guards().contains(&skipped));
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }

    #[test]
    fn literal_absolute_paths_under_cwd_are_concrete_before_pattern_matching() {
        let cwd = unique_dir("absolute-under-cwd");
        let missing = cwd.join("missing");
        let policy = FilesystemPolicy::new(
            vec![missing.to_string_lossy().to_string()],
            vec![".".to_string()],
            Default::default(),
        );

        let materialized = FilesystemPolicyMaterializer::new(&cwd, &policy)
            .materialize()
            .expect("policy materializes");

        assert!(materialized.writable_targets().contains(&cwd));
        assert!(materialized.missing_deny_guards().contains(&missing));
        assert!(!missing.exists());
        std::fs::remove_dir_all(cwd).expect("temp dir removed");
    }
}
