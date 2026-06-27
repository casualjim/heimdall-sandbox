//! Shared sandbox policy types and filesystem policy materialization.

mod filesystem;
mod materializer;
mod paths;
mod runtime;

use std::path::PathBuf;

use thiserror::Error as ThisError;

/// Cwd-local deny fragment filename.
pub const DENY_FRAGMENT: &str = ".heimdall-deny";
/// Cwd-local writable fragment filename.
pub const WRITE_FRAGMENT: &str = ".heimdall-write";

/// Result type for sandbox policy operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by shared sandbox policy operations
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
    /// Concrete path existence could not be determined safely.
    #[error("failed to determine whether {} exists: {source}", path.display())]
    IndeterminatePath {
        /// Path being classified.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

pub use filesystem::{
    FilesystemPolicy, MaterializedFilesystemPolicy, broadly_grants_cwd, validate_filesystem_policy,
    validate_patterns,
};
pub use materializer::FilesystemPolicyMaterializer;
pub use paths::{ConcretePathState, concrete_path_state, home_dir};
pub use runtime::{AgentPolicy, NetworkMode, ProcMode};
