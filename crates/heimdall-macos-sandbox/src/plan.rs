//! Prepared Seatbelt invocation and rendered policy container.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Prepared Seatbelt invocation.
pub struct SeatbeltPlan {
    pub(crate) seatbelt: PathBuf,
    pub(crate) args: Vec<String>,
}

impl SeatbeltPlan {
    /// Convert this prepared Seatbelt invocation into a command.
    #[must_use]
    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.seatbelt);
        command.args(&self.args);
        command
    }

    /// Seatbelt executable path.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.seatbelt
    }

    /// Seatbelt command arguments.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }
}

/// Rendered Seatbelt policy text and the ordered `-D` parameters it references.
pub(crate) struct SeatbeltPolicy {
    pub(crate) text: String,
    pub(crate) params: Vec<(String, PathBuf)>,
}
