//! Process hardening helpers shared by Heimdall sandbox runtime crates.

mod environment;
mod hardening;
#[cfg(target_os = "linux")]
mod parent;

pub use environment::is_dangerous_environment_key;
pub use hardening::{apply_child_hardening, apply_process_hardening};
#[cfg(target_os = "linux")]
pub use parent::terminate_with_parent;
