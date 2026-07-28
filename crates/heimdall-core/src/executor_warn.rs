//! Platform-runtime warnings for microvm-only controls that cannot be honored.

use crate::request::ExecRequest;

/// Warn on stderr about microvm-only controls that the platform runtime ignores.
///
/// The platform backends (bubblewrap, seatbelt) cannot honor resource limits,
/// lifecycle timeouts, guest identity, secrets, or the security profile. Emit
/// one warning per configured knob so a policy written for the microvm runtime
/// is not silently downgraded when run on platform.
pub(crate) fn warn_ignored_microvm_controls(request: &ExecRequest) {
    if let Some(image) = request.microvm_image() {
        warn_ignored("image", image);
    }
    let policy = request.microvm_policy();
    if policy.is_empty() {
        return;
    }
    let resources = policy.resources();
    if let Some(cpus) = resources.cpus() {
        warn_ignored("microvm.resources.cpus", &cpus.to_string());
    }
    if let Some(memory) = resources.memory_mib() {
        warn_ignored("microvm.resources.memory", &memory.to_string());
    }
    if let Some(upper) = resources.upper_size_mib() {
        warn_ignored("microvm.resources.upper_size", &upper.to_string());
    }
    if !resources.rlimits().is_empty() {
        warn_ignored(
            "microvm.resources.rlimits",
            &resources.rlimits().len().to_string(),
        );
    }
    let lifecycle = policy.lifecycle();
    if let Some(secs) = lifecycle.max_duration_secs() {
        warn_ignored("microvm.lifecycle.max_duration", &secs.to_string());
    }
    if let Some(secs) = lifecycle.idle_timeout_secs() {
        warn_ignored("microvm.lifecycle.idle_timeout", &secs.to_string());
    }
    let guest = policy.guest();
    if let Some(user) = guest.user() {
        warn_ignored("microvm.guest.user", user);
    }
    if guest.entrypoint().is_some() {
        warn_ignored("microvm.guest.entrypoint", "set");
    }
    if !policy.secrets().is_empty() {
        warn_ignored("microvm.secrets", &policy.secrets().len().to_string());
    }
    if policy.security_profile().is_some() {
        warn_ignored("microvm.security", "set");
    }
}

fn warn_ignored(path: &str, value: &str) {
    eprintln!("heimdall: warning: {path} ({value}) ignored on platform runtime");
}
