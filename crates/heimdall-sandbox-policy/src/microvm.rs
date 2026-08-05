//! MicroVM-only sandbox policy: resource limits, lifecycle, guest identity,
//! secrets, and security profile knobs that only apply when the microvm
//! runtime is selected. Neutral runtime-agnostic value types; backends
//! translate these to their own SDK types.
//!
//! The surface is shrunk to boxlite-native knobs only. Dropped fields
//! (`image.snapshot`, `image.pullPolicy`, rlimits beyond the boxlite 5,
//! `guest.hostname`/`shell`/`init`, `SecretHostPattern::Any`) are rejected at
//! the JSON/schema layer — they have no boxlite equivalent and are not
//! expressible here (V39).

/// MicroVM-only sandbox policy.
///
/// Applies only when the effective runtime is `microvm`. When the platform
/// runtime is selected, a non-empty microvm policy is a configuration error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MicrovmPolicy {
    resources: MicrovmResources,
    lifecycle: MicrovmLifecycle,
    guest: MicrovmGuest,
    secrets: Vec<MicrovmSecret>,
    security_profile: Option<SecurityProfile>,
}

impl MicrovmPolicy {
    /// Create a microvm policy from its constituent parts.
    #[must_use]
    pub fn new(
        resources: MicrovmResources,
        lifecycle: MicrovmLifecycle,
        guest: MicrovmGuest,
        secrets: Vec<MicrovmSecret>,
        security_profile: Option<SecurityProfile>,
    ) -> Self {
        Self {
            resources,
            lifecycle,
            guest,
            secrets,
            security_profile,
        }
    }

    /// Return true when no microvm controls are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
            && self.lifecycle.is_empty()
            && self.guest.is_empty()
            && self.secrets.is_empty()
            && self.security_profile.is_none()
    }

    /// Resource limits applied to the guest.
    #[must_use]
    pub fn resources(&self) -> &MicrovmResources {
        &self.resources
    }

    /// Lifecycle timeouts applied to the sandbox.
    #[must_use]
    pub fn lifecycle(&self) -> &MicrovmLifecycle {
        &self.lifecycle
    }

    /// Guest identity and boot configuration.
    #[must_use]
    pub fn guest(&self) -> &MicrovmGuest {
        &self.guest
    }

    /// Secrets injected via the TLS proxy with host-allowlist gating.
    #[must_use]
    pub fn secrets(&self) -> &[MicrovmSecret] {
        &self.secrets
    }

    /// In-guest security profile.
    #[must_use]
    pub const fn security_profile(&self) -> Option<SecurityProfile> {
        self.security_profile
    }
}

/// Resource limits applied to the microvm guest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MicrovmResources {
    cpus: Option<u8>,
    memory_mib: Option<u32>,
    upper_size_mib: Option<u32>,
    rlimits: Vec<RlimitSpec>,
}

impl MicrovmResources {
    /// Create resource limits from the given knobs.
    #[must_use]
    pub fn new(
        cpus: Option<u8>,
        memory_mib: Option<u32>,
        upper_size_mib: Option<u32>,
        rlimits: Vec<RlimitSpec>,
    ) -> Self {
        Self {
            cpus,
            memory_mib,
            upper_size_mib,
            rlimits,
        }
    }

    /// Return true when no resource knobs are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cpus.is_none()
            && self.memory_mib.is_none()
            && self.upper_size_mib.is_none()
            && self.rlimits.is_empty()
    }

    /// Virtual CPU count.
    #[must_use]
    pub const fn cpus(&self) -> Option<u8> {
        self.cpus
    }

    /// Guest memory size in mebibytes.
    #[must_use]
    pub const fn memory_mib(&self) -> Option<u32> {
        self.memory_mib
    }

    /// Writable overlay upper size in mebibytes (OCI images only).
    #[must_use]
    pub const fn upper_size_mib(&self) -> Option<u32> {
        self.upper_size_mib
    }

    /// POSIX resource limits inherited by guest processes.
    #[must_use]
    pub fn rlimits(&self) -> &[RlimitSpec] {
        &self.rlimits
    }
}

/// Lifecycle timeouts applied to the sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MicrovmLifecycle {
    max_duration_secs: Option<u64>,
    idle_timeout_secs: Option<u64>,
}

impl MicrovmLifecycle {
    /// Create lifecycle timeouts from the given knobs.
    #[must_use]
    pub fn new(max_duration_secs: Option<u64>, idle_timeout_secs: Option<u64>) -> Self {
        Self {
            max_duration_secs,
            idle_timeout_secs,
        }
    }

    /// Return true when no lifecycle knobs are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.max_duration_secs.is_none() && self.idle_timeout_secs.is_none()
    }

    /// Maximum sandbox lifetime in seconds.
    #[must_use]
    pub const fn max_duration_secs(&self) -> Option<u64> {
        self.max_duration_secs
    }

    /// Auto-stop the sandbox after this many seconds of inactivity.
    #[must_use]
    pub const fn idle_timeout_secs(&self) -> Option<u64> {
        self.idle_timeout_secs
    }
}

/// Guest identity and boot configuration.
///
/// Shrunk to boxlite-native knobs: `user` and `entrypoint` only. The
/// `hostname`, `shell`, and `init` knobs have no boxlite equivalent and are
/// rejected at the JSON/schema layer (V39).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MicrovmGuest {
    user: Option<String>,
    entrypoint: Option<Vec<String>>,
}

impl MicrovmGuest {
    /// Create guest configuration from a user and optional entrypoint override.
    #[must_use]
    pub fn new(user: Option<String>, entrypoint: Option<Vec<String>>) -> Self {
        Self { user, entrypoint }
    }

    /// Return true when no guest knobs are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.user.is_none() && self.entrypoint.is_none()
    }

    /// Guest user identity (e.g., `"1000"`, `"appuser"`, `"1000:1000"`).
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// OCI image entrypoint override.
    #[must_use]
    pub fn entrypoint(&self) -> Option<&[String]> {
        self.entrypoint.as_deref()
    }
}

/// A secret injected via the boxlite MITM proxy with host-allowlist gating.
///
/// Maps 1:1 to `boxlite::runtime::options::Secret{name, hosts, placeholder,
/// value}` (V44). The guest sees `BOXLITE_SECRET_<NAME>=<placeholder>`; the
/// real `value` never enters the VM and is substituted only for traffic to
/// matching `hosts` (R5). `SecretHostPattern::Any` is rejected at the schema
/// layer (V44).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicrovmSecret {
    name: String,
    placeholder: String,
    value: String,
    hosts: Vec<SecretHostPattern>,
}

impl MicrovmSecret {
    /// Create a secret from a name, placeholder, value, and allowed-host patterns.
    #[must_use]
    pub fn new(
        name: String,
        placeholder: String,
        value: String,
        hosts: Vec<SecretHostPattern>,
    ) -> Self {
        Self {
            name,
            placeholder,
            value,
            hosts,
        }
    }

    /// Human-readable secret name; boxlite derives the guest env var key
    /// (`BOXLITE_SECRET_<NAME>`) from it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Placeholder string visible to the guest; substituted with `value` on
    /// egress to matching `hosts`.
    #[must_use]
    pub fn placeholder(&self) -> &str {
        &self.placeholder
    }

    /// The actual secret value (never enters the sandbox unguarded).
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Hosts allowed to receive this secret (exact or wildcard).
    #[must_use]
    pub fn hosts(&self) -> &[SecretHostPattern] {
        &self.hosts
    }
}

/// Host pattern for secret allowlisting.
///
/// `Any` is dropped: a secret allowlisting every host can be exfiltrated and
/// has no boxlite equivalent (V39). Only `Exact` and `Wildcard` are accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretHostPattern {
    /// Exact hostname match.
    Exact(String),
    /// Wildcard match (e.g., `*.openai.com`).
    Wildcard(String),
}

/// In-guest security profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// Preserve normal guest-root semantics.
    Default,
    /// Harden guest exec sessions (`no_new_privs`, drop `CAP_SYS_ADMIN`).
    Restricted,
}

/// POSIX resource limit identifier.
///
/// Shrunk to the boxlite-native 5 (`max_open_files`, `max_file_size`,
/// `max_processes`, `max_memory`, `max_cpu_time`). The other 11 rlimits have
/// no boxlite knob and are rejected at the JSON/schema layer (V39).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlimitResource {
    /// Max CPU time in seconds (`RLIMIT_CPU`).
    Cpu,
    /// Max file size in bytes (`RLIMIT_FSIZE`).
    Fsize,
    /// Max number of processes (`RLIMIT_NPROC`).
    Nproc,
    /// Max open file descriptors (`RLIMIT_NOFILE`).
    Nofile,
    /// Max address space size (`RLIMIT_AS`).
    As,
}

/// A POSIX resource limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RlimitSpec {
    resource: RlimitResource,
    soft: u64,
    hard: u64,
}

impl RlimitSpec {
    /// Create a resource limit from a resource type, soft limit, and hard limit.
    #[must_use]
    pub const fn new(resource: RlimitResource, soft: u64, hard: u64) -> Self {
        Self {
            resource,
            soft,
            hard,
        }
    }

    /// Resource type.
    #[must_use]
    pub const fn resource(&self) -> RlimitResource {
        self.resource
    }

    /// Soft limit (can be raised up to the hard limit by the process).
    #[must_use]
    pub const fn soft(&self) -> u64 {
        self.soft
    }

    /// Hard limit (ceiling, requires privileges to raise).
    #[must_use]
    pub const fn hard(&self) -> u64 {
        self.hard
    }
}

/// Validate a microvm policy's internal consistency and bounds.
///
/// # Errors
///
/// Returns a sandbox misconfiguration when any knob is out of bounds or
/// a secret is missing required fields.
pub fn validate_microvm_policy(policy: &MicrovmPolicy) -> crate::Result<()> {
    let MicrovmResources {
        cpus,
        memory_mib,
        upper_size_mib,
        rlimits,
    } = policy.resources();
    if let Some(cpus) = cpus
        && *cpus == 0
    {
        return Err(crate::Error::InvalidMicrovmPolicy(
            "resources.cpus must be at least 1".to_string(),
        ));
    }
    if let Some(memory) = memory_mib
        && *memory == 0
    {
        return Err(crate::Error::InvalidMicrovmPolicy(
            "resources.memory must be at least 1 MiB".to_string(),
        ));
    }
    if let Some(upper) = upper_size_mib
        && *upper == 0
    {
        return Err(crate::Error::InvalidMicrovmPolicy(
            "resources.upperSize must be at least 1 MiB".to_string(),
        ));
    }
    for spec in rlimits {
        if spec.soft() > spec.hard() {
            return Err(crate::Error::InvalidMicrovmPolicy(format!(
                "resources.rlimits {:?} soft {} exceeds hard {}",
                spec.resource(),
                spec.soft(),
                spec.hard()
            )));
        }
    }

    let MicrovmLifecycle {
        max_duration_secs,
        idle_timeout_secs,
    } = policy.lifecycle();
    if let Some(secs) = max_duration_secs
        && *secs == 0
    {
        return Err(crate::Error::InvalidMicrovmPolicy(
            "lifecycle.maxDuration must be at least 1 second".to_string(),
        ));
    }
    if let Some(secs) = idle_timeout_secs
        && *secs == 0
    {
        return Err(crate::Error::InvalidMicrovmPolicy(
            "lifecycle.idleTimeout must be at least 1 second".to_string(),
        ));
    }

    for (index, secret) in policy.secrets().iter().enumerate() {
        if secret.name().is_empty() {
            return Err(crate::Error::InvalidMicrovmPolicy(format!(
                "secrets[{index}].name must be non-empty"
            )));
        }
        if secret.name().contains('\0') {
            return Err(crate::Error::InvalidMicrovmPolicy(format!(
                "secrets[{index}].name must not contain NUL"
            )));
        }
        if secret.placeholder().is_empty() {
            return Err(crate::Error::InvalidMicrovmPolicy(format!(
                "secrets[{index}].placeholder must be non-empty"
            )));
        }
        if secret.placeholder().contains('\0') {
            return Err(crate::Error::InvalidMicrovmPolicy(format!(
                "secrets[{index}].placeholder must not contain NUL"
            )));
        }
        if secret.value().is_empty() {
            return Err(crate::Error::InvalidMicrovmPolicy(format!(
                "secrets[{index}].value must be non-empty"
            )));
        }
        if secret.hosts().is_empty() {
            return Err(crate::Error::InvalidMicrovmPolicy(format!(
                "secrets[{index}].hosts must be non-empty"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with_resources(resources: MicrovmResources) -> MicrovmPolicy {
        MicrovmPolicy::new(
            resources,
            MicrovmLifecycle::default(),
            MicrovmGuest::default(),
            Vec::new(),
            None,
        )
    }

    #[test]
    fn empty_policy_is_empty() {
        assert!(MicrovmPolicy::default().is_empty());
    }

    #[test]
    fn validates_zero_cpus() {
        let policy = policy_with_resources(MicrovmResources::new(Some(0), None, None, Vec::new()));

        let error = validate_microvm_policy(&policy).expect_err("zero cpus rejects");

        assert!(error.to_string().contains("cpus"));
    }

    #[test]
    fn validates_zero_memory() {
        let policy = policy_with_resources(MicrovmResources::new(None, Some(0), None, Vec::new()));

        let error = validate_microvm_policy(&policy).expect_err("zero memory rejects");

        assert!(error.to_string().contains("memory"));
    }

    #[test]
    fn validates_rlimit_soft_exceeds_hard() {
        let spec = RlimitSpec::new(RlimitResource::Nofile, 200, 100);
        let policy = policy_with_resources(MicrovmResources::new(None, None, None, vec![spec]));

        let error = validate_microvm_policy(&policy).expect_err("soft>hard rejects");

        assert!(error.to_string().contains("Nofile"));
    }

    #[test]
    fn validates_zero_max_duration() {
        let policy = MicrovmPolicy::new(
            MicrovmResources::default(),
            MicrovmLifecycle::new(Some(0), None),
            MicrovmGuest::default(),
            Vec::new(),
            None,
        );

        let error = validate_microvm_policy(&policy).expect_err("zero maxDuration rejects");

        assert!(error.to_string().contains("maxDuration"));
    }

    #[test]
    fn validates_secret_missing_hosts() {
        let secret = MicrovmSecret::new(
            "API_KEY".to_string(),
            "<PLACEHOLDER>".to_string(),
            "sk-...".to_string(),
            Vec::new(),
        );
        let policy = MicrovmPolicy::new(
            MicrovmResources::default(),
            MicrovmLifecycle::default(),
            MicrovmGuest::default(),
            vec![secret],
            None,
        );

        let error = validate_microvm_policy(&policy).expect_err("missing hosts rejects");

        assert!(error.to_string().contains("hosts"));
    }

    #[test]
    fn validates_secret_name_with_nul() {
        let secret = MicrovmSecret::new(
            "API\0KEY".to_string(),
            "<PLACEHOLDER>".to_string(),
            "sk-...".to_string(),
            vec![SecretHostPattern::Exact("api.openai.com".to_string())],
        );
        let policy = MicrovmPolicy::new(
            MicrovmResources::default(),
            MicrovmLifecycle::default(),
            MicrovmGuest::default(),
            vec![secret],
            None,
        );

        let error = validate_microvm_policy(&policy).expect_err("name with NUL rejects");

        assert!(error.to_string().contains("name"));
    }

    #[test]
    fn validates_secret_empty_placeholder() {
        let secret = MicrovmSecret::new(
            "API_KEY".to_string(),
            String::new(),
            "sk-...".to_string(),
            vec![SecretHostPattern::Exact("api.openai.com".to_string())],
        );
        let policy = MicrovmPolicy::new(
            MicrovmResources::default(),
            MicrovmLifecycle::default(),
            MicrovmGuest::default(),
            vec![secret],
            None,
        );

        let error = validate_microvm_policy(&policy).expect_err("empty placeholder rejects");

        assert!(error.to_string().contains("placeholder"));
    }

    #[test]
    fn accepts_well_formed_policy() {
        let secret = MicrovmSecret::new(
            "openai_api_key".to_string(),
            "<BOXLITE_SECRET:openai>".to_string(),
            "sk-...".to_string(),
            vec![
                SecretHostPattern::Exact("api.openai.com".to_string()),
                SecretHostPattern::Wildcard("*.openai.com".to_string()),
            ],
        );
        let policy = MicrovmPolicy::new(
            MicrovmResources::new(Some(2), Some(512), Some(256), Vec::new()),
            MicrovmLifecycle::new(Some(3600), None),
            MicrovmGuest::new(Some("appuser".to_string()), None),
            vec![secret],
            Some(SecurityProfile::Restricted),
        );

        validate_microvm_policy(&policy).expect("well-formed policy validates");
        assert!(!policy.is_empty());
    }
}
