//! MicroVM-only sandbox policy: resource limits, lifecycle, guest identity,
//! secrets, and image integrity knobs that only apply when the microvm runtime
//! is selected. Neutral runtime-agnostic value types; backends translate these
//! to their own SDK types.

/// Maximum guest hostname length in bytes (Linux UTS limit).
pub const MAX_HOSTNAME_BYTES: usize = 64;

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
    image: MicrovmImage,
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
        image: MicrovmImage,
        security_profile: Option<SecurityProfile>,
    ) -> Self {
        Self {
            resources,
            lifecycle,
            guest,
            secrets,
            image,
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
            && self.image.is_empty()
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

    /// Image pull and snapshot pinning policy.
    #[must_use]
    pub fn image(&self) -> &MicrovmImage {
        &self.image
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MicrovmGuest {
    user: Option<String>,
    hostname: Option<String>,
    shell: Option<String>,
    entrypoint: Option<Vec<String>>,
    init: Option<MicrovmInit>,
}

impl MicrovmGuest {
    /// Create guest configuration from the given knobs.
    #[must_use]
    pub fn new(
        user: Option<String>,
        hostname: Option<String>,
        shell: Option<String>,
        entrypoint: Option<Vec<String>>,
        init: Option<MicrovmInit>,
    ) -> Self {
        Self {
            user,
            hostname,
            shell,
            entrypoint,
            init,
        }
    }

    /// Return true when no guest knobs are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.user.is_none()
            && self.hostname.is_none()
            && self.shell.is_none()
            && self.entrypoint.is_none()
            && self.init.is_none()
    }

    /// Guest user identity (e.g., `"1000"`, `"appuser"`, `"1000:1000"`).
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Guest hostname.
    #[must_use]
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// Shell used for shell sessions.
    #[must_use]
    pub fn shell(&self) -> Option<&str> {
        self.shell.as_deref()
    }

    /// OCI image entrypoint override.
    #[must_use]
    pub fn entrypoint(&self) -> Option<&[String]> {
        self.entrypoint.as_deref()
    }

    /// PID 1 init handoff configuration.
    #[must_use]
    pub fn init(&self) -> Option<&MicrovmInit> {
        self.init.as_ref()
    }
}

/// PID 1 init handoff configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicrovmInit {
    cmd: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
}

impl MicrovmInit {
    /// Create an init handoff from a command path (or `"auto"`), argv, and env.
    #[must_use]
    pub fn new(cmd: String, args: Vec<String>, env: Vec<(String, String)>) -> Self {
        Self { cmd, args, env }
    }

    /// Init binary path or the literal `"auto"`.
    #[must_use]
    pub fn cmd(&self) -> &str {
        &self.cmd
    }

    /// Supplemental argv. `argv[0]` is implicitly `cmd`.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Extra env vars merged on top of the inherited env.
    #[must_use]
    pub fn env(&self) -> &[(String, String)] {
        &self.env
    }
}

/// A secret injected via the TLS proxy with host-allowlist gating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicrovmSecret {
    env_var: String,
    value: String,
    allowed_hosts: Vec<SecretHostPattern>,
}

impl MicrovmSecret {
    /// Create a secret from an env var name, value, and allowed-host patterns.
    #[must_use]
    pub fn new(env_var: String, value: String, allowed_hosts: Vec<SecretHostPattern>) -> Self {
        Self {
            env_var,
            value,
            allowed_hosts,
        }
    }

    /// Environment variable name exposed to the sandbox (holds the placeholder).
    #[must_use]
    pub fn env_var(&self) -> &str {
        &self.env_var
    }

    /// The actual secret value (never enters the sandbox unguarded).
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Hosts allowed to receive this secret.
    #[must_use]
    pub fn allowed_hosts(&self) -> &[SecretHostPattern] {
        &self.allowed_hosts
    }
}

/// Host pattern for secret allowlisting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretHostPattern {
    /// Exact hostname match.
    Exact(String),
    /// Wildcard match (e.g., `*.openai.com`).
    Wildcard(String),
    /// Any host (dangerous: secret can be exfiltrated).
    Any,
}

/// Image pull and snapshot pinning policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MicrovmImage {
    pull_policy: Option<PullPolicy>,
    snapshot: Option<String>,
}

impl MicrovmImage {
    /// Create image policy from a pull policy and optional snapshot reference.
    #[must_use]
    pub fn new(pull_policy: Option<PullPolicy>, snapshot: Option<String>) -> Self {
        Self {
            pull_policy,
            snapshot,
        }
    }

    /// Return true when no image knobs are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pull_policy.is_none() && self.snapshot.is_none()
    }

    /// OCI image pull policy.
    #[must_use]
    pub const fn pull_policy(&self) -> Option<PullPolicy> {
        self.pull_policy
    }

    /// Snapshot artifact path or bare name to boot from (mutually exclusive
    /// with an explicit image reference).
    #[must_use]
    pub fn snapshot(&self) -> Option<&str> {
        self.snapshot.as_deref()
    }
}

/// OCI image pull policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullPolicy {
    /// Use cached layers if complete, pull otherwise.
    IfMissing,
    /// Always fetch the manifest from the registry.
    Always,
    /// Never contact the registry; error if the image is not fully cached.
    Never,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlimitResource {
    /// Max CPU time in seconds (`RLIMIT_CPU`).
    Cpu,
    /// Max file size in bytes (`RLIMIT_FSIZE`).
    Fsize,
    /// Max data segment size (`RLIMIT_DATA`).
    Data,
    /// Max stack size (`RLIMIT_STACK`).
    Stack,
    /// Max core file size (`RLIMIT_CORE`).
    Core,
    /// Max resident set size (`RLIMIT_RSS`).
    Rss,
    /// Max number of processes (`RLIMIT_NPROC`).
    Nproc,
    /// Max open file descriptors (`RLIMIT_NOFILE`).
    Nofile,
    /// Max locked memory (`RLIMIT_MEMLOCK`).
    Memlock,
    /// Max address space size (`RLIMIT_AS`).
    As,
    /// Max file locks (`RLIMIT_LOCKS`).
    Locks,
    /// Max pending signals (`RLIMIT_SIGPENDING`).
    Sigpending,
    /// Max bytes in POSIX message queues (`RLIMIT_MSGQUEUE`).
    Msgqueue,
    /// Max nice priority (`RLIMIT_NICE`).
    Nice,
    /// Max real-time priority (`RLIMIT_RTPRIO`).
    Rtprio,
    /// Max real-time timeout (`RLIMIT_RTTIME`).
    Rttime,
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

    if let Some(hostname) = policy.guest().hostname() {
        if hostname.is_empty() {
            return Err(crate::Error::InvalidMicrovmPolicy(
                "guest.hostname must be non-empty".to_string(),
            ));
        }
        if hostname.len() > MAX_HOSTNAME_BYTES {
            return Err(crate::Error::InvalidMicrovmPolicy(format!(
                "guest.hostname must be at most {MAX_HOSTNAME_BYTES} bytes"
            )));
        }
    }
    if let Some(init) = policy.guest().init()
        && init.cmd().is_empty()
    {
        return Err(crate::Error::InvalidMicrovmPolicy(
            "guest.init.cmd must be non-empty".to_string(),
        ));
    }

    for (index, secret) in policy.secrets().iter().enumerate() {
        if secret.env_var().is_empty() {
            return Err(crate::Error::InvalidMicrovmPolicy(format!(
                "secrets[{index}].envVar must be non-empty"
            )));
        }
        if secret.env_var().contains('=') || secret.env_var().contains('\0') {
            return Err(crate::Error::InvalidMicrovmPolicy(format!(
                "secrets[{index}].envVar must not contain '=' or NUL"
            )));
        }
        if secret.value().is_empty() {
            return Err(crate::Error::InvalidMicrovmPolicy(format!(
                "secrets[{index}].value must be non-empty"
            )));
        }
        if secret.allowed_hosts().is_empty() {
            return Err(crate::Error::InvalidMicrovmPolicy(format!(
                "secrets[{index}].allowedHosts must be non-empty"
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
            MicrovmImage::default(),
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
            MicrovmImage::default(),
            None,
        );

        let error = validate_microvm_policy(&policy).expect_err("zero maxDuration rejects");

        assert!(error.to_string().contains("maxDuration"));
    }

    #[test]
    fn validates_long_hostname() {
        let guest = MicrovmGuest::new(
            None,
            Some("x".repeat(MAX_HOSTNAME_BYTES + 1)),
            None,
            None,
            None,
        );
        let policy = MicrovmPolicy::new(
            MicrovmResources::default(),
            MicrovmLifecycle::default(),
            guest,
            Vec::new(),
            MicrovmImage::default(),
            None,
        );

        let error = validate_microvm_policy(&policy).expect_err("long hostname rejects");

        assert!(error.to_string().contains("hostname"));
    }

    #[test]
    fn validates_empty_init_cmd() {
        let guest = MicrovmGuest::new(
            None,
            None,
            None,
            None,
            Some(MicrovmInit::new(String::new(), Vec::new(), Vec::new())),
        );
        let policy = MicrovmPolicy::new(
            MicrovmResources::default(),
            MicrovmLifecycle::default(),
            guest,
            Vec::new(),
            MicrovmImage::default(),
            None,
        );

        let error = validate_microvm_policy(&policy).expect_err("empty init cmd rejects");

        assert!(error.to_string().contains("init.cmd"));
    }

    #[test]
    fn validates_secret_missing_allowed_hosts() {
        let secret = MicrovmSecret::new("API_KEY".to_string(), "sk-...".to_string(), Vec::new());
        let policy = MicrovmPolicy::new(
            MicrovmResources::default(),
            MicrovmLifecycle::default(),
            MicrovmGuest::default(),
            vec![secret],
            MicrovmImage::default(),
            None,
        );

        let error = validate_microvm_policy(&policy).expect_err("missing allowedHosts rejects");

        assert!(error.to_string().contains("allowedHosts"));
    }

    #[test]
    fn validates_secret_env_var_with_equals() {
        let secret = MicrovmSecret::new(
            "API=KEY".to_string(),
            "sk-...".to_string(),
            vec![SecretHostPattern::Exact("api.openai.com".to_string())],
        );
        let policy = MicrovmPolicy::new(
            MicrovmResources::default(),
            MicrovmLifecycle::default(),
            MicrovmGuest::default(),
            vec![secret],
            MicrovmImage::default(),
            None,
        );

        let error = validate_microvm_policy(&policy).expect_err("env var with = rejects");

        assert!(error.to_string().contains("envVar"));
    }

    #[test]
    fn accepts_well_formed_policy() {
        let policy = MicrovmPolicy::new(
            MicrovmResources::new(Some(2), Some(512), Some(256), Vec::new()),
            MicrovmLifecycle::new(Some(3600), None),
            MicrovmGuest::new(Some("appuser".to_string()), None, None, None, None),
            Vec::new(),
            MicrovmImage::new(Some(PullPolicy::Always), None),
            Some(SecurityProfile::Restricted),
        );

        validate_microvm_policy(&policy).expect("well-formed policy validates");
        assert!(!policy.is_empty());
    }
}
