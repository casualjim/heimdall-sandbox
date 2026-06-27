//! microVM integration tests that boot a real microsandbox via `msb` + libkrun.
//!
//! These tests are `#[ignore]` because they require a KVM-capable Linux host
//! (or aarch64 macOS Hypervisor.framework) with `msb` and `libkrunfw` installed.
//! Run them opt-in via the `microvm` nextest profile:
//!
//! ```sh
//! mise run test:microvm
//! # equivalently:
//! cargo nextest run --profile microvm --run-ignored only -p heimdall-microvm-sandbox
//! ```

#![cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "macos", target_arch = "aarch64"),
))]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use heimdall_microvm_sandbox::MicrovmRequest;
use heimdall_sandbox_policy::{AgentPolicy, FilesystemPolicy, NetworkMode, ProcMode};
use microsandbox::Sandbox;

fn unique_dir(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("heimdall-microvm-{name}-{stamp}"));
    std::fs::create_dir(&dir).expect("temp dir is created");
    dir
}

fn unique_name(prefix: &str) -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after Unix epoch")
        .as_nanos();
    format!("{prefix}-{stamp}")
}

/// Minimal direct-SDK check: bind the host cwd at `/workspace`, set the guest
/// workdir to `/workspace`, run a command, and confirm the artifact lands on
/// the host. Bypasses heimdall's `MicrovmRequest`/plan layer to isolate whether
/// the bare SDK call pattern works (mirrors `msb run --mount-dir $PWD:/workspace
/// -w /workspace alpine -- sh -c '...'`).
#[test]
#[ignore]
fn minimal_workspace_bindmount_and_workdir() {
    let cwd = unique_dir("minimal");
    let host = cwd.clone();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime builds");

    let output = runtime.block_on(async {
        let sandbox = Sandbox::builder(unique_name("heimdall-minimal"))
            .image("alpine")
            .ephemeral(true)
            .volume("/workspace", move |m| m.bind(host))
            .workdir("/workspace")
            .create()
            .await
            .expect("sandbox creates");

        let output = sandbox
            .exec("sh", ["-c", "printf hello > out.txt"])
            .await
            .expect("exec runs");

        sandbox.stop().await.ok();
        output
    });

    assert!(
        output.status().success,
        "guest exec failed: {:?}",
        output.status(),
    );
    assert_eq!(
        std::fs::read_to_string(cwd.join("out.txt")).expect("guest artifact is readable on host"),
        "hello",
    );

    std::fs::remove_dir_all(cwd).ok();
}

/// Exercise heimdall's `MicrovmRequest` (the production path: `plan_filesystem` +
/// `apply_filesystem_plan` + `execute`). Uses the simplest policy that grants
/// the workspace writable, then confirms the guest writes back to the host.
#[test]
#[ignore]
fn microvm_request_writes_to_mounted_workspace() {
    let cwd = unique_dir("req-smoke");
    let filesystem_policy =
        FilesystemPolicy::new(Vec::new(), vec![".".to_string()], Default::default());
    let argv = [
        "sh".to_string(),
        "-c".to_string(),
        "printf hello > out.txt".to_string(),
    ];
    let request = MicrovmRequest {
        cwd: &cwd,
        argv: &argv,
        image: "alpine",
        environment: &[],
        network_mode: NetworkMode::Host,
        filesystem_policy: &filesystem_policy,
        proc_mode: ProcMode::Default,
        agent_policy: AgentPolicy::default(),
    };

    let exit = request
        .execute()
        .expect("microvm boots and execs the command");

    assert_eq!(exit, 0, "guest command should exit successfully");
    assert_eq!(
        std::fs::read_to_string(cwd.join("out.txt")).expect("guest artifact is readable on host"),
        "hello",
    );

    std::fs::remove_dir_all(cwd).ok();
}
