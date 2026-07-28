//! microVM integration tests that boot a real boxlite microVM.
//!
//! These tests are `#[ignore]` because they require a KVM-capable Linux host
//! (or aarch64 macOS Hypervisor.framework). The boxlite runtime is embedded
//! (build-time fetch), so no host preinstall is needed — only the virtualization
//! backend. Run them opt-in via the `microvm` nextest profile:
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

use boxlite::runtime::options::VolumeSpec;
use boxlite::{BoxCommand, BoxOptions, BoxliteRuntime, RootfsSpec};
use futures::StreamExt;
use heimdall_microvm_sandbox::MicrovmRequest;
use heimdall_sandbox_policy::{
    AgentPolicy, FilesystemPolicy, MicrovmPolicy, NetworkMode, ProcMode,
};

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

/// Minimal direct-SDK check: create a boxlite box with the host cwd bound at
/// `/workspace`, run a command, and confirm the artifact lands on the host.
/// Bypasses heimdall's `MicrovmRequest`/plan layer to isolate whether the bare
/// boxlite call pattern works.
#[test]
#[ignore]
fn minimal_workspace_bindmount_and_workdir() {
    let cwd = unique_dir("minimal");
    let host = cwd.clone();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime builds");

    let result = runtime.block_on(async {
        let runtime = BoxliteRuntime::with_defaults().expect("boxlite runtime creates");
        let litebox = runtime
            .create(
                BoxOptions {
                    rootfs: RootfsSpec::Image("alpine:latest".into()),
                    working_dir: Some("/workspace".into()),
                    volumes: vec![VolumeSpec {
                        host_path: host.to_string_lossy().into_owned(),
                        guest_path: "/workspace".into(),
                        read_only: false,
                    }],
                    auto_remove: true,
                    detach: false,
                    ..Default::default()
                },
                Some(unique_name("heimdall-minimal")),
            )
            .await
            .expect("box creates");

        let mut execution = litebox
            .exec(
                BoxCommand::new("sh")
                    .args(["-c", "printf hello > out.txt"])
                    .working_dir("/workspace"),
            )
            .await
            .expect("exec runs");

        // Drain output concurrently with completion so unbounded streams do not
        // buffer the whole run before the box stops.
        let mut stdout = execution.stdout();
        let mut stderr = execution.stderr();
        let (stdout_res, stderr_res, wait_res) = futures::join!(
            async {
                let Some(stdout) = stdout.as_mut() else {
                    return Ok(());
                };
                while stdout.next().await.is_some() {}
                Ok::<(), std::io::Error>(())
            },
            async {
                let Some(stderr) = stderr.as_mut() else {
                    return Ok(());
                };
                while stderr.next().await.is_some() {}
                Ok::<(), std::io::Error>(())
            },
            execution.wait(),
        );
        stdout_res.expect("stdout drains");
        stderr_res.expect("stderr drains");
        let result = wait_res.expect("exec completes");

        litebox.stop().await.ok();
        result
    });

    assert!(result.success(), "guest exec failed: {result:?}",);
    assert_eq!(
        std::fs::read_to_string(cwd.join("out.txt")).expect("guest artifact is readable on host"),
        "hello",
    );

    std::fs::remove_dir_all(cwd).ok();
}

/// Exercise heimdall's `MicrovmRequest` (the production path: `plan_filesystem`,
/// `build_box_options`, and `execute`). Uses the simplest policy that grants
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
    let microvm_policy = MicrovmPolicy::default();
    let request = MicrovmRequest {
        cwd: &cwd,
        argv: &argv,
        image: Some("alpine:latest"),
        environment: &[],
        network_mode: NetworkMode::Host,
        filesystem_policy: &filesystem_policy,
        proc_mode: ProcMode::Default,
        agent_policy: AgentPolicy::default(),
        microvm_policy: &microvm_policy,
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
