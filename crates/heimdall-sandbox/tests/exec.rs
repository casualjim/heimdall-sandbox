use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn sandbox() -> Command {
    Command::new(env!("CARGO_BIN_EXE_heimdall-sandbox"))
}

#[test]
fn smoke_test_runs_simple_command() {
    let output = sandbox()
        .args(["exec", "--cwd", ".", "--", "sh", "-c", "printf smoke"])
        .output()
        .expect("sandbox command runs");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "smoke");
}

#[test]
fn child_defaults_to_current_cwd() {
    let current_dir = std::env::current_dir().expect("current dir exists");
    let output = sandbox()
        .args(["exec", "--", "pwd"])
        .output()
        .expect("sandbox command runs");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        current_dir.to_string_lossy()
    );
}

#[test]
fn child_runs_in_requested_cwd() {
    let temp_dir = std::env::temp_dir();
    let output = sandbox()
        .args(["exec", "--cwd"])
        .arg(&temp_dir)
        .args(["--", "pwd"])
        .output()
        .expect("sandbox command runs");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        temp_dir.to_string_lossy()
    );
}

#[test]
fn allow_env_controls_inherited_environment() {
    let output = sandbox()
        .env("HEIMDALL_ALLOWED", "visible")
        .env("HEIMDALL_SECRET", "hidden")
        .args([
            "exec",
            "--cwd",
            ".",
            "--allow-env",
            "HEIMDALL_ALLOWED",
            "--",
            "sh",
            "-c",
            "printf '%s:%s' \"${HEIMDALL_ALLOWED-unset}\" \"${HEIMDALL_SECRET-unset}\"",
        ])
        .output()
        .expect("sandbox command runs");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "visible:unset");
}

#[test]
fn blocklist_env_removes_denied_keys() {
    let output = sandbox()
        .env("HEIMDALL_VISIBLE", "visible")
        .env("HEIMDALL_SECRET", "hidden")
        .args([
            "exec",
            "--cwd",
            ".",
            "--deny-env",
            "HEIMDALL_SECRET",
            "--",
            "sh",
            "-c",
            "printf '%s:%s' \"${HEIMDALL_VISIBLE-unset}\" \"${HEIMDALL_SECRET-unset}\"",
        ])
        .output()
        .expect("sandbox command runs");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "visible:unset");
}

#[test]
fn policy_file_controls_sandbox_request() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after Unix epoch")
        .as_nanos();
    let policy = std::env::temp_dir().join(format!("heimdall-policy-{stamp}.json"));
    std::fs::write(
        &policy,
        r#"{
          "cwd": ".",
          "command": ["sh", "-c", "printf '%s:%s' \"${HEIMDALL_VISIBLE-unset}\" \"${HEIMDALL_SECRET-unset}\""],
          "env": { "deny": ["HEIMDALL_SECRET"] },
          "stdio": "piped"
        }"#,
    )
    .expect("policy file is written");

    let output = sandbox()
        .env("HEIMDALL_VISIBLE", "visible")
        .env("HEIMDALL_SECRET", "hidden")
        .args(["exec", "--policy"])
        .arg(&policy)
        .output()
        .expect("sandbox command runs");
    std::fs::remove_file(&policy).expect("policy file is removed");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "visible:unset");
}

#[test]
fn policy_stdin_controls_sandbox_request() {
    let mut child = sandbox()
        .env("HEIMDALL_ALLOWED", "visible")
        .env("HEIMDALL_SECRET", "hidden")
        .args(["exec", "--policy", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("sandbox command starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(
            br#"{
              "cwd": ".",
              "command": ["sh", "-c", "printf '%s:%s' \"${HEIMDALL_ALLOWED-unset}\" \"${HEIMDALL_SECRET-unset}\""],
              "env": { "allow": ["HEIMDALL_ALLOWED", "HEIMDALL_SECRET"], "deny": ["HEIMDALL_SECRET"] },
              "stdio": "piped"
            }"#,
        )
        .expect("policy write succeeds");

    let output = child.wait_with_output().expect("sandbox command exits");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "visible:unset");
}

#[test]
fn non_zero_child_status_is_propagated() {
    let output = sandbox()
        .args(["exec", "--cwd", ".", "--", "sh", "-c", "exit 37"])
        .output()
        .expect("sandbox command runs");

    assert_eq!(output.status.code(), Some(37));
}

#[test]
fn child_stderr_is_inherited() {
    let output = sandbox()
        .args(["exec", "--cwd", ".", "--", "sh", "-c", "printf error >&2"])
        .output()
        .expect("sandbox command runs");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stderr), "error");
}

#[test]
fn inherited_stdio_can_read_parent_stdin() {
    let mut child = sandbox()
        .args([
            "exec",
            "--cwd",
            ".",
            "--",
            "sh",
            "-c",
            "if read line; then printf '%s' \"$line\"; else printf no-input; fi",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("sandbox command starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(b"got-input\n")
        .expect("stdin write succeeds");

    let output = child.wait_with_output().expect("sandbox command exits");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "got-input");
}

#[test]
fn piped_stdio_uses_null_stdin() {
    let mut child = sandbox()
        .args([
            "exec",
            "--cwd",
            ".",
            "--stdio",
            "piped",
            "--",
            "sh",
            "-c",
            "if read line; then printf '%s' \"$line\"; else printf no-input; fi",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("sandbox command starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(b"got-input\n")
        .expect("stdin write succeeds");

    let output = child.wait_with_output().expect("sandbox command exits");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "no-input");
}

#[test]
fn piped_stdio_preserves_stdout_and_stderr() {
    let output = sandbox()
        .args([
            "exec",
            "--cwd",
            ".",
            "--stdio",
            "piped",
            "--",
            "sh",
            "-c",
            "printf out; printf err >&2",
        ])
        .output()
        .expect("sandbox command runs");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "out");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "err");
}

#[cfg(unix)]
#[test]
fn non_utf8_parent_environment_does_not_crash_sandbox() {
    use std::os::unix::ffi::OsStringExt;

    let output = sandbox()
        .env(
            "HEIMDALL_NON_UTF8",
            std::ffi::OsString::from_vec(vec![0xff]),
        )
        .args(["exec", "--cwd", ".", "--", "sh", "-c", "exit 0"])
        .output()
        .expect("sandbox command runs");

    assert_eq!(output.status.code(), Some(0));
}

#[cfg(unix)]
fn assert_signal_is_forwarded(signal_name: &str, trap_name: &str, exit_code: i32) {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after Unix epoch")
        .as_nanos();
    let marker = std::env::temp_dir().join(format!("heimdall-signal-{stamp}"));
    let script = format!(
        "trap 'printf forwarded > {}; exit {exit_code}' {trap_name}; while true; do sleep 1; done",
        marker.display()
    );
    let mut child = sandbox()
        .args(["exec", "--cwd", ".", "--", "sh", "-c"])
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sandbox command starts");

    std::thread::sleep(Duration::from_millis(250));
    let kill_status = Command::new("kill")
        .args([signal_name, &child.id().to_string()])
        .status()
        .expect("kill command runs");
    assert!(kill_status.success());

    let status = child.wait().expect("sandbox command exits");
    let marker_contents = std::fs::read_to_string(&marker).expect("signal marker is written");
    std::fs::remove_file(&marker).expect("signal marker is removed");

    assert_eq!(status.code(), Some(exit_code));
    assert_eq!(marker_contents, "forwarded");
}

#[cfg(unix)]
#[test]
fn sigint_is_forwarded_to_child() {
    assert_signal_is_forwarded("-INT", "INT", 41);
}

#[cfg(unix)]
#[test]
fn sigterm_is_forwarded_to_child() {
    assert_signal_is_forwarded("-TERM", "TERM", 42);
}
