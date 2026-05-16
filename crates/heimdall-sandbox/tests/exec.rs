use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn sandbox() -> Command {
    Command::new(env!("CARGO_BIN_EXE_heimdall-sandbox"))
}

#[cfg(target_os = "linux")]
fn bwrap_available() -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| {
            let candidate = dir.join("bwrap");
            candidate.is_file()
                && Command::new(candidate)
                    .arg("--version")
                    .status()
                    .is_ok_and(|status| status.success())
        })
    })
}

fn unique_temp_dir(name: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("heimdall-{name}-{stamp}"));
    std::fs::create_dir(&dir).expect("temp dir is created");
    dir
}

#[cfg(target_os = "macos")]
fn unique_project_dir(name: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after Unix epoch")
        .as_nanos();
    let dir = std::env::current_dir()
        .expect("current dir exists")
        .join("target")
        .join(format!("heimdall-{name}-{stamp}"));
    std::fs::create_dir_all(&dir).expect("project temp dir is created");
    dir
}

#[cfg(target_os = "macos")]
fn seatbelt_available() -> bool {
    std::path::Path::new("/usr/bin/sandbox-exec").is_file()
}

fn run_policy(policy: &str) -> std::process::Output {
    let mut child = sandbox()
        .args(["exec", "--policy", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sandbox command starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(policy.as_bytes())
        .expect("policy write succeeds");
    child.wait_with_output().expect("sandbox command exits")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn wait_for_file_contents(path: &std::path::Path, expected: &str) -> String {
    for _ in 0..40 {
        if let Ok(contents) = std::fs::read_to_string(path)
            && contents == expected
        {
            return contents;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    std::fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn policy_schema_outputs_json_schema() {
    let output = sandbox()
        .args(["policy", "schema"])
        .output()
        .expect("schema command runs");

    assert!(output.status.success());
    let schema =
        serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("schema output is JSON");
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["additionalProperties"], false);
    assert!(schema["properties"].get("filesystem").is_some());
}

#[test]
fn policy_validate_accepts_file() {
    let policy = unique_temp_dir("policy-validate").join("policy.json");
    std::fs::write(&policy, r#"{"cwd":".","command":["true"]}"#).expect("policy file is written");

    let output = sandbox()
        .args(["policy", "validate"])
        .arg(&policy)
        .output()
        .expect("validate command runs");
    std::fs::remove_file(&policy).expect("policy file is removed");
    std::fs::remove_dir(policy.parent().expect("policy has parent"))
        .expect("policy dir is removed");

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn policy_validate_accepts_stdin() {
    let mut child = sandbox()
        .args(["policy", "validate", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("validate command starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(br#"{"cwd":".","command":["true"]}"#)
        .expect("policy write succeeds");

    let output = child.wait_with_output().expect("validate command exits");

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn policy_validate_rejects_invalid_policy() {
    let mut child = sandbox()
        .args(["policy", "validate", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("validate command starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(br#"{"cwd":".","command":["true"],"bogus":true}"#)
        .expect("policy write succeeds");

    let output = child.wait_with_output().expect("validate command exits");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown policy field: bogus"));
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
        std::path::PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_string())
            .canonicalize()
            .expect("pwd output canonicalizes"),
        temp_dir.canonicalize().expect("temp dir canonicalizes")
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

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_runs_isolated_command_when_filesystem_requested() {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-smoke");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","printf isolated"],"filesystem":{{"deny":["missing"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "isolated");
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_home_dotfiles_are_readable() {
    if !bwrap_available() {
        return;
    }
    let home = std::env::var("HOME").expect("HOME is set");
    let has_gitconfig = std::path::Path::new(&home).join(".gitconfig").exists();
    let cwd = unique_temp_dir("bwrap-home-read");
    let test_cmd = format!(
        "test -r {}/.gitconfig && printf readable || printf blocked",
        home
    );
    let policy = serde_json::json!({
        "cwd": cwd,
        "command": ["sh", "-c", test_cmd],
        "filesystem": {"deny": ["missing"]},
        "stdio": "piped"
    })
    .to_string();

    let output = run_policy(&policy);
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if has_gitconfig {
        assert_eq!(String::from_utf8_lossy(&output.stdout), "readable");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_keeps_unmatched_project_files_readonly() {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-readonly");
    std::fs::write(cwd.join("data.txt"), "old").expect("file is written");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","echo new > data.txt"],"filesystem":{{"deny":["missing"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    let host_contents = std::fs::read_to_string(cwd.join("data.txt")).expect("file is readable");
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(!output.status.success());
    assert_eq!(host_contents, "old");
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_writable_patterns_allow_edits_and_creation() {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-writable");
    std::fs::create_dir(cwd.join("work")).expect("directory is created");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","echo edited > work/new.txt"],"filesystem":{{"writable":["work"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    let host_contents =
        std::fs::read_to_string(cwd.join("work/new.txt")).expect("file is readable");
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(host_contents.trim(), "edited");
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_broad_writable_cwd_allows_regular_writes_and_protects_control_paths() {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-broad-writable");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","echo edited > regular.txt; touch .heimdall-deny || printf deny-blocked; touch .heimdall-write || printf write-blocked; touch .heimdall-local || true; mkdir .git || true; mkdir .agents || true; mkdir .pi || true"],"filesystem":{{"writable":["."]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    let host_contents = std::fs::read_to_string(cwd.join("regular.txt")).expect("file is readable");
    let git_exists = cwd.join(".git").exists();
    let agents_exists = cwd.join(".agents").exists();
    let pi_exists = cwd.join(".pi").exists();
    let deny_exists = cwd.join(".heimdall-deny").exists();
    let write_exists = cwd.join(".heimdall-write").exists();
    let heimdall_local_exists = cwd.join(".heimdall-local").exists();
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "deny-blockedwrite-blocked"
    );
    assert_eq!(host_contents.trim(), "edited");
    assert!(!git_exists);
    assert!(!agents_exists);
    assert!(!pi_exists);
    assert!(!deny_exists);
    assert!(!write_exists);
    assert!(!heimdall_local_exists);
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_unavailable_fails_without_running_command() {
    let cwd = unique_temp_dir("bwrap-missing");
    let path = unique_temp_dir("bwrap-empty-path");
    let marker = cwd.join("marker");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","touch marker"],"filesystem":{{"deny":["missing"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let mut child = sandbox()
        .env("PATH", &path)
        .args(["exec", "--policy", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sandbox command starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(policy.as_bytes())
        .expect("policy write succeeds");
    let output = child.wait_with_output().expect("sandbox command exits");
    let marker_exists = marker.exists();
    std::fs::remove_dir_all(path).expect("path dir is removed");
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert_eq!(output.status.code(), Some(2));
    assert!(!marker_exists);
    assert!(String::from_utf8_lossy(&output.stderr).contains("bubblewrap executable not found"));
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_deny_masks_env_files_and_supports_negation() {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-deny");
    std::fs::write(cwd.join(".env"), "secret").expect("file is written");
    std::fs::write(cwd.join(".env.example"), "example").expect("file is written");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","printf '%s:%s' \"$(cat .env)\" \"$(cat .env.example)\""],"filesystem":{{"deny":[".env*","!.env.example"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), ":example");
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_reads_heimdall_fragments_from_cwd_after_json_patterns() {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-fragments");
    std::fs::write(cwd.join("secret.txt"), "secret").expect("file is written");
    std::fs::write(cwd.join("write.txt"), "old").expect("file is written");
    std::fs::write(cwd.join(".heimdall-deny"), "!secret.txt\n").expect("deny fragment is written");
    std::fs::write(cwd.join(".heimdall-write"), "write.txt\n").expect("write fragment is written");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","cat secret.txt; echo new > write.txt"],"filesystem":{{"deny":["secret.txt"],"writable":[]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    let host_contents = std::fs::read_to_string(cwd.join("write.txt")).expect("file is readable");
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "secret");
    assert_eq!(host_contents.trim(), "new");
}

#[cfg(target_os = "linux")]
#[test]
fn native_does_not_discover_pi_config() {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-pi-config");
    std::fs::create_dir(cwd.join(".pi")).expect("pi directory is created");
    std::fs::write(cwd.join("secret.txt"), "secret").expect("file is written");
    std::fs::write(
        cwd.join(".pi").join("heimdall.json"),
        r#"{"filesystem":{"deny":["secret.txt"]}}"#,
    )
    .expect("pi config is written");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","cat secret.txt"],"filesystem":{{"deny":["missing"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "secret");
}

#[cfg(target_os = "linux")]
#[test]
fn native_does_not_walk_upward_for_fragments() {
    if !bwrap_available() {
        return;
    }
    let root = unique_temp_dir("bwrap-parent-fragment");
    let cwd = root.join("subdir");
    std::fs::create_dir(&cwd).expect("subdir is created");
    std::fs::write(root.join(".heimdall-deny"), "secret.txt\n")
        .expect("parent deny fragment is written");
    std::fs::write(cwd.join("secret.txt"), "secret").expect("file is written");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","cat secret.txt"],"filesystem":{{"deny":["missing"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    std::fs::remove_dir_all(root).expect("temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "secret");
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_virtual_files_are_readable_and_readonly() {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-virtual");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","cat /tmp/heimdall-virtual; echo bad > /tmp/heimdall-virtual"],"filesystem":{{"virtual":{{"/tmp/heimdall-virtual":"virtual"}}}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "virtual");
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_network_none_still_executes_in_isolated_path() {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-network");
    let policy = format!(
        r#"{{"cwd":"{}","network":"none","command":["sh","-c","printf net-none"],"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "net-none");
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_no_proc_policy_skips_proc_mount() {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-no-proc");
    let policy = format!(
        r#"{{"cwd":"{}","proc":"none","command":["sh","-c","test ! -e /proc/self && printf no-proc"],"filesystem":{{"deny":["missing"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "no-proc");
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_sees_host_identity_files_when_no_virtual_override() {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-identity");
    let policy = format!(
        r#"{{\"cwd\":\"{}\",\"command\":[\"sh\",\"-c\",\"test -r /etc/passwd && test -r /etc/group && printf ok\"],\"filesystem\":{{\"deny\":[\"missing\"]}},\"stdio\":\"piped\"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ok");
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_preserves_env_stdio_and_exit_status() {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-runtime");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","printf '%s:%s' \"${{HEIMDALL_VISIBLE-unset}}\" \"${{HEIMDALL_SECRET-unset}}\"; printf err >&2; exit 37"],"filesystem":{{"deny":["missing"]}},"env":{{"deny":["HEIMDALL_SECRET"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let mut child = sandbox()
        .env("HEIMDALL_VISIBLE", "visible")
        .env("HEIMDALL_SECRET", "hidden")
        .args(["exec", "--policy", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sandbox command starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(policy.as_bytes())
        .expect("policy write succeeds");
    let output = child.wait_with_output().expect("sandbox command exits");
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert_eq!(output.status.code(), Some(37));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "visible:unset");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "err");
}

#[cfg(target_os = "linux")]
fn spawn_bubblewrap_signal_child(cwd: &std::path::Path, script: &str) -> std::process::Child {
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c",{}],"filesystem":{{"writable":["."]}},"stdio":"piped"}}"#,
        cwd.display(),
        serde_json::to_string(script).expect("script serializes")
    );
    let mut child = sandbox()
        .args(["exec", "--policy", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sandbox command starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(policy.as_bytes())
        .expect("policy write succeeds");
    child
}

#[cfg(target_os = "linux")]
fn assert_bubblewrap_signal_is_forwarded(signal_name: &str, trap_name: &str, exit_code: i32) {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-signal");
    let marker = cwd.join("marker");
    let ready = cwd.join("ready");
    let script = format!(
        "trap 'printf forwarded > {}; exit {exit_code}' {trap_name}; touch {}; while true; do sleep 1; done",
        marker.display(),
        ready.display()
    );
    let mut child = spawn_bubblewrap_signal_child(&cwd, &script);

    for _ in 0..40 {
        if ready.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready.exists(), "bubblewrap child did not signal readiness");
    let kill_status = Command::new("kill")
        .args([signal_name, &child.id().to_string()])
        .status()
        .expect("kill command runs");
    assert!(kill_status.success());

    let status = child.wait().expect("sandbox command exits");
    let marker_contents = wait_for_file_contents(&marker, "forwarded");
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert_eq!(status.code(), Some(exit_code));
    assert_eq!(marker_contents, "forwarded");
}

#[cfg(target_os = "linux")]
fn assert_bubblewrap_signal_terminates_child(signal_name: &str) {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-signal-terminate");
    let ready = cwd.join("ready");
    let script = format!("touch {}; while true; do sleep 1; done", ready.display());
    let mut child = spawn_bubblewrap_signal_child(&cwd, &script);

    for _ in 0..40 {
        if ready.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready.exists(), "bubblewrap child did not signal readiness");
    let kill_status = Command::new("kill")
        .args([signal_name, &child.id().to_string()])
        .status()
        .expect("kill command runs");
    assert!(kill_status.success());

    let mut status = None;
    for _ in 0..40 {
        status = child.try_wait().expect("sandbox wait can be polled");
        if status.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(status.is_some(), "bubblewrap child did not terminate");
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_child_dies_when_parent_crashes() {
    if !bwrap_available() {
        return;
    }
    let cwd = unique_temp_dir("bwrap-parent-crash");
    let ready = cwd.join("ready");
    let marker = cwd.join("marker");
    let script = format!(
        "touch {}; sleep 2; touch {}",
        ready.display(),
        marker.display()
    );
    let mut child = spawn_bubblewrap_signal_child(&cwd, &script);

    for _ in 0..40 {
        if ready.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready.exists(), "bubblewrap child did not signal readiness");

    child.kill().expect("sandbox parent is killed");
    let _ = child.wait().expect("sandbox parent exits");
    std::thread::sleep(Duration::from_secs(3));
    let marker_exists = marker.exists();
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(!marker_exists, "bubblewrap child survived parent crash");
}

#[cfg(target_os = "linux")]
#[test]
fn sighup_is_forwarded_to_bubblewrap_process_group() {
    assert_bubblewrap_signal_is_forwarded("-HUP", "HUP", 43);
}

#[cfg(target_os = "linux")]
#[test]
fn sigint_is_forwarded_to_bubblewrap_process_group() {
    assert_bubblewrap_signal_is_forwarded("-INT", "INT", 44);
}

#[cfg(target_os = "linux")]
#[test]
fn sigquit_is_forwarded_to_bubblewrap_process_group() {
    assert_bubblewrap_signal_terminates_child("-QUIT");
}

#[cfg(target_os = "linux")]
#[test]
fn sigterm_is_forwarded_to_bubblewrap_process_group() {
    assert_bubblewrap_signal_terminates_child("-TERM");
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

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_reads_temp_cwd_through_canonical_alias() {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_temp_dir("seatbelt-temp-alias");
    std::fs::write(cwd.join("data.txt"), "alias").expect("file is written");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","cat data.txt"],"filesystem":{{"deny":["missing"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "alias");
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_writes_temp_cwd_through_canonical_alias() {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_temp_dir("seatbelt-temp-write-alias");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","echo alias > data.txt"],"filesystem":{{"writable":["."]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    let host_contents = std::fs::read_to_string(cwd.join("data.txt")).expect("file is readable");
    std::fs::remove_dir_all(cwd).expect("temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(host_contents.trim(), "alias");
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_denies_unselected_non_cwd_temp_writes() {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_project_dir("seatbelt-temp-deny-cwd");
    let outside = unique_temp_dir("seatbelt-temp-deny-outside");
    let target = outside.join("blocked.txt");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","echo blocked > '{}'"],"filesystem":{{"deny":["missing"]}},"stdio":"piped"}}"#,
        cwd.display(),
        target.display()
    );

    let output = run_policy(&policy);
    let target_exists = target.exists();
    std::fs::remove_dir_all(cwd).expect("project temp dir is removed");
    std::fs::remove_dir_all(outside).expect("temp dir is removed");

    assert!(!output.status.success());
    assert!(!target_exists);
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_runs_isolated_command_when_filesystem_requested() {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_project_dir("seatbelt-smoke");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","printf isolated"],"filesystem":{{"deny":["missing"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    std::fs::remove_dir_all(cwd).expect("project temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "isolated");
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_home_dotfiles_are_readable() {
    if !seatbelt_available() {
        return;
    }
    let home = std::env::var("HOME").expect("HOME is set");
    let has_gitconfig = std::path::Path::new(&home).join(".gitconfig").exists();
    let cwd = unique_project_dir("seatbelt-home-read");
    let test_cmd = format!(
        "test -r {}/.gitconfig && printf readable || printf blocked",
        home
    );
    let policy = serde_json::json!({
        "cwd": cwd,
        "command": ["sh", "-c", test_cmd],
        "filesystem": {"deny": ["missing"]},
        "stdio": "piped"
    })
    .to_string();

    let output = run_policy(&policy);
    std::fs::remove_dir_all(cwd).expect("project temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if has_gitconfig {
        assert_eq!(String::from_utf8_lossy(&output.stdout), "readable");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_keeps_unmatched_project_files_readonly() {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_project_dir("seatbelt-readonly");
    std::fs::write(cwd.join("data.txt"), "old").expect("file is written");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","echo new > data.txt"],"filesystem":{{"deny":["missing"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    let host_contents = std::fs::read_to_string(cwd.join("data.txt")).expect("file is readable");
    std::fs::remove_dir_all(cwd).expect("project temp dir is removed");

    assert!(!output.status.success());
    assert_eq!(host_contents, "old");
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_writable_patterns_allow_edits_and_creation() {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_project_dir("seatbelt-writable");
    std::fs::create_dir(cwd.join("work")).expect("directory is created");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","echo edited > work/new.txt"],"filesystem":{{"writable":["work"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    let host_contents =
        std::fs::read_to_string(cwd.join("work/new.txt")).expect("file is readable");
    std::fs::remove_dir_all(cwd).expect("project temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(host_contents.trim(), "edited");
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_deny_masks_env_files_and_supports_negation() {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_project_dir("seatbelt-deny");
    std::fs::write(cwd.join(".env"), "secret").expect("file is written");
    std::fs::write(cwd.join(".env.example"), "example").expect("file is written");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","cat .env 2>/dev/null || true; printf ':'; cat .env.example"],"filesystem":{{"deny":[".env*","!.env.example"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    std::fs::remove_dir_all(cwd).expect("project temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), ":example");
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_nested_env_pattern_matches_cwd_relative_paths() {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_project_dir("seatbelt-nested-env-deny");
    std::fs::create_dir_all(cwd.join("packages/api")).expect("nested directory is created");
    std::fs::write(cwd.join(".env"), "secret").expect("file is written");
    std::fs::write(cwd.join(".env.example"), "example").expect("file is written");
    std::fs::write(cwd.join("packages/api/.env.local"), "nested").expect("nested file is written");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","cat .env 2>/dev/null || printf root-blocked; printf ':'; cat packages/api/.env.local 2>/dev/null || printf nested-blocked; printf ':'; cat .env.example"],"filesystem":{{"deny":["**/.env*","!**/.env.example"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    std::fs::remove_dir_all(cwd).expect("project temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "root-blocked:nested-blocked:example"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_reads_heimdall_fragments_from_cwd_after_json_patterns() {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_project_dir("seatbelt-fragments");
    std::fs::write(cwd.join("secret.txt"), "secret").expect("file is written");
    std::fs::write(cwd.join("write.txt"), "old").expect("file is written");
    std::fs::write(cwd.join(".heimdall-deny"), "!secret.txt\n").expect("deny fragment is written");
    std::fs::write(cwd.join(".heimdall-write"), "write.txt\n").expect("write fragment is written");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","cat secret.txt; echo new > write.txt"],"filesystem":{{"deny":["secret.txt"],"writable":[]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    let host_contents = std::fs::read_to_string(cwd.join("write.txt")).expect("file is readable");
    std::fs::remove_dir_all(cwd).expect("project temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "secret");
    assert_eq!(host_contents.trim(), "new");
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_does_not_discover_pi_config() {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_project_dir("seatbelt-pi-config");
    std::fs::create_dir(cwd.join(".pi")).expect("pi directory is created");
    std::fs::write(cwd.join("secret.txt"), "secret").expect("file is written");
    std::fs::write(
        cwd.join(".pi").join("heimdall.json"),
        r#"{"filesystem":{"deny":["secret.txt"]}}"#,
    )
    .expect("pi config is written");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","cat secret.txt"],"filesystem":{{"deny":["missing"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    std::fs::remove_dir_all(cwd).expect("project temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "secret");
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_does_not_walk_upward_for_fragments() {
    if !seatbelt_available() {
        return;
    }
    let root = unique_project_dir("seatbelt-parent-fragment");
    let cwd = root.join("subdir");
    std::fs::create_dir(&cwd).expect("subdir is created");
    std::fs::write(root.join(".heimdall-deny"), "secret.txt\n")
        .expect("parent deny fragment is written");
    std::fs::write(cwd.join("secret.txt"), "secret").expect("file is written");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","cat secret.txt"],"filesystem":{{"deny":["missing"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    std::fs::remove_dir_all(root).expect("project temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "secret");
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_broad_writable_cwd_allows_regular_writes_and_protects_control_paths() {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_project_dir("seatbelt-broad-writable");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","echo edited > regular.txt; touch .heimdall-deny || printf deny-blocked; touch .heimdall-write || printf write-blocked; touch .heimdall-local || printf local-blocked; mkdir .git || printf git-blocked; mkdir .agents || printf agents-blocked; mkdir .pi || printf pi-blocked"],"filesystem":{{"writable":["."]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let output = run_policy(&policy);
    let host_contents = std::fs::read_to_string(cwd.join("regular.txt")).expect("file is readable");
    let git_exists = cwd.join(".git").exists();
    let agents_exists = cwd.join(".agents").exists();
    let pi_exists = cwd.join(".pi").exists();
    let deny_exists = cwd.join(".heimdall-deny").exists();
    let write_exists = cwd.join(".heimdall-write").exists();
    let heimdall_local_exists = cwd.join(".heimdall-local").exists();
    std::fs::remove_dir_all(cwd).expect("project temp dir is removed");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(host_contents.trim(), "edited");
    assert!(!git_exists);
    assert!(!agents_exists);
    assert!(!pi_exists);
    assert!(!deny_exists);
    assert!(!write_exists);
    assert!(!heimdall_local_exists);
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_virtual_targets_are_readonly_and_contents_are_not_materialized() {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_project_dir("seatbelt-virtual");
    let virtual_target = cwd.join("virtual.txt");
    std::fs::write(&virtual_target, "real").expect("virtual target host file is written");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","cat virtual.txt; echo bad > virtual.txt"],"filesystem":{{"writable":["."],"virtual":{{"{}":"synthetic"}}}},"stdio":"piped"}}"#,
        cwd.display(),
        virtual_target.display()
    );

    let output = run_policy(&policy);
    let host_contents = std::fs::read_to_string(&virtual_target).expect("file is readable");
    std::fs::remove_dir_all(cwd).expect("project temp dir is removed");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "real");
    assert_eq!(host_contents, "real");
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_network_modes_control_loopback_connections() {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_project_dir("seatbelt-network");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener binds");
    let port = listener.local_addr().expect("listener has addr").port();
    let policy_none = format!(
        r#"{{"cwd":"{}","network":"none","command":["/usr/bin/nc","-z","127.0.0.1","{}"],"stdio":"piped"}}"#,
        cwd.display(),
        port
    );
    let none_output = run_policy(&policy_none);

    let host_listener = listener.try_clone().expect("listener clones");
    let accept_thread = std::thread::spawn(move || host_listener.accept());
    let policy_host = format!(
        r#"{{"cwd":"{}","network":"host","command":["/usr/bin/nc","-z","127.0.0.1","{}"],"stdio":"piped"}}"#,
        cwd.display(),
        port
    );
    let host_output = run_policy(&policy_host);
    let _ = accept_thread.join();
    std::fs::remove_dir_all(cwd).expect("project temp dir is removed");

    assert!(!none_output.status.success());
    assert!(
        host_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&host_output.stderr)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_preserves_env_stdio_and_exit_status() {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_project_dir("seatbelt-runtime");
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c","printf '%s:%s' \"${{HEIMDALL_VISIBLE-unset}}\" \"${{HEIMDALL_SECRET-unset}}\"; printf err >&2; exit 37"],"filesystem":{{"deny":["missing"]}},"env":{{"deny":["HEIMDALL_SECRET"]}},"stdio":"piped"}}"#,
        cwd.display()
    );

    let mut child = sandbox()
        .env("HEIMDALL_VISIBLE", "visible")
        .env("HEIMDALL_SECRET", "hidden")
        .args(["exec", "--policy", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sandbox command starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(policy.as_bytes())
        .expect("policy write succeeds");
    let output = child.wait_with_output().expect("sandbox command exits");
    std::fs::remove_dir_all(cwd).expect("project temp dir is removed");

    assert_eq!(output.status.code(), Some(37));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "visible:unset");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "err");
}

#[cfg(target_os = "macos")]
fn assert_seatbelt_signal_is_forwarded(signal_name: &str, trap_name: &str, exit_code: i32) {
    if !seatbelt_available() {
        return;
    }
    let cwd = unique_project_dir("seatbelt-signal");
    let marker = cwd.join("marker");
    let ready = cwd.join("ready");
    let script = format!(
        "trap 'printf forwarded > {}; exit {exit_code}' {trap_name}; touch {}; while true; do sleep 1; done",
        marker.display(),
        ready.display()
    );
    let policy = format!(
        r#"{{"cwd":"{}","command":["sh","-c",{}],"filesystem":{{"writable":["."]}},"stdio":"piped"}}"#,
        cwd.display(),
        serde_json::to_string(&script).expect("script serializes")
    );
    let mut child = sandbox()
        .args(["exec", "--policy", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sandbox command starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(policy.as_bytes())
        .expect("policy write succeeds");

    for _ in 0..40 {
        if ready.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready.exists(), "seatbelt child did not signal readiness");
    let kill_status = Command::new("kill")
        .args([signal_name, &child.id().to_string()])
        .status()
        .expect("kill command runs");
    assert!(kill_status.success());

    let status = child.wait().expect("sandbox command exits");
    let marker_contents = wait_for_file_contents(&marker, "forwarded");
    std::fs::remove_dir_all(cwd).expect("project temp dir is removed");

    assert_eq!(status.code(), Some(exit_code));
    assert_eq!(marker_contents, "forwarded");
}

#[cfg(target_os = "macos")]
#[test]
fn sighup_is_forwarded_to_seatbelt_child() {
    assert_seatbelt_signal_is_forwarded("-HUP", "HUP", 45);
}

#[cfg(target_os = "macos")]
#[test]
fn sigint_is_forwarded_to_seatbelt_child() {
    assert_seatbelt_signal_is_forwarded("-INT", "INT", 46);
}

#[cfg(target_os = "macos")]
#[test]
fn sigquit_is_forwarded_to_seatbelt_child() {
    assert_seatbelt_signal_is_forwarded("-QUIT", "QUIT", 47);
}

#[cfg(target_os = "macos")]
#[test]
fn sigterm_is_forwarded_to_seatbelt_child() {
    assert_seatbelt_signal_is_forwarded("-TERM", "TERM", 48);
}
