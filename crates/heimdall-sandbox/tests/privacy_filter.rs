//! Integration tests for `heimdall-sandbox setup` and `heimdall-sandbox privacy-filter` commands.

use std::io::Write;
use std::process::{Command, Stdio};

fn sandbox() -> Command {
    Command::new(env!("CARGO_BIN_EXE_heimdall-sandbox"))
}

fn temp_input_path(name: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "heimdall-privacy-filter-{name}-{}-{}.txt",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    path
}

#[test]
fn setup_help_shows_expected_flags() {
    let output = sandbox()
        .arg("setup")
        .arg("--help")
        .output()
        .expect("setup --help runs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--force"));
    assert!(stdout.contains("--cache-dir"));
    assert!(stdout.contains("--variant"));
    assert!(stdout.contains("--revision"));
}

#[test]
fn setup_defaults_to_q4_variant() {
    let output = sandbox()
        .arg("setup")
        .arg("--help")
        .output()
        .expect("setup --help runs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("q4"));
}

#[test]
fn setup_accepts_fp16_variant() {
    let output = sandbox()
        .arg("setup")
        .arg("--variant")
        .arg("fp16")
        .arg("--help")
        .output()
        .expect("setup --variant fp16 --help runs");

    assert!(output.status.success());
}

#[test]
fn setup_accepts_force_flag() {
    let output = sandbox()
        .arg("setup")
        .arg("--force")
        .arg("--help")
        .output()
        .expect("setup --force --help runs");

    assert!(output.status.success());
}

#[test]
fn redact_help_shows_expected_flags() {
    let output = sandbox()
        .arg("privacy-filter")
        .arg("redact")
        .arg("--help")
        .output()
        .expect("privacy-filter redact --help runs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("TEXT_OR_FILE"));
    assert!(stdout.contains("--cache-dir"));
    assert!(stdout.contains("--variant"));
    assert!(stdout.contains("--revision"));
    assert!(stdout.contains("--execution-provider"));
}

#[test]
fn redact_positional_text_parses() {
    let output = sandbox()
        .arg("privacy-filter")
        .arg("redact")
        .arg("email alice@example.com")
        .arg("--help")
        .output()
        .expect("privacy-filter redact with positional text parses");

    assert!(output.status.success());
}

#[test]
fn redact_empty_stdin_is_rejected() {
    let mut child = sandbox()
        .arg("privacy-filter")
        .arg("redact")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sandbox command starts");
    // Close stdin immediately to provide empty input.
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("sandbox command exits");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("empty"),
        "expected 'empty' error, got: {stderr}"
    );
}

#[test]
fn redact_reads_from_stdin() {
    let mut child = sandbox()
        .arg("privacy-filter")
        .arg("redact")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sandbox command starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(b"alice@example.com")
        .expect("stdin write succeeds");

    let output = child.wait_with_output().expect("sandbox command exits");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[REDACTED:"),
        "expected redaction in output, got: {stdout}"
    );
}

#[test]
fn redact_reads_long_stdin_without_truncating_tail() {
    let text = format!("{} alice@example.com tail-marker", "filler ".repeat(2_000));
    let mut child = sandbox()
        .arg("privacy-filter")
        .arg("redact")
        .arg("--test-usable-token-limit")
        .arg("32")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sandbox command starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(text.as_bytes())
        .expect("stdin write succeeds");

    let output = child.wait_with_output().expect("sandbox command exits");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("tail-marker"), "got: {stdout}");
    assert!(!stdout.contains("alice@example.com"), "got: {stdout}");
}

#[test]
fn redact_reads_long_file_without_truncating_tail() {
    let path = temp_input_path("file");
    let text = format!("{} alice@example.com tail-marker", "filler ".repeat(2_000));
    std::fs::write(&path, text).expect("write temp input");

    let output = sandbox()
        .arg("privacy-filter")
        .arg("redact")
        .arg("--test-usable-token-limit")
        .arg("32")
        .arg(&path)
        .output()
        .expect("sandbox command runs");
    let _ = std::fs::remove_file(&path);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("tail-marker"), "got: {stdout}");
    assert!(!stdout.contains("alice@example.com"), "got: {stdout}");
}

#[test]
fn redact_execution_provider_parses() {
    let output = sandbox()
        .arg("privacy-filter")
        .arg("redact")
        .arg("--execution-provider")
        .arg("cpu")
        .arg("test")
        .arg("--help")
        .output()
        .expect("privacy-filter redact --execution-provider parses");

    assert!(output.status.success());
}
