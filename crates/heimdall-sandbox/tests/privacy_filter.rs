//! Integration tests for `heimdall-sandbox setup` and `heimdall-sandbox privacy-filter` commands.

use std::process::Command;

fn sandbox() -> Command {
    Command::new(env!("CARGO_BIN_EXE_heimdall-sandbox"))
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
    assert!(stdout.contains("--text"));
    assert!(stdout.contains("--stdin"));
    assert!(stdout.contains("--cache-dir"));
    assert!(stdout.contains("--variant"));
    assert!(stdout.contains("--revision"));
    assert!(stdout.contains("--execution-provider"));
}

#[test]
fn redact_text_parses_correctly() {
    let output = sandbox()
        .arg("privacy-filter")
        .arg("redact")
        .arg("--text")
        .arg("email alice@example.com")
        .arg("--help")
        .output()
        .expect("privacy-filter redact --text parses");

    assert!(output.status.success());
}

#[test]
fn redact_stdin_parses_correctly() {
    let output = sandbox()
        .arg("privacy-filter")
        .arg("redact")
        .arg("--stdin")
        .arg("--help")
        .output()
        .expect("privacy-filter redact --stdin parses");

    assert!(output.status.success());
}

#[test]
fn redact_text_and_stdin_are_mutually_exclusive() {
    let output = sandbox()
        .arg("privacy-filter")
        .arg("redact")
        .arg("--text")
        .arg("hello")
        .arg("--stdin")
        .output()
        .expect("privacy-filter redact with both flags runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--text") || stderr.contains("--stdin"),
        "expected conflict error, got: {stderr}"
    );
}

#[test]
fn redact_without_text_or_stdin_is_rejected() {
    let output = sandbox()
        .arg("privacy-filter")
        .arg("redact")
        .output()
        .expect("privacy-filter redact without input runs");

    assert!(!output.status.success());
}

#[test]
fn redact_execution_provider_parses() {
    let output = sandbox()
        .arg("privacy-filter")
        .arg("redact")
        .arg("--text")
        .arg("test")
        .arg("--execution-provider")
        .arg("cpu")
        .arg("--help")
        .output()
        .expect("privacy-filter redact --execution-provider parses");

    assert!(output.status.success());
}
