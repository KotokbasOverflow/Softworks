//! Black-box CLI tests: flags, validation, conflicts, Unicode handling.

use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    Command::cargo_bin("password-generator").unwrap()
}

fn stdout_line(cmd: &mut Command) -> String {
    let out = cmd.assert().success().get_output().stdout.clone();
    String::from_utf8(out).unwrap()
}

#[test]
fn help_lists_key_flags() {
    bin()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--include-ambiguous"))
        .stdout(predicate::str::contains("--passphrase"))
        .stdout(predicate::str::contains("--custom"));
}

#[test]
fn generates_password_of_requested_length() {
    let stdout = stdout_line(bin().args(["-l", "16"]));
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].chars().count(), 16);
}

#[test]
fn count_zero_is_rejected() {
    bin()
        .args(["-l", "10", "--count", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--count must be positive"));
}

#[test]
fn custom_conflicts_with_charset_flags() {
    // clap usage error (exit code 2), not a runtime error.
    bin()
        .args(["--custom", "abc", "-a", "-l", "10"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn unicode_custom_charset_works() {
    // Regression: the old byte-based implementation errored on multi-byte sets.
    let stdout = stdout_line(bin().args(["--custom", "éüäöåβ✓", "-l", "12"]));
    let line = stdout.lines().next().unwrap();
    assert_eq!(line.chars().count(), 12);
    assert!(line.chars().all(|c| "éüäöåβ✓".contains(c)));
}

#[test]
fn empty_custom_is_rejected() {
    bin()
        .args(["--custom", "", "-l", "10"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Custom set cannot be empty"));
}

#[test]
fn passphrase_word_count() {
    // Space separator: unambiguous even with EFF's 4 hyphenated words.
    let stdout = stdout_line(bin().args(["-p", "-w", "3", "--separator", " "]));
    assert_eq!(stdout.lines().next().unwrap().split(' ').count(), 3);
}

#[test]
fn old_no_ambiguous_alias_still_works() {
    bin()
        .args(["-l", "12", "--no-ambiguous"])
        .assert()
        .success();
}

#[test]
fn no_print_without_copy_is_rejected_by_clap() {
    bin()
        .args(["-l", "10", "--no-print"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn no_print_with_copy_passes_parsing() {
    bin()
        .args(["-l", "10", "--no-print", "--copy"])
        .assert()
        // --copy needs a display clipboard; on headless CI this fails at
        // clipboard access, but flag parsing itself must succeed past clap.
        // Either outcome is acceptable except a clap usage error (exit 2).
        .code(predicate::ne(2));
}

#[test]
fn copy_with_multiple_count_is_rejected() {
    bin()
        .args(["-l", "10", "--count", "2", "--copy"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ambiguous"));
}

#[test]
fn show_entropy_goes_to_stderr() {
    bin()
        .args(["-l", "16", "--show-entropy"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Estimated entropy"));
}

#[test]
fn multiple_passwords_print_count_lines() {
    let stdout = stdout_line(bin().args(["-l", "8", "--count", "3"]));
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines.iter().all(|l| l.chars().count() == 8));
}
