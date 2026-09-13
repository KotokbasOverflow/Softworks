//! Black-box CLI tests on fixture history files (fake secrets only).

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn bin() -> Command {
    Command::cargo_bin("hist").unwrap()
}

#[test]
fn scan_clean_file_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clean.history");
    std::fs::write(&path, "ls -la\ncargo test\n").unwrap();
    bin()
        .args(["scan", "--history"])
        .arg(&path)
        .assert()
        .success();
}

#[test]
fn scan_fixture_finds_secrets_and_exits_one() {
    bin()
        .args(["scan", "--history"])
        .arg(fixture("bash.history"))
        .assert()
        .failure()
        .code(1)
        // Findings reported, secrets themselves never printed.
        .stdout(predicate::str::contains("aws-access-key"))
        .stdout(predicate::str::contains("github-token"))
        .stdout(predicate::str::contains("***REDACTED***"))
        .stdout(predicate::str::contains("AKIAIOSFODNN7EXAMPLE").not())
        .stdout(predicate::str::contains("ghp_fixturetoken").not());
}

#[test]
fn scan_json_format() {
    bin()
        .args(["scan", "--history"])
        .arg(fixture("bash.history"))
        .args(["--format", "json"])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("\"detectors\""))
        .stdout(predicate::str::contains("AKIAIOSFODNN7EXAMPLE").not());
}

#[test]
fn scan_understands_zsh_format() {
    bin()
        .args(["scan", "--history"])
        .arg(fixture("zsh.history"))
        .args(["--shell", "zsh"])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("bearer-token"))
        .stdout(predicate::str::contains("url-credentials"));
}

#[test]
fn scan_powershell_fixture() {
    bin()
        .args(["scan", "--history"])
        .arg(fixture("ps.history"))
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("password-assign"))
        .stdout(predicate::str::contains("hunter2").not());
}

#[test]
fn clean_dry_run_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("h.history");
    std::fs::write(&path, "ls\npassword=hunter2\n").unwrap();

    bin()
        .args(["clean", "--history"])
        .arg(&path)
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("would change"));

    // File untouched, no backup created.
    assert!(std::fs::read_to_string(&path).unwrap().contains("hunter2"));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn clean_redacts_and_backs_up() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("h.history");
    std::fs::write(&path, "ls\npassword=hunter2\n").unwrap();

    bin()
        .args(["clean", "--history"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("1/2 lines changed"));

    let after = std::fs::read_to_string(&path).unwrap();
    assert!(!after.contains("hunter2"));
    assert!(after.contains("***REDACTED***"));
    // Original + backup = 2 files.
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn clean_dry_run_counts_lines_not_findings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("h.history");
    // One line, two detectors (password-assign + aws-access-key) — still a
    // single finding, matching `clean_history`'s `lines_changed`.
    std::fs::write(&path, "ls\npassword=hunter2 AKIAIOSFODNN7EXAMPLE\n").unwrap();

    bin()
        .args(["clean", "--history"])
        .arg(&path)
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "1 line(s) would change (1 finding(s))",
        ));

    // File untouched, no backup created.
    assert!(std::fs::read_to_string(&path).unwrap().contains("hunter2"));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn clean_no_backup_leaves_single_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("h.history");
    std::fs::write(&path, "ls\npassword=hunter2\n").unwrap();

    bin()
        .args(["clean", "--history"])
        .arg(&path)
        .arg("--no-backup")
        .assert()
        .success()
        .stdout(predicate::str::contains("no backup (--no-backup)"));

    assert!(!std::fs::read_to_string(&path).unwrap().contains("hunter2"));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn clean_missing_file_fails() {
    bin()
        .args(["scan", "--history", "no-such-file.history"])
        .assert()
        .failure()
        .code(1);
}

#[test]
fn detectors_lists_all() {
    bin()
        .arg("detectors")
        .assert()
        .success()
        .stdout(predicate::str::contains("aws-access-key"))
        .stdout(predicate::str::contains("password-assign"));
}
