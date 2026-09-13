//! Black-box CLI tests (fake secrets only).

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

fn bin() -> Command {
    Command::cargo_bin("snip").unwrap()
}

fn db_dir() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("snips.db");
    (dir, db)
}

#[test]
fn add_refuses_secret_without_force() {
    let (_dir, db) = db_dir();
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["add", "leak", "--", "export TOKEN=ghp_fixturetokenABC"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to store"))
        .stderr(predicate::str::contains("github-token"));
}

#[test]
fn add_force_stores_and_list_redacts() {
    let (_dir, db) = db_dir();
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["add", "leak", "--force", "--", "password=hunter2"])
        .assert()
        .success();

    bin()
        .args(["--db"])
        .arg(&db)
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("leak"))
        .stdout(predicate::str::contains("***REDACTED***"))
        .stdout(predicate::str::contains("hunter2").not());
}

#[test]
fn import_refuses_secret_without_force() {
    let (_dir, db) = db_dir();
    let export = _dir.path().join("export.json");
    std::fs::write(
        &export,
        r#"[{"name":"bad","command":"token=ghp_fixturetokenXYZ","description":"","tags":[],"created_at":0,"updated_at":0,"use_count":0}]"#,
    )
    .unwrap();

    bin()
        .args(["--db"])
        .arg(&db)
        .args(["import", "--file"])
        .arg(&export)
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to store"));
}

#[test]
fn import_force_stores_secret() {
    let (_dir, db) = db_dir();
    let export = _dir.path().join("export.json");
    std::fs::write(
        &export,
        r#"[{"name":"bad","command":"password=hunter2","description":"","tags":[],"created_at":0,"updated_at":0,"use_count":0}]"#,
    )
    .unwrap();

    bin()
        .args(["--db"])
        .arg(&db)
        .args(["import", "--force", "--file"])
        .arg(&export)
        .assert()
        .success()
        .stdout(predicate::str::contains("imported 1"));

    bin()
        .args(["--db"])
        .arg(&db)
        .args(["get", "bad"])
        .assert()
        .success()
        .stdout(predicate::str::contains("password=hunter2"));
}

#[test]
fn import_clean_snippet_ok() {
    let (_dir, db) = db_dir();
    let export = _dir.path().join("export.json");
    std::fs::write(
        &export,
        r#"[{"name":"ok","command":"cargo test","description":"","tags":[],"created_at":0,"updated_at":0,"use_count":0}]"#,
    )
    .unwrap();

    bin()
        .args(["--db"])
        .arg(&db)
        .args(["import", "--file"])
        .arg(&export)
        .assert()
        .success()
        .stdout(predicate::str::contains("imported 1"));
}

#[test]
fn exec_dry_run_prints_without_running() {
    let (_dir, db) = db_dir();
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["add", "hi", "--", "echo", "hello"])
        .assert()
        .success();

    bin()
        .args(["--db"])
        .arg(&db)
        .args(["exec", "hi", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("echo hello"));
}

#[test]
fn exec_warns_on_forced_secret() {
    let (_dir, db) = db_dir();
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["add", "leak", "--force", "--", "echo", "password=hunter2"])
        .assert()
        .success();

    bin()
        .args(["--db"])
        .arg(&db)
        .args(["exec", "leak", "--yes"])
        .assert()
        .success()
        .stderr(predicate::str::contains("looks like it contains secret"))
        .stderr(predicate::str::contains("password-assign"));
}

#[test]
fn import_rejects_oversized_file() {
    let (_dir, db) = db_dir();
    let export = _dir.path().join("big.json");
    // 11 MiB of filler: the size guard fires before JSON parsing.
    std::fs::write(&export, "x".repeat(11 * 1024 * 1024)).unwrap();

    bin()
        .args(["--db"])
        .arg(&db)
        .args(["import", "--file"])
        .arg(&export)
        .assert()
        .failure()
        .stderr(predicate::str::contains("limit"));
}
