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

fn keypair() -> (String, String) {
    use age::secrecy::ExposeSecret;
    let id = age::x25519::Identity::generate();
    (
        id.to_public().to_string(),
        id.to_string().expose_secret().to_owned(),
    )
}

fn write_identity(dir: &tempfile::TempDir, secret: &str) -> PathBuf {
    let path = dir.path().join("identity.txt");
    std::fs::write(&path, format!("# test identity\n{secret}\n")).unwrap();
    path
}

#[test]
fn export_encrypted_hides_plaintext_and_imports_back() {
    let (recipient, identity) = keypair();
    let (_dir, db) = db_dir();
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["add", "deploy", "--", "ssh", "prod", "uptime"])
        .assert()
        .success();

    let export = _dir.path().join("export.age");
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["export", "--file"])
        .arg(&export)
        .args(["--age-recipient"])
        .arg(&recipient)
        .assert()
        .success()
        .stdout(predicate::str::contains("age-encrypted"));

    // Opaque blob: no plaintext residue.
    let blob = std::fs::read(&export).unwrap();
    assert!(secdetect::age_crypt::is_age_blob(&blob));
    assert!(!blob.windows(4).any(|w| w == b"prod"));

    // Roundtrip into a fresh database via the identity file.
    let (_dir2, db2) = db_dir();
    let id_file = write_identity(&_dir2, &identity);
    bin()
        .args(["--db"])
        .arg(&db2)
        .args(["import", "--file"])
        .arg(&export)
        .args(["--age-identity"])
        .arg(&id_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("imported 1"));

    bin()
        .args(["--db"])
        .arg(&db2)
        .args(["get", "deploy"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ssh prod uptime"));
}

#[test]
fn import_encrypted_without_identity_fails_cleanly() {
    let (recipient, _) = keypair();
    let (_dir, db) = db_dir();
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["add", "x", "--", "echo", "hi"])
        .assert()
        .success();

    let export = _dir.path().join("export.age");
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["export", "--file"])
        .arg(&export)
        .args(["--age-recipient"])
        .arg(&recipient)
        .assert()
        .success();

    // Key-encrypted blob, no identity: hard error, nothing imported.
    let (_dir2, db2) = db_dir();
    bin()
        .args(["--db"])
        .arg(&db2)
        .args(["import", "--file"])
        .arg(&export)
        .assert()
        .failure()
        .stderr(predicate::str::contains("--age-identity"));
}

#[test]
fn encrypted_db_full_session_flow() {
    let (recipient, identity) = keypair();
    let (_dir, db) = db_dir();
    let id_file = write_identity(&_dir, &identity);

    // Encrypted init: the file is an age blob from the start.
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["init", "--age-recipient"])
        .arg(&recipient)
        .assert()
        .success()
        .stdout(predicate::str::contains("initialized"));
    let blob = std::fs::read(&db).unwrap();
    assert!(secdetect::age_crypt::is_age_blob(&blob));

    // add/get/list work with the identity file...
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["--age-identity"])
        .arg(&id_file)
        .args(["add", "deploy", "--", "ssh", "prod", "uptime"])
        .assert()
        .success();
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["--age-identity"])
        .arg(&id_file)
        .args(["get", "deploy"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ssh prod uptime"));

    // ...stay encrypted on disk with no plaintext residue...
    let blob = std::fs::read(&db).unwrap();
    assert!(secdetect::age_crypt::is_age_blob(&blob));
    assert!(!blob.windows(4).any(|w| w == b"prod"));

    // ...and refuse to open without the key.
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["get", "deploy"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--age-identity"));

    // Wrong identity fails closed too.
    let (_, other_identity) = keypair();
    let bad_id = write_identity(&_dir, &other_identity);
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["--age-identity"])
        .arg(&bad_id)
        .args(["get", "deploy"])
        .assert()
        .failure();
}

#[test]
fn encrypted_init_refuses_existing_plaintext() {
    let (recipient, _) = keypair();
    let (_dir, db) = db_dir();
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["add", "x", "--", "echo", "hi"])
        .assert()
        .success();
    bin()
        .args(["--db"])
        .arg(&db)
        .args(["init", "--age-recipient"])
        .arg(&recipient)
        .assert()
        .failure()
        .stderr(predicate::str::contains("export"));
}
