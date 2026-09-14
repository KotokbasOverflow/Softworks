//! Clean: back up a history file, then redact (or drop) tainted lines.
//!
//! Default mode redacts secrets in place (`***REDACTED***`) so the history
//! stays usable. `--drop-lines` removes whole lines instead.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::history::{HistoryFile, split_command};
use secdetect::redact;

/// Outcome of cleaning one history file.
#[derive(Debug)]
pub struct CleanStats {
    /// Total lines in the file.
    pub lines_total: usize,
    /// Lines redacted (or dropped with `--drop-lines`).
    pub lines_changed: usize,
    /// Where the pre-clean copy was stored (holds original secrets).
    /// `None` with `--no-backup`.
    pub backup_path: Option<PathBuf>,
}

/// Options for [`clean_history`].
#[derive(Debug, Default)]
pub struct CleanOptions {
    /// Remove whole tainted lines instead of redacting secrets.
    pub drop_lines: bool,
    /// Skip the `*.histbak.*` backup entirely (conflicts with `age_recipient`).
    pub no_backup: bool,
    /// Encrypt the backup to this age recipient (`*.histbak.*.age`).
    pub age_recipient: Option<String>,
}

fn backup_path_for(path: &Path) -> PathBuf {
    // Nanosecond stamp + pid: two cleanups within the same second must not collide.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "history".to_string());
    name.push_str(&format!(".histbak.{stamp}.{}", std::process::id()));
    path.with_file_name(name)
}

/// Refuse symlinks: cleaning through one could clobber an unexpected
/// target, and the backup would disclose secrets elsewhere.
fn ensure_not_symlink(path: &Path) -> Result<()> {
    if std::fs::symlink_metadata(path)
        .with_context(|| format!("cannot stat {}", path.display()))?
        .file_type()
        .is_symlink()
    {
        anyhow::bail!("refusing to clean symlink {}", path.display());
    }
    Ok(())
}

/// Copy `path` to a timestamped `*.histbak.*` sibling. Returns backup path.
pub fn backup(path: &Path) -> Result<PathBuf> {
    ensure_not_symlink(path)?;
    let dest = backup_path_for(path);
    std::fs::copy(path, &dest)
        .with_context(|| format!("cannot back up {} to {}", path.display(), dest.display()))?;
    restrict_backup_perms(&dest);
    Ok(dest)
}

/// Copy `path` to an age-encrypted `*.histbak.*.age` sibling.
/// Returns backup path.
pub fn backup_encrypted(path: &Path, recipient: &str) -> Result<PathBuf> {
    ensure_not_symlink(path)?;
    let plain = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let blob = secdetect::age_crypt::encrypt_to_recipient(&plain, recipient)?;
    let mut name = backup_path_for(path).into_os_string();
    name.push(".age");
    let dest = PathBuf::from(name);
    std::fs::write(&dest, &blob).with_context(|| format!("cannot write {}", dest.display()))?;
    restrict_backup_perms(&dest);
    Ok(dest)
}

#[cfg(unix)]
fn restrict_backup_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perm = std::fs::Permissions::from_mode(0o600);
    if let Err(e) = std::fs::set_permissions(path, perm) {
        eprintln!("warning: cannot chmod 0600 {}: {e:#}", path.display());
    }
}

#[cfg(not(unix))]
fn restrict_backup_perms(_path: &Path) {
    // Windows DACLs require the `windows-sys` crate to restrict beyond
    // owner-only.  Files created here inherit the parent directory's
    // default DACL (typically owner-RW only on standard user profiles).
    // If the workspace is on a shared drive the operator should ensure
    // the directory ACL is restrictive.  Documented in SECURITY.md.
}

/// Atomically replace `path` with `content` (temp file + rename in the
/// same directory, so a crash cannot leave a half-written history).
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    use std::io::Write as _;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_name = format!(
        ".{}.tmp.{}.{}.histclean",
        path.file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "history".to_string()),
        nanos,
        std::process::id()
    );
    let tmp_path = path.with_file_name(tmp_name);
    let result = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .with_context(|| format!("cannot create {}", tmp_path.display()))?;
        f.write_all(content.as_bytes())
            .context("cannot write temp history file")?;
        f.flush().context("cannot flush temp history file")?;
        f.sync_all().context("cannot fsync temp history file")?;
        drop(f);
        std::fs::rename(&tmp_path, path)
            .with_context(|| format!("cannot replace {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

/// Redact (or drop) tainted lines of an already-loaded history file.
/// Writes the file back in its original line format (zsh metadata kept).
/// With `no_backup` no `*.histbak.*` copy is made (cannot be undone);
/// with `age_recipient` the backup is age-encrypted (`*.histbak.*.age`).
pub fn clean_history(h: &HistoryFile, opts: &CleanOptions) -> Result<CleanStats> {
    if opts.no_backup && opts.age_recipient.is_some() {
        anyhow::bail!("--no-backup conflicts with --backup-age-recipient");
    }
    let backup_path = if opts.no_backup {
        None
    } else if let Some(recipient) = &opts.age_recipient {
        Some(backup_encrypted(&h.path, recipient)?)
    } else {
        Some(backup(&h.path)?)
    };

    let mut changed = 0usize;
    let mut out_lines: Vec<String> = Vec::with_capacity(h.lines.len());
    for raw in &h.lines {
        let (prefix, cmd, suffix) = split_command(h.shell, raw);
        let (redacted_cmd, matched) = redact(cmd);
        if matched.is_empty() {
            out_lines.push(raw.clone());
            continue;
        }
        changed += 1;
        if opts.drop_lines {
            continue;
        }
        // Preserve the original stored format (e.g. zsh `: ts;` prefix)
        // and surrounding whitespace; only the secret itself is replaced.
        out_lines.push(format!("{prefix}{redacted_cmd}{suffix}"));
    }

    let mut content = out_lines.join("\n");
    if h.trailing_newline {
        content.push('\n');
    }
    atomic_write(&h.path, &content)?;

    Ok(CleanStats {
        lines_total: h.lines.len(),
        lines_changed: changed,
        backup_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::Shell;

    fn write_temp(lines: &[&str]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_history");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        (dir, path)
    }

    fn load(shell: Shell, path: &Path) -> HistoryFile {
        crate::history::load(shell, path.to_path_buf()).unwrap()
    }

    #[test]
    fn clean_redacts_and_backs_up() {
        let (_dir, path) = write_temp(&["ls", "password=hunter2", "echo ok"]);
        let h = load(Shell::Bash, &path);
        let stats = clean_history(&h, &CleanOptions::default()).unwrap();
        assert_eq!(stats.lines_total, 3);
        assert_eq!(stats.lines_changed, 1);
        assert!(stats.backup_path.as_ref().is_some_and(|f| f.is_file()));

        let after = std::fs::read_to_string(&path).unwrap();
        assert!(!after.contains("hunter2"));
        assert!(after.contains("***REDACTED***"));
        // Backup still holds the original (user restores manually if needed).
        let backup = std::fs::read_to_string(stats.backup_path.as_ref().unwrap()).unwrap();
        assert!(backup.contains("hunter2"));
    }

    #[test]
    fn clean_drop_lines_removes_tainted() {
        let (_dir, path) = write_temp(&["ls", "password=hunter2"]);
        let h = load(Shell::Bash, &path);
        let stats = clean_history(
            &h,
            &CleanOptions {
                drop_lines: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(stats.lines_changed, 1);
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(!after.contains("hunter2"));
        assert!(!after.contains("REDACTED"));
    }

    #[test]
    fn clean_keeps_zsh_metadata() {
        let (_dir, path) = write_temp(&[": 1690000000:0;password=hunter2"]);
        let h = load(Shell::Zsh, &path);
        clean_history(&h, &CleanOptions::default()).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.starts_with(": 1690000000:0;"));
        assert!(!after.contains("hunter2"));
    }

    #[test]
    fn backup_names_are_unique() {
        let (_dir, path) = write_temp(&["ls"]);
        let a = backup(&path).unwrap();
        let b = backup(&path).unwrap();
        assert_ne!(a, b);
        assert!(a.is_file() && b.is_file());
    }

    #[test]
    fn clean_preserves_whitespace_and_newline_style() {
        let dir = tempfile::tempdir().unwrap();
        // Trailing spaces + no trailing newline must survive the rewrite.
        let path = dir.path().join("h");
        std::fs::write(&path, "ls  \n  password=hunter2  ").unwrap();
        let h = load(Shell::Bash, &path);
        clean_history(&h, &CleanOptions::default()).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, "ls  \n  ***REDACTED***  ");
    }

    #[test]
    fn clean_no_backup_skips_histbak() {
        let (_dir, path) = write_temp(&["ls", "password=hunter2"]);
        let h = load(Shell::Bash, &path);
        let stats = clean_history(
            &h,
            &CleanOptions {
                no_backup: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(stats.lines_changed, 1);
        assert!(stats.backup_path.is_none());
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(!after.contains("hunter2"));
    }

    #[test]
    fn clean_encrypted_backup_roundtrips() {
        use age::secrecy::ExposeSecret;
        let id = age::x25519::Identity::generate();
        let recipient = id.to_public().to_string();
        let (_dir, path) = write_temp(&["ls", "password=hunter2"]);
        let h = load(Shell::Bash, &path);
        let stats = clean_history(
            &h,
            &CleanOptions {
                age_recipient: Some(recipient),
                ..Default::default()
            },
        )
        .unwrap();
        let backup = stats.backup_path.expect("encrypted backup expected");
        assert_eq!(backup.extension().and_then(|e| e.to_str()), Some("age"));
        // No plaintext residue in the backup file.
        let blob = std::fs::read(&backup).unwrap();
        assert!(secdetect::age_crypt::is_age_blob(&blob));
        assert!(!blob.windows(7).any(|w| w == b"hunter2"));
        // ...but it decrypts back to the original.
        let secret = id.to_string();
        let plain =
            secdetect::age_crypt::decrypt_with_identity(&blob, secret.expose_secret()).unwrap();
        assert!(String::from_utf8_lossy(&plain).contains("hunter2"));
        // Working file redacted as usual.
        assert!(!std::fs::read_to_string(&path).unwrap().contains("hunter2"));
    }

    #[test]
    fn clean_no_backup_conflicts_with_recipient() {
        let (_dir, path) = write_temp(&["ls", "password=hunter2"]);
        let h = load(Shell::Bash, &path);
        let err = clean_history(
            &h,
            &CleanOptions {
                no_backup: true,
                age_recipient: Some(
                    "age1ql3z7hj432v2jl2z8alunwwun8hm4s4fjljxlxeq9w3y6sms0r99t8".into(),
                ),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("conflicts"));
    }

    #[test]
    fn clean_rejects_symlinks() {
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let real = dir.path().join("real");
            std::fs::write(&real, "password=hunter2\n").unwrap();
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            let h = load(Shell::Bash, &link);
            assert!(clean_history(&h, &CleanOptions::default()).is_err());
            // Target untouched.
            assert!(std::fs::read_to_string(&real).unwrap().contains("hunter2"));
        }
    }
}
