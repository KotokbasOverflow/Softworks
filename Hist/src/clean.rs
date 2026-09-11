//! Clean: back up a history file, then redact (or drop) tainted lines.
//!
//! Default mode redacts secrets in place (`***REDACTED***`) so the history
//! stays usable. `--drop-lines` removes whole lines instead.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::detectors::redact;
use crate::history::{HistoryFile, command_text};

pub struct CleanStats {
    pub lines_total: usize,
    pub lines_changed: usize,
    pub backup_path: PathBuf,
}

fn backup_path_for(path: &Path) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "history".to_string());
    name.push_str(&format!(".histbak.{stamp}"));
    path.with_file_name(name)
}

/// Copy `path` to a timestamped `*.histbak.*` sibling. Returns backup path.
pub fn backup(path: &Path) -> Result<PathBuf> {
    let dest = backup_path_for(path);
    std::fs::copy(path, &dest)
        .with_context(|| format!("cannot back up {} to {}", path.display(), dest.display()))?;
    Ok(dest)
}

/// Redact (or drop) tainted lines of an already-loaded history file.
/// Writes the file back in its original line format (zsh metadata kept).
pub fn clean_history(h: &HistoryFile, drop_lines: bool) -> Result<CleanStats> {
    let backup_path = backup(&h.path)?;

    let mut changed = 0usize;
    let mut out_lines: Vec<String> = Vec::with_capacity(h.lines.len());
    for raw in &h.lines {
        let cmd = command_text(h.shell, raw);
        let (redacted_cmd, matched) = redact(cmd);
        if matched.is_empty() {
            out_lines.push(raw.clone());
            continue;
        }
        changed += 1;
        if drop_lines {
            continue;
        }
        // Preserve the original stored format (e.g. zsh `: ts;` prefix).
        let prefix_len = raw.len() - cmd.len();
        out_lines.push(format!("{}{}", &raw[..prefix_len], redacted_cmd));
    }

    let mut content = out_lines.join("\n");
    if !h.lines.is_empty() {
        content.push('\n');
    }
    std::fs::write(&h.path, content)
        .with_context(|| format!("cannot rewrite {}", h.path.display()))?;

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
        let stats = clean_history(&h, false).unwrap();
        assert_eq!(stats.lines_total, 3);
        assert_eq!(stats.lines_changed, 1);
        assert!(stats.backup_path.is_file());

        let after = std::fs::read_to_string(&path).unwrap();
        assert!(!after.contains("hunter2"));
        assert!(after.contains("***REDACTED***"));
        // Backup still holds the original (user restores manually if needed).
        let backup = std::fs::read_to_string(&stats.backup_path).unwrap();
        assert!(backup.contains("hunter2"));
    }

    #[test]
    fn clean_drop_lines_removes_tainted() {
        let (_dir, path) = write_temp(&["ls", "password=hunter2"]);
        let h = load(Shell::Bash, &path);
        let stats = clean_history(&h, true).unwrap();
        assert_eq!(stats.lines_changed, 1);
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(!after.contains("hunter2"));
        assert!(!after.contains("REDACTED"));
    }

    #[test]
    fn clean_keeps_zsh_metadata() {
        let (_dir, path) = write_temp(&[": 1690000000:0;password=hunter2"]);
        let h = load(Shell::Zsh, &path);
        clean_history(&h, false).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.starts_with(": 1690000000:0;"));
        assert!(!after.contains("hunter2"));
    }
}
