//! Shell history readers: locate and parse history files.
//!
//! Supported formats:
//! - PowerShell PSReadLine: one command per line (`ConsoleHost_history.txt`)
//! - bash: one command per line (`~/.bash_history`)
//! - zsh extended: `: <epoch>:<elapsed>;<command>` lines (`~/.zsh_history`)

use anyhow::{Context, Result};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Supported shell history formats.
pub enum Shell {
    /// PowerShell PSReadLine (one command per line).
    PowerShell,
    /// bash (one command per line).
    Bash,
    /// zsh extended history (`: <epoch>:<elapsed>;<command>`).
    Zsh,
}

impl Shell {
    /// Stable lowercase name (`"powershell"`, `"bash"`, `"zsh"`).
    pub fn name(self) -> &'static str {
        match self {
            Shell::PowerShell => "powershell",
            Shell::Bash => "bash",
            Shell::Zsh => "zsh",
        }
    }
}

/// A loaded history file: parsed format, raw lines, newline style.
pub struct HistoryFile {
    /// Shell format the file was parsed with.
    pub shell: Shell,
    /// Path of the history file.
    pub path: PathBuf,
    /// Raw lines as stored (without trailing newlines).
    pub lines: Vec<String>,
    /// Whether the file ended with a newline (preserved by `clean`).
    pub trailing_newline: bool,
}

/// Strip zsh extended-history metadata (`: 1234567890:0;cmd` → `cmd`).
/// Plain lines pass through unchanged.
pub fn parse_zsh_line(line: &str) -> &str {
    // No let-chains: keep MSRV 1.85.
    match line.strip_prefix(": ") {
        Some(rest) => match rest.find(';') {
            Some(semi) => rest[semi + 1..].trim(),
            None => line,
        },
        None => line,
    }
}

/// Normalize a stored line to the command text for a given shell.
pub fn command_text(shell: Shell, line: &str) -> &str {
    split_command(shell, line).1
}

/// Split a stored line into `(prefix, command, suffix)`.
///
/// `command` is trimmed (metadata stripped, whitespace trimmed) for
/// detection; `prefix` + `suffix` restore the original layout so `clean`
/// rewrites the line faithfully instead of normalizing whitespace.
pub fn split_command(shell: Shell, line: &str) -> (&str, &str, &str) {
    let (body_off, body) = match shell {
        Shell::Zsh => match line.strip_prefix(": ") {
            // +2 for ": ", +1 to step past ';' (first one ends the metadata).
            Some(rest) => match rest.find(';') {
                Some(semi) => (2 + semi + 1, &rest[semi + 1..]),
                None => (0, line),
            },
            None => (0, line),
        },
        Shell::PowerShell | Shell::Bash => (0, line),
    };
    let trimmed = body.trim();
    // ASCII whitespace only, so byte arithmetic stays on char boundaries.
    let leading = body.len() - body.trim_start().len();
    let trailing = body.len() - leading - trimmed.len();
    let prefix = line.get(..body_off + leading).unwrap_or("");
    let suffix = body.get(body.len() - trailing..).unwrap_or("");
    (prefix, trimmed, suffix)
}

fn read_lines(path: &PathBuf) -> Result<(Vec<String>, bool)> {
    // DoS guard: refuse to slurp huge history files into memory.
    const MAX_HISTORY_BYTES: u64 = 20 * 1024 * 1024;
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_HISTORY_BYTES {
            anyhow::bail!(
                "history file {} is {} bytes (limit {}): pass a smaller file explicitly",
                path.display(),
                meta.len(),
                MAX_HISTORY_BYTES
            );
        }
    }
    let content =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    if content.len() as u64 > MAX_HISTORY_BYTES {
        anyhow::bail!(
            "history file {} exceeds {} bytes after decoding",
            path.display(),
            MAX_HISTORY_BYTES
        );
    }
    Ok((
        content.lines().map(str::to_string).collect(),
        content.ends_with('\n'),
    ))
}

/// Load a history file for `shell` from `path` (20 MiB size guard).
pub fn load(shell: Shell, path: PathBuf) -> Result<HistoryFile> {
    let (lines, trailing_newline) = read_lines(&path)?;
    Ok(HistoryFile {
        shell,
        path,
        lines,
        trailing_newline,
    })
}

fn home() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
}

/// Default history locations per shell on this machine.
/// Missing files are skipped (not an error).
pub fn default_paths() -> Vec<(Shell, PathBuf)> {
    let mut out = Vec::new();
    if let Some(home) = home() {
        // PowerShell 7+ (all OSes).
        out.push((
            Shell::PowerShell,
            home.join(".config/powershell/ConsoleHost_history.txt"),
        ));
        // Windows PowerShell 5.1.
        if cfg!(windows) {
            if let Some(appdata) = std::env::var_os("APPDATA").map(PathBuf::from) {
                out.push((
                    Shell::PowerShell,
                    appdata.join("Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"),
                ));
            }
        }
        out.push((Shell::Bash, home.join(".bash_history")));
        out.push((Shell::Zsh, home.join(".zsh_history")));
    }
    out.into_iter().filter(|(_, p)| p.is_file()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zsh_extended_lines_parse() {
        assert_eq!(parse_zsh_line(": 1690000000:0;git status"), "git status");
        assert_eq!(parse_zsh_line(": 1690000000:12;echo a;b"), "echo a;b");
    }

    #[test]
    fn plain_lines_pass_through() {
        assert_eq!(parse_zsh_line("ls -la"), "ls -la");
        assert_eq!(parse_zsh_line(": not-a-timestamp"), ": not-a-timestamp");
        assert_eq!(command_text(Shell::Bash, "ls"), "ls");
    }

    #[test]
    fn oversized_history_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.history");
        // Sparse-ish: 21 MiB of newlines trips the metadata fast-path
        // without meaningful IO cost.
        std::fs::write(&path, "a\n".repeat(21 * 1024 * 1024 / 2)).unwrap();
        assert!(load(Shell::Bash, path).is_err());
    }

    #[test]
    fn default_paths_never_panics() {
        // Must not panic even with HOME/USERPROFILE unset.
        let _ = default_paths();
    }

    #[test]
    fn split_command_preserves_layout() {
        // Leading/trailing whitespace survives; detection sees trimmed cmd.
        let (pre, cmd, suf) = split_command(Shell::Bash, "  password=hunter2  ");
        assert_eq!(cmd, "password=hunter2");
        assert_eq!(format!("{pre}{cmd}{suf}"), "  password=hunter2  ");
        // zsh metadata + inner spacing.
        let (pre, cmd, suf) = split_command(Shell::Zsh, ": 1690000000:0;  password=hunter2\t");
        assert_eq!(pre, ": 1690000000:0;  ");
        assert_eq!(cmd, "password=hunter2");
        assert_eq!(suf, "\t");
        // Plain lines round-trip exactly.
        for line in ["ls -la", ": not-a-timestamp"] {
            let (pre, cmd, suf) = split_command(Shell::Zsh, line);
            assert_eq!(format!("{pre}{cmd}{suf}"), line);
        }
    }

    #[test]
    fn load_records_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = dir.path().join("h1");
        let p2 = dir.path().join("h2");
        std::fs::write(&p1, "a\nb\n").unwrap();
        std::fs::write(&p2, "a\nb").unwrap();
        assert!(load(Shell::Bash, p1).unwrap().trailing_newline);
        assert!(!load(Shell::Bash, p2).unwrap().trailing_newline);
    }
}
