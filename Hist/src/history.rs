//! Shell history readers: locate and parse history files.
//!
//! Supported formats:
//! - PowerShell PSReadLine: one command per line (`ConsoleHost_history.txt`)
//! - bash: one command per line (`~/.bash_history`)
//! - zsh extended: `: <epoch>:<elapsed>;<command>` lines (`~/.zsh_history`)

use anyhow::{Context, Result};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    PowerShell,
    Bash,
    Zsh,
}

impl Shell {
    pub fn name(self) -> &'static str {
        match self {
            Shell::PowerShell => "powershell",
            Shell::Bash => "bash",
            Shell::Zsh => "zsh",
        }
    }
}

pub struct HistoryFile {
    pub shell: Shell,
    pub path: PathBuf,
    /// Raw lines as stored (without trailing newlines).
    pub lines: Vec<String>,
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
    match shell {
        Shell::Zsh => parse_zsh_line(line),
        Shell::PowerShell | Shell::Bash => line,
    }
}

fn read_lines(path: &PathBuf) -> Result<Vec<String>> {
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
    Ok(content.lines().map(str::to_string).collect())
}

pub fn load(shell: Shell, path: PathBuf) -> Result<HistoryFile> {
    let lines = read_lines(&path)?;
    Ok(HistoryFile { shell, path, lines })
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
    fn default_paths_never_panics() {
        // Must not panic even with HOME/USERPROFILE unset.
        let _ = default_paths();
    }
}
