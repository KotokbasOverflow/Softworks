//! Scan: run detectors over history files, collect [`Finding`]s.

use crate::detectors::redact;
use crate::finding::Finding;
use crate::history::{HistoryFile, command_text};

/// Scan one loaded history file.
pub fn scan_history(h: &HistoryFile) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, line) in h.lines.iter().enumerate() {
        let cmd = command_text(h.shell, line);
        let (redacted, matched) = redact(cmd);
        if !matched.is_empty() {
            out.push(Finding {
                file: h.path.clone(),
                shell: h.shell.name(),
                line_no: i + 1,
                detectors: matched,
                preview: truncate(&redacted, 120),
            });
        }
    }
    out
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    s.chars().take(max_chars).collect::<String>() + "…"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::Shell;
    use std::path::PathBuf;

    fn hist(shell: Shell, lines: &[&str]) -> HistoryFile {
        HistoryFile {
            shell,
            path: PathBuf::from("test.history"),
            lines: lines.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn scan_finds_and_numbers_lines() {
        let h = hist(
            Shell::Bash,
            &["ls -la", "export TOKEN=ghp_abcDEF", "echo done"],
        );
        let findings = scan_history(&h);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line_no, 2);
        assert!(!findings[0].preview.contains("ghp_abcDEF"));
    }

    #[test]
    fn scan_clean_file_has_no_findings() {
        let h = hist(Shell::Bash, &["ls", "cargo test"]);
        assert!(scan_history(&h).is_empty());
    }

    #[test]
    fn scan_understands_zsh_format() {
        let h = hist(
            Shell::Zsh,
            &[
                ": 1690000000:0;git status",
                ": 1690000001:0;password=hunter2",
            ],
        );
        let findings = scan_history(&h);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line_no, 2);
    }
}
