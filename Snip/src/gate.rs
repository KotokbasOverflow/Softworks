//! Redaction gate: refuse to store commands containing secrets.
//!
//! Display everywhere else shows redacted previews, so a `--force`-stored
//! secret never leaks through `list`/`search` output.

use anyhow::{Result, bail};
use secdetect::redact;

/// Check a command before storing. Returns the matched detector ids.
pub fn gate(command: &str) -> Result<()> {
    let (_, matched) = redact(command);
    if matched.is_empty() {
        return Ok(());
    }
    bail!(
        "refusing to store: command contains secret(s) [{}]. Rotate them, use a placeholder, or re-run with --force",
        matched.join(",")
    );
}

/// Redacted preview for display (list/search).
pub fn preview(command: &str, max_chars: usize) -> String {
    let (redacted, _) = redact(command);
    if redacted.chars().count() <= max_chars {
        return redacted;
    }
    redacted.chars().take(max_chars).collect::<String>() + "…"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_command_passes() {
        assert!(gate("docker system prune -af").is_ok());
    }

    #[test]
    fn secret_command_refused_with_detector_id() {
        let err = gate("export TOKEN=ghp_abcDEF123").unwrap_err();
        assert!(err.to_string().contains("github-token"));
        assert!(err.to_string().contains("--force"));
    }

    #[test]
    fn preview_never_leaks() {
        let p = preview("password=hunter2 extra", 200);
        assert!(!p.contains("hunter2"));
        assert!(p.contains(secdetect::REDACTED));
    }
}
