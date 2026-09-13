//! Clipboard helpers (copy + explicit clear).

use anyhow::{Context, Result};
use arboard::Clipboard;

/// Copy `text` to the OS clipboard.
pub fn copy_to_clipboard(text: &str) -> Result<()> {
    let mut clipboard = Clipboard::new().context("Failed to access clipboard")?;
    clipboard
        .set_text(text.to_string())
        .context("Failed to set clipboard text")?;
    Ok(())
}

/// Clear the OS clipboard (writes an empty string; platform clipboard
/// history, if any, is out of scope — see `SECURITY.md`).
pub fn clear_clipboard() -> Result<()> {
    let mut clipboard = Clipboard::new().context("Failed to access clipboard")?;
    clipboard
        .set_text(String::new())
        .context("Failed to clear clipboard")?;
    Ok(())
}
