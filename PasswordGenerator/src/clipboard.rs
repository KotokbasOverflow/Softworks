//! Clipboard helpers (copy + explicit clear).

use anyhow::{Context, Result};
use arboard::Clipboard;

pub fn copy_to_clipboard(text: &str) -> Result<()> {
    let mut clipboard = Clipboard::new().context("Failed to access clipboard")?;
    clipboard
        .set_text(text.to_string())
        .context("Failed to set clipboard text")?;
    Ok(())
}

pub fn clear_clipboard() -> Result<()> {
    let mut clipboard = Clipboard::new().context("Failed to access clipboard")?;
    clipboard
        .set_text(String::new())
        .context("Failed to clear clipboard")?;
    Ok(())
}
