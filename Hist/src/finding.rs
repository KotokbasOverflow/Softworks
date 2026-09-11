//! Finding model shared by scan output and tests.

use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub file: PathBuf,
    pub shell: &'static str,
    pub line_no: usize,
    pub detectors: Vec<&'static str>,
    /// Redacted preview — the secret itself is never stored or printed.
    pub preview: String,
}
