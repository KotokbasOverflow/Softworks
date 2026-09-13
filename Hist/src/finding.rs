//! Finding model shared by scan output and tests.

use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
/// One tainted history line: location, matched detectors, redacted preview.
pub struct Finding {
    /// History file containing the line.
    pub file: PathBuf,
    /// Shell format name (`"powershell"`, `"bash"`, `"zsh"`).
    pub shell: &'static str,
    /// 1-based line number.
    pub line_no: usize,
    /// Ids of the detectors that matched.
    pub detectors: Vec<&'static str>,
    /// Redacted preview — the secret itself is never stored or printed.
    pub preview: String,
}
