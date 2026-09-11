//! CLI definition: `scan`, `clean`, `detectors`.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "hist",
    version,
    about = "Find and redact leaked secrets in shell history files"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan history files and report findings (exit 1 if any).
    /// Secrets are never printed — only redacted previews.
    Scan {
        /// History files to scan (default: auto-discovered PS/bash/zsh).
        #[arg(long = "history")]
        history: Vec<PathBuf>,

        /// Assume this shell format for all files.
        #[arg(long = "shell")]
        shell: Option<ShellOpt>,

        /// Output format.
        #[arg(long = "format", default_value = "text")]
        format: FormatOpt,
    },
    /// Back up history files, then redact (or drop) tainted lines.
    Clean {
        /// History files to clean (default: auto-discovered).
        #[arg(long = "history")]
        history: Vec<PathBuf>,

        /// Assume this shell format for all files.
        #[arg(long = "shell")]
        shell: Option<ShellOpt>,

        /// Show what would change without writing anything.
        #[arg(long = "dry-run")]
        dry_run: bool,

        /// Remove whole tainted lines instead of redacting secrets.
        #[arg(long = "drop-lines")]
        drop_lines: bool,
    },
    /// List built-in secret detectors.
    Detectors,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum ShellOpt {
    Powershell,
    Bash,
    Zsh,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatOpt {
    Text,
    Json,
}
