//! CLI definition: `scan`, `clean`, `detectors`.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "hist",
    version,
    about = "Find and redact leaked secrets in shell history files"
)]
/// Command-line interface definition: `scan`, `clean`, `detectors`.
pub struct Cli {
    #[command(subcommand)]
    /// Subcommand to run.
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
/// Available subcommands.
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

        /// Skip the `*.histbak.*` backup (no plaintext copy of the secrets
        /// is left behind, but the clean cannot be undone).
        #[arg(long = "no-backup", conflicts_with = "age_recipient")]
        no_backup: bool,

        /// Encrypt the backup to this age recipient (`*.histbak.*.age`
        /// instead of plaintext). Pass an `age1...` public key.
        #[arg(long = "backup-age-recipient", conflicts_with = "no_backup")]
        age_recipient: Option<String>,
    },
    /// List built-in secret detectors.
    Detectors,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
/// Shell format override for `--shell`.
pub enum ShellOpt {
    /// PowerShell PSReadLine (also covers one-command-per-line formats).
    Powershell,
    /// bash one-command-per-line format.
    Bash,
    /// zsh extended-history format.
    Zsh,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
/// `scan` output format.
pub enum FormatOpt {
    /// Human-readable lines.
    Text,
    /// JSON array of findings.
    Json,
}
