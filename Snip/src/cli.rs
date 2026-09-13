//! CLI definition: init/add/get/list/search/exec/rm/export/import.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "snip",
    version,
    about = "Shell snippet manager with a secret-redaction gate"
)]
pub struct Cli {
    /// Database path (default: $SNIP_DB or ~/.snip/snips.db).
    #[arg(long = "db", global = true)]
    pub db: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create the database (also created implicitly by add/import).
    Init,
    /// Store a snippet. Refuses commands with secrets unless --force.
    Add {
        /// Snippet name.
        name: String,
        /// Short description.
        #[arg(long = "desc", default_value = "")]
        desc: String,
        /// Tags (repeatable).
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Store even if secrets are detected.
        #[arg(long = "force")]
        force: bool,
        /// The command (after `--`).
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Print the raw command (for copy/eval).
    Get { name: String },
    /// List snippets with redacted previews.
    List {
        /// Output JSON.
        #[arg(long = "json")]
        json: bool,
    },
    /// Fuzzy-search by name, command, description, tags.
    Search {
        query: String,
        /// Max results.
        #[arg(long = "limit", default_value_t = 10)]
        limit: usize,
        /// Output JSON.
        #[arg(long = "json")]
        json: bool,
    },
    /// Run the snippet via your shell (asks unless --yes).
    Exec {
        name: String,
        /// Skip confirmation.
        #[arg(long = "yes")]
        yes: bool,
        /// Print without running.
        #[arg(long = "dry-run")]
        dry_run: bool,
    },
    /// Delete a snippet (asks unless --yes).
    Rm {
        name: String,
        /// Skip confirmation.
        #[arg(long = "yes")]
        yes: bool,
    },
    /// Export all snippets as JSON (stdout or file).
    Export {
        /// Write to file instead of stdout.
        #[arg(long = "file")]
        file: Option<PathBuf>,
    },
    /// Import snippets from JSON export (skips existing names).
    ///
    /// Each command is run through the same secret gate as `add` unless
    /// `--force`. Export files contain raw commands — treat them as secrets.
    Import {
        /// Read from file instead of stdin.
        #[arg(long = "file")]
        file: Option<PathBuf>,
        /// Overwrite existing names instead of skipping.
        #[arg(long = "overwrite")]
        overwrite: bool,
        /// Store even if secrets are detected (same as `add --force`).
        #[arg(long = "force")]
        force: bool,
    },
}
