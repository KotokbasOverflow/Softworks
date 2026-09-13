//! `snip` library: snippet store, fuzzy search, redaction gate.
//!
//! The binary (`src/main.rs`) is a thin CLI wrapper; all logic lives here
//! so it can be unit-tested and reused.

pub mod cli;
pub mod fuzzy;
pub mod gate;
pub mod store;

pub use cli::Cli;
pub use store::Snippet;

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Resolve the database path: `--db` > `$SNIP_DB` > `~/.snip/snips.db`.
pub fn resolve_db(explicit: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.clone());
    }
    if let Some(env) = std::env::var_os("SNIP_DB") {
        return Ok(PathBuf::from(env));
    }
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .context("cannot locate home directory (set --db or $SNIP_DB)")?;
    Ok(home.join(".snip/snips.db"))
}

/// Ranked fuzzy search over name (×3), tags (×2), command and description.
pub fn search<'a>(snips: &'a [Snippet], query: &str, limit: usize) -> Vec<(&'a Snippet, i64)> {
    let mut scored: Vec<(&Snippet, i64)> = snips
        .iter()
        .filter_map(|s| {
            let name = fuzzy::fuzzy_score(query, &s.name).map(|x| x * 3);
            let tags = s
                .tags
                .iter()
                .filter_map(|t| fuzzy::fuzzy_score(query, t).map(|x| x * 2))
                .max();
            let cmd = fuzzy::fuzzy_score(query, &s.command);
            let desc = fuzzy::fuzzy_score(query, &s.description);
            let best = [name, tags, cmd, desc].into_iter().flatten().max()?;
            // Name matches outrank everything: small bump, ties broken by use.
            let bump = if fuzzy::fuzzy_score(query, &s.name).is_some() {
                1000
            } else {
                0
            };
            Some((s, best + bump + s.use_count))
        })
        .collect();
    scored.sort_by_key(|a| std::cmp::Reverse(a.1));
    scored.truncate(limit);
    scored
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Snippet;

    fn snip(name: &str, command: &str) -> Snippet {
        Snippet {
            name: name.into(),
            command: command.into(),
            description: String::new(),
            tags: Vec::new(),
            created_at: 0,
            updated_at: 0,
            use_count: 0,
        }
    }

    #[test]
    fn name_match_outranks_command_match() {
        let snips = vec![
            snip("cleanup", "echo unrelated"),
            snip("other", "docker cleanup --all"),
        ];
        let res = search(&snips, "cleanup", 10);
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].0.name, "cleanup");
    }

    #[test]
    fn no_match_gives_empty() {
        let snips = vec![snip("a", "echo hi")];
        assert!(search(&snips, "zzzqqq", 10).is_empty());
    }

    #[test]
    fn limit_applies() {
        let snips = vec![snip("a1", "x"), snip("a2", "x"), snip("a3", "x")];
        assert_eq!(search(&snips, "a", 2).len(), 2);
    }
}
