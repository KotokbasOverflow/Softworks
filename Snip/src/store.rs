//! SQLite snippet store.

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snippet {
    pub name: String,
    pub command: String,
    pub description: String,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub use_count: i64,
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn tags_to_str(tags: &[String]) -> String {
    tags.join(",")
}

fn tags_from_str(s: &str) -> Vec<String> {
    if s.trim().is_empty() {
        return Vec::new();
    }
    s.split(',').map(|t| t.trim().to_string()).collect()
}

pub fn open(db_path: &Path) -> Result<Connection> {
    // No let-chains: keep MSRV 1.85.
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
    }
    let conn =
        Connection::open(db_path).with_context(|| format!("cannot open {}", db_path.display()))?;
    restrict_db_perms(db_path);
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS snips (
            name        TEXT PRIMARY KEY,
            command     TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            tags        TEXT NOT NULL DEFAULT '',
            created_at  INTEGER NOT NULL,
            updated_at  INTEGER NOT NULL,
            use_count   INTEGER NOT NULL DEFAULT 0
        );",
    )
    .context("cannot init schema")?;
    Ok(conn)
}

#[cfg(unix)]
fn restrict_db_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perm = std::fs::Permissions::from_mode(0o600);
    if let Err(e) = std::fs::set_permissions(path, perm) {
        eprintln!("warning: cannot chmod 0600 {}: {e:#}", path.display());
    }
}

#[cfg(not(unix))]
fn restrict_db_perms(_path: &Path) {}

/// Bounds for stored snippets (DoS guard for `add`/`import`).
pub const MAX_NAME_CHARS: usize = 128;
pub const MAX_COMMAND_CHARS: usize = 64 * 1024;
pub const MAX_DESC_CHARS: usize = 8 * 1024;
pub const MAX_TAGS: usize = 32;
pub const MAX_TAG_CHARS: usize = 64;

fn validate(snippet: &Snippet) -> Result<()> {
    if snippet.name.trim().is_empty() {
        bail!("snippet name must not be empty");
    }
    if snippet.name.chars().count() > MAX_NAME_CHARS {
        bail!("snippet name exceeds {MAX_NAME_CHARS} chars");
    }
    if snippet.command.trim().is_empty() {
        bail!("command must not be empty");
    }
    if snippet.command.chars().count() > MAX_COMMAND_CHARS {
        bail!("command exceeds {MAX_COMMAND_CHARS} chars");
    }
    if snippet.description.chars().count() > MAX_DESC_CHARS {
        bail!("description exceeds {MAX_DESC_CHARS} chars");
    }
    if snippet.tags.len() > MAX_TAGS {
        bail!("too many tags (max {MAX_TAGS})");
    }
    if snippet
        .tags
        .iter()
        .any(|t| t.chars().count() > MAX_TAG_CHARS)
    {
        bail!("tag exceeds {MAX_TAG_CHARS} chars");
    }
    Ok(())
}

pub fn add(conn: &Connection, snip: &Snippet) -> Result<()> {
    validate(snip)?;
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM snips WHERE name = ?1)",
            params![snip.name],
            |r| r.get(0),
        )
        .context("cannot query")?;
    if exists {
        bail!("snippet {:?} already exists (rm it first)", snip.name);
    }
    conn.execute(
        "INSERT INTO snips (name, command, description, tags, created_at, updated_at, use_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
        params![
            snip.name,
            snip.command,
            snip.description,
            tags_to_str(&snip.tags),
            snip.created_at,
            snip.updated_at,
        ],
    )
    .context("cannot insert")?;
    Ok(())
}

pub fn get(conn: &Connection, name: &str) -> Result<Option<Snippet>> {
    let mut stmt = conn
        .prepare("SELECT name, command, description, tags, created_at, updated_at, use_count FROM snips WHERE name = ?1")
        .context("cannot prepare")?;
    let mut rows = stmt.query(params![name]).context("cannot query")?;
    match rows.next().context("cannot read row")? {
        Some(r) => Ok(Some(row_to_snippet(r)?)),
        None => Ok(None),
    }
}

pub fn list(conn: &Connection) -> Result<Vec<Snippet>> {
    let mut stmt = conn
        .prepare("SELECT name, command, description, tags, created_at, updated_at, use_count FROM snips ORDER BY name")
        .context("cannot prepare")?;
    let rows = stmt.query_map([], row_to_snippet).context("cannot query")?;
    rows.collect::<Result<Vec<_>, _>>()
        .context("cannot read rows")
}

pub fn remove(conn: &Connection, name: &str) -> Result<bool> {
    let n = conn
        .execute("DELETE FROM snips WHERE name = ?1", params![name])
        .context("cannot delete")?;
    Ok(n > 0)
}

pub fn bump_use_count(conn: &Connection, name: &str) -> Result<()> {
    conn.execute(
        "UPDATE snips SET use_count = use_count + 1 WHERE name = ?1",
        params![name],
    )
    .context("cannot update use_count")?;
    Ok(())
}

fn row_to_snippet(r: &rusqlite::Row<'_>) -> Result<Snippet, rusqlite::Error> {
    let tags: String = r.get(3)?;
    Ok(Snippet {
        name: r.get(0)?,
        command: r.get(1)?,
        description: r.get(2)?,
        tags: tags_from_str(&tags),
        created_at: r.get(4)?,
        updated_at: r.get(5)?,
        use_count: r.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE snips (
                name TEXT PRIMARY KEY, command TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                use_count INTEGER NOT NULL DEFAULT 0);",
        )
        .unwrap();
        conn
    }

    fn sample(name: &str) -> Snippet {
        Snippet {
            name: name.into(),
            command: "echo hi".into(),
            description: String::new(),
            tags: vec!["demo".into()],
            created_at: 1,
            updated_at: 1,
            use_count: 0,
        }
    }

    #[test]
    fn add_get_roundtrip() {
        let conn = mem();
        add(&conn, &sample("a")).unwrap();
        let got = get(&conn, "a").unwrap().unwrap();
        assert_eq!(got.command, "echo hi");
        assert_eq!(got.tags, vec!["demo"]);
    }

    #[test]
    fn add_duplicate_rejected() {
        let conn = mem();
        add(&conn, &sample("a")).unwrap();
        assert!(add(&conn, &sample("a")).is_err());
    }

    #[test]
    fn get_missing_returns_none_and_remove_reports() {
        let conn = mem();
        assert!(get(&conn, "nope").unwrap().is_none());
        assert!(!remove(&conn, "nope").unwrap());
        add(&conn, &sample("a")).unwrap();
        assert!(remove(&conn, "a").unwrap());
    }

    #[test]
    fn list_is_sorted_and_bump_works() {
        let conn = mem();
        add(&conn, &sample("b")).unwrap();
        add(&conn, &sample("a")).unwrap();
        let all = list(&conn).unwrap();
        assert_eq!(all[0].name, "a");
        bump_use_count(&conn, "a").unwrap();
        assert_eq!(get(&conn, "a").unwrap().unwrap().use_count, 1);
    }

    #[test]
    fn oversized_snippet_rejected() {
        let conn = mem();
        let mut bad = sample("big");
        bad.command = "x".repeat(MAX_COMMAND_CHARS + 1);
        assert!(add(&conn, &bad).is_err());
        let mut bad_name = sample(&"n".repeat(MAX_NAME_CHARS + 1));
        bad_name.command = "echo hi".into();
        assert!(add(&conn, &bad_name).is_err());
    }
}
