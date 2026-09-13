//! SQLite snippet store (plaintext or age-encrypted).

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, params};
use secdetect::age_crypt::AgeKey;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A stored shell snippet.
pub struct Snippet {
    /// Unique snippet name (lookup key).
    pub name: String,
    /// Raw shell command (may contain secrets when stored with `--force`).
    pub command: String,
    /// Short human description.
    pub description: String,
    /// Tags for search and grouping.
    pub tags: Vec<String>,
    /// Creation time (unix seconds).
    pub created_at: i64,
    /// Last update time (unix seconds).
    pub updated_at: i64,
    /// Successful `exec` runs.
    pub use_count: i64,
}

/// Current unix time in seconds (0 on clock error).
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

/// Open (creating parent dirs and schema as needed) the SQLite store.
/// Best-effort restricts the DB file to `0600` on unix.
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
    restrict_0600(db_path);
    init_schema(&conn)?;
    Ok(conn)
}

/// Create the `snips` table when missing.
fn init_schema(conn: &Connection) -> Result<()> {
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
    Ok(())
}

/// Directory holding `db_path` (`.` for bare filenames).
fn db_dir_of(db_path: &Path) -> PathBuf {
    match db_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Best-effort `0600` on unix (backup/encrypted/temp files hold secrets).
#[cfg(unix)]
fn restrict_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perm = std::fs::Permissions::from_mode(0o600);
    if let Err(e) = std::fs::set_permissions(path, perm) {
        eprintln!("warning: cannot chmod 0600 {}: {e:#}", path.display());
    }
}

#[cfg(not(unix))]
fn restrict_0600(_path: &Path) {}

/// Atomically replace `path` with `bytes` (sibling temp file + rename).
fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let nanos = now_nanos();
    let tmp_name = format!(
        ".{}.tmp.{}.{}.snipwrite",
        path.file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "snips.db".to_string()),
        nanos,
        std::process::id()
    );
    let tmp_path = path.with_file_name(tmp_name);
    let result = (|| -> Result<()> {
        std::fs::write(&tmp_path, bytes)
            .with_context(|| format!("cannot write {}", tmp_path.display()))?;
        restrict_0600(&tmp_path);
        std::fs::rename(&tmp_path, path)
            .with_context(|| format!("cannot replace {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Bounds for stored snippets (DoS guard for `add`/`import`).
/// Maximum snippet name length in chars.
pub const MAX_NAME_CHARS: usize = 128;
/// Maximum command length in chars.
pub const MAX_COMMAND_CHARS: usize = 64 * 1024;
/// Maximum description length in chars.
pub const MAX_DESC_CHARS: usize = 8 * 1024;
/// Maximum number of tags per snippet.
pub const MAX_TAGS: usize = 32;
/// Maximum single tag length in chars.
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

/// Insert a snippet; fails on duplicate names and oversized fields.
/// Which backend holds the snippets for this session.
pub enum Backend {
    /// Plaintext SQLite file (existing behavior).
    Plain(Connection),
    /// age-encrypted SQLite file, decrypted to a `0600` tempfile for the session.
    Encrypted(EncryptedStore),
}

impl Backend {
    /// Active connection for this session.
    pub fn conn(&self) -> &Connection {
        match self {
            Backend::Plain(conn) => conn,
            Backend::Encrypted(store) => store.conn(),
        }
    }

    /// Flush and close. Re-encrypts encrypted stores (atomic replace) and
    /// releases the session lock. Always call, even when the command failed,
    /// so no plaintext tempfile lingers.
    pub fn close(self) -> Result<()> {
        if let Backend::Encrypted(store) = self {
            store.close()?;
        }
        Ok(())
    }
}

/// Marker inside our session tempfile names (stale ones are ours to clean
/// while the session lock is held).
const ENC_TMP_MARK: &str = ".snip-enc-tmp.";

/// An age-encrypted snippet store. SQLite works on a `0600` tempfile;
/// [`EncryptedStore::close`] re-encrypts atomically. `Drop` closes
/// best-effort as a safety net.
pub struct EncryptedStore {
    inner: Option<EncryptedInner>,
}

struct EncryptedInner {
    conn: Connection,
    db_path: PathBuf,
    tmp_path: PathBuf,
    lock_path: PathBuf,
    key: AgeKey,
}

fn lock_path_for(db_path: &Path) -> PathBuf {
    let mut name = db_path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| "snips.db".into());
    name.push(".lock");
    db_path.with_file_name(name)
}

#[cfg(target_os = "linux")]
fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(not(target_os = "linux"))]
fn pid_alive(_pid: u32) -> bool {
    // No cheap check: treat the lock as held, manual removal documented.
    true
}

/// Acquire `<db>.lock` (pid-tagged). Clears stale locks from dead pids on
/// Linux; elsewhere a leftover lock blocks with removal instructions.
fn acquire_lock(db_path: &Path) -> Result<PathBuf> {
    let lock = lock_path_for(db_path);
    let claim = || -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)?;
        use std::io::Write as _;
        write!(f, "{}", std::process::id())?;
        restrict_0600(&lock);
        Ok(())
    };
    match claim() {
        Ok(()) => Ok(lock),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let content = std::fs::read_to_string(&lock).unwrap_or_default();
            let pid: u32 = content.trim().parse().unwrap_or(0);
            #[cfg(target_os = "linux")]
            if pid != 0 && !pid_alive(pid) {
                eprintln!("warning: clearing stale lock from dead pid {pid}");
                std::fs::remove_file(&lock)
                    .with_context(|| format!("cannot clear stale lock {}", lock.display()))?;
                return claim()
                    .map(|()| lock)
                    .with_context(|| format!("cannot lock {}", lock.display()));
            }
            let _ = pid;
            bail!(
                "database is locked by pid {} (another snip session?); remove {} if stale",
                content.trim(),
                lock.display()
            )
        }
        Err(e) => Err(e).with_context(|| format!("cannot lock {}", lock.display())),
    }
}

/// Remove our leftover session tempfiles (lock is held: no live owner).
fn cleanup_stale_tmps(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.contains(ENC_TMP_MARK) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

impl EncryptedStore {
    /// Decrypt `db_path` with `key` into a `0600` session tempfile, or (with
    /// `create`) start a fresh database there.
    fn open(db_path: &Path, key: AgeKey, create: bool) -> Result<Self> {
        let dir = db_dir_of(db_path);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
        let lock_path = acquire_lock(db_path)?;
        cleanup_stale_tmps(&dir);
        let stem = db_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "snips.db".to_string());
        let tmp_path = dir.join(format!(
            ".{stem}{ENC_TMP_MARK}{}.{}.db",
            now_nanos(),
            std::process::id()
        ));
        if !create {
            let blob = std::fs::read(db_path)
                .with_context(|| format!("cannot read {}", db_path.display()))?;
            let plain = key
                .decrypt(&blob)
                .with_context(|| format!("cannot decrypt {} (wrong key?)", db_path.display()))?;
            std::fs::write(&tmp_path, &plain)
                .with_context(|| format!("cannot write {}", tmp_path.display()))?;
            restrict_0600(&tmp_path);
        }
        let conn = Connection::open(&tmp_path)
            .with_context(|| format!("cannot open {}", tmp_path.display()))?;
        init_schema(&conn)?;
        Ok(Self {
            inner: Some(EncryptedInner {
                conn,
                db_path: db_path.to_path_buf(),
                tmp_path,
                lock_path,
                key,
            }),
        })
    }

    /// Active session connection.
    pub fn conn(&self) -> &Connection {
        &self
            .inner
            .as_ref()
            .expect("encrypted store already closed")
            .conn
    }

    /// Re-encrypt the session tempfile over the database (atomic replace),
    /// remove the tempfile and release the lock.
    pub fn close(mut self) -> Result<()> {
        let Some(inner) = self.inner.take() else {
            return Ok(());
        };
        Self::flush_inner(inner)
    }

    fn flush_inner(inner: EncryptedInner) -> Result<()> {
        let EncryptedInner {
            conn,
            db_path,
            tmp_path,
            lock_path,
            key,
        } = inner;
        drop(conn); // close SQLite first: all pages must be on disk
        let result = (|| -> Result<()> {
            let plain = std::fs::read(&tmp_path)
                .with_context(|| format!("cannot read {}", tmp_path.display()))?;
            let blob = key.encrypt(&plain)?;
            atomic_write_bytes(&db_path, &blob)?;
            restrict_0600(&db_path);
            Ok(())
        })();
        let _ = std::fs::remove_file(&tmp_path);
        let _ = std::fs::remove_file(&lock_path);
        result
    }
}

impl Drop for EncryptedStore {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            if let Err(e) = Self::flush_inner(inner) {
                eprintln!("warning: failed to re-encrypt database: {e:#}");
            }
        }
    }
}

/// First bytes of a file (for age-magic detection without reading all).
fn head_bytes(path: &Path, n: usize) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let file =
        std::fs::File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut buf = Vec::new();
    file.take(n as u64)
        .read_to_end(&mut buf)
        .with_context(|| format!("cannot read {}", path.display()))?;
    Ok(buf)
}

/// True when a live session holds `<db>.lock`. Checked before any backend
/// branch so a second session cannot slip in while the first one is still
/// decrypting (the database file may not exist yet at that point).
fn session_locked(db_path: &Path) -> bool {
    let lock = lock_path_for(db_path);
    let Ok(content) = std::fs::read_to_string(&lock) else {
        return false;
    };
    let pid: u32 = content.trim().parse().unwrap_or(0);
    if pid == 0 {
        return true;
    }
    pid_alive(pid)
}

/// Open `db_path`, auto-detecting age-encrypted files.
///
/// - missing file without `create`: plaintext database (existing behavior);
/// - missing file with `create`: fresh encrypted database (`key` required);
/// - existing age blob: `key` is required, fails closed without it;
/// - existing plaintext with `key`: hard error (likely a wrong `--db` path;
///   migrate via `export` + `import`).
pub fn open_auto(db_path: &Path, key: Option<AgeKey>, create: bool) -> Result<Backend> {
    if session_locked(db_path) {
        bail!(
            "database is locked by another snip session; remove {} if stale",
            lock_path_for(db_path).display()
        );
    }
    if !db_path.is_file() {
        if create {
            if let Some(key) = key {
                return Ok(Backend::Encrypted(EncryptedStore::open(
                    db_path, key, true,
                )?));
            }
        }
        return Ok(Backend::Plain(open(db_path)?));
    }
    if secdetect::age_crypt::is_age_blob(&head_bytes(db_path, 64)?) {
        let key = key.context(
            "database is age-encrypted: pass --age-identity, or open a passphrase-encrypted database on a terminal",
        )?;
        return Ok(Backend::Encrypted(EncryptedStore::open(
            db_path, key, false,
        )?));
    }
    if key.is_some() {
        bail!("database is not encrypted: --age-identity has no effect (wrong --db path?)");
    }
    Ok(Backend::Plain(open(db_path)?))
}

/// Insert a snippet; fails on duplicate names and oversized fields.
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

/// Fetch a snippet by name (`None` when missing).
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

/// List all snippets ordered by name.
pub fn list(conn: &Connection) -> Result<Vec<Snippet>> {
    let mut stmt = conn
        .prepare("SELECT name, command, description, tags, created_at, updated_at, use_count FROM snips ORDER BY name")
        .context("cannot prepare")?;
    let rows = stmt.query_map([], row_to_snippet).context("cannot query")?;
    rows.collect::<Result<Vec<_>, _>>()
        .context("cannot read rows")
}

/// Delete a snippet by name; returns whether anything was removed.
pub fn remove(conn: &Connection, name: &str) -> Result<bool> {
    let n = conn
        .execute("DELETE FROM snips WHERE name = ?1", params![name])
        .context("cannot delete")?;
    Ok(n > 0)
}

/// Increment the successful-run counter of a snippet.
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

    fn enc_tmp() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("snips.db");
        (dir, db)
    }

    fn recipient_keypair() -> (String, String) {
        use age::secrecy::ExposeSecret;
        let id = age::x25519::Identity::generate();
        (
            id.to_public().to_string(),
            id.to_string().expose_secret().to_owned(),
        )
    }

    fn write_key_file(dir: &tempfile::TempDir, identity: &str) -> std::path::PathBuf {
        let path = dir.path().join("key.txt");
        std::fs::write(&path, format!("# test key\n{identity}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    #[test]
    fn encrypted_roundtrip() {
        let (dir, db) = enc_tmp();
        let (recipient, identity) = recipient_keypair();
        let key = AgeKey::from_recipient(&recipient).unwrap();
        let backend = open_auto(&db, Some(key), true).unwrap();
        assert!(matches!(backend, Backend::Encrypted(_)));
        add(backend.conn(), &sample("a")).unwrap();
        backend.close().unwrap();

        // On-disk: age blob, no plaintext residue, no leftovers.
        let blob = std::fs::read(&db).unwrap();
        assert!(secdetect::age_crypt::is_age_blob(&blob));
        assert!(!blob.windows(7).any(|w| w == b"echo hi"));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);

        // Reopen via identity file, data intact.
        let key_path = write_key_file(&dir, &identity);
        let key2 = AgeKey::from_identity_file(&key_path).unwrap();
        let backend2 = open_auto(&db, Some(key2), false).unwrap();
        assert_eq!(
            get(backend2.conn(), "a").unwrap().unwrap().command,
            "echo hi"
        );
        backend2.close().unwrap();
    }

    #[test]
    fn encrypted_wrong_key_and_missing_key_fail() {
        let (_dir, db) = enc_tmp();
        let (recipient, _) = recipient_keypair();
        let (_, other_identity) = recipient_keypair();
        open_auto(&db, AgeKey::from_recipient(&recipient).ok(), true)
            .unwrap()
            .close()
            .unwrap();
        assert!(open_auto(&db, None, false).is_err());
        let wrong = AgeKey::from_identity_str(&other_identity).unwrap();
        assert!(open_auto(&db, Some(wrong), false).is_err());
    }

    #[test]
    fn plaintext_db_rejects_key() {
        let (_dir, db) = enc_tmp();
        open(&db).unwrap();
        let (recipient, _) = recipient_keypair();
        let key = AgeKey::from_recipient(&recipient).unwrap();
        assert!(open_auto(&db, Some(key), false).is_err());
        // ...and still opens fine without one.
        let backend = open_auto(&db, None, false).unwrap();
        assert!(list(backend.conn()).unwrap().is_empty());
    }

    #[test]
    fn lock_blocks_second_session_and_drop_reencrypts() {
        let (_dir, db) = enc_tmp();
        let (recipient, identity) = recipient_keypair();
        let key = AgeKey::from_recipient(&recipient).unwrap();
        let backend = open_auto(&db, Some(key), true).unwrap();
        add(backend.conn(), &sample("a")).unwrap();
        // Second session while the first holds the lock: refused.
        let key2 = AgeKey::from_recipient(&recipient).unwrap();
        assert!(open_auto(&db, Some(key2), false).is_err());
        // Forget close(): Drop must still re-encrypt.
        drop(backend);
        let key3 = AgeKey::from_identity_str(&identity).unwrap();
        let backend3 = open_auto(&db, Some(key3), false).unwrap();
        assert!(get(backend3.conn(), "a").unwrap().is_some());
        backend3.close().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_linux_lock_is_cleared() {
        let (_dir, db) = enc_tmp();
        let lock = lock_path_for(&db);
        // Implausibly large pid: no such /proc entry.
        std::fs::write(&lock, "42424242").unwrap();
        let (recipient, _) = recipient_keypair();
        let key = AgeKey::from_recipient(&recipient).unwrap();
        open_auto(&db, Some(key), true).unwrap().close().unwrap();
    }
}
