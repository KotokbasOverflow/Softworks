# snip

Shell snippet manager with a secret-redaction gate.

- Store named commands in a local SQLite DB (`~/.snip/snips.db` or `$SNIP_DB` / `--db`)
- `add` / `import` refuse secrets unless `--force` (shared detectors via [`secdetect`](../Secdetect/))
- `list` / `search` show **redacted** previews only
- `get` / `export` emit **raw** commands (treat export files as secrets)
- Fuzzy search; `exec` runs via PowerShell/`sh` (confirm unless `--yes`)

## Install

```powershell
cargo install --path Snip
# or from workspace root
cargo build --release -p snip
```

## Usage

```powershell
snip init
snip add prune -- docker system prune -af
snip add leak --force -- export TOKEN=ghp_...   # explicit override
snip list
snip search prune
snip get prune
snip exec prune                 # prompts
snip exec prune --yes
snip exec prune --dry-run
snip export --file snips.json   # plaintext commands
snip export --file snips.age --age-recipient age1...   # age-encrypted
snip import --file snips.json   # gated like add
snip import --file snips.age --age-identity key.txt    # age-decrypted
snip import --force --file snips.json
snip rm prune --yes
```

## Encrypted database (age)

```powershell
snip init --age-recipient age1...   # new encrypted DB (X25519)
snip init --age-passphrase          # new encrypted DB (scrypt passphrase)
snip --age-identity key.txt add api -- curl -H "Authorization: Bearer ..."
snip --age-identity key.txt list
```

The database file stays an age blob at rest; each session decrypts to a
`0600` tempfile and re-encrypts atomically on close (even on command
failure). Concurrent sessions are refused via a pid-tagged lock file
(stale Linux locks from dead pids are cleared; elsewhere remove it
manually). Migrate a plaintext DB with `export` + `import --age-identity`
into a fresh encrypted one. Lost identity/passphrase = lost snippets.

## Safety notes

- The gate is best-effort (same conservative patterns as `hist`). Absence of a refusal is not proof the command is safe.
- `export` / `get` intentionally return raw text so you can eval or migrate; do not commit export files. `export --age-recipient age1...` writes an age-encrypted blob instead; `import` auto-detects it and needs `--age-identity` (or a terminal passphrase for scrypt files).
- Identity files must be `0600` (refused when group/other-readable on unix). Lost passphrase/identity = lost export: no recovery, by design.
- `exec` runs arbitrary shell code from the DB — review snippets, prefer `--dry-run`, avoid casual `--yes`.

## Development

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test -p snip
```

## License

MIT OR Apache-2.0. See `LICENSE-MIT`, `LICENSE-APACHE`.
