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
snip import --file snips.json   # gated like add
snip import --force --file snips.json
snip rm prune --yes
```

## Safety notes

- The gate is best-effort (same conservative patterns as `hist`). Absence of a refusal is not proof the command is safe.
- `export` / `get` intentionally return raw text so you can eval or migrate; do not commit export files.
- `exec` runs arbitrary shell code from the DB — review snippets, prefer `--dry-run`, avoid casual `--yes`.

## Development

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test -p snip
```

## License

MIT OR Apache-2.0. See `LICENSE-MIT`, `LICENSE-APACHE`.
