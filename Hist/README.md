# hist

Find and redact leaked secrets in shell history files.

- 10 built-in detectors: AWS keys, GitHub/Slack/Stripe/OpenAI/Google tokens, PEM private keys, Bearer tokens, URL credentials, password assignments
- Readers for PowerShell PSReadLine, bash, and zsh (extended format) + auto-discovery of history files
- `scan` reports findings with **redacted** previews (exit 1 on findings — scriptable in CI/hooks); secrets are never printed
- `clean` backs up (`*.histbak.*`) then redacts in place, or drops lines with `--drop-lines`; `--dry-run` for preview

## Install

```powershell
cargo install --path Hist
# or from workspace root
cargo build --release -p hist
```

## Usage

```powershell
# scan auto-discovered histories (exit 1 if secrets found)
hist scan

# scan a specific file as zsh, JSON output
hist scan --history ~/.zsh_history --shell zsh --format json

# preview what clean would change
hist clean --dry-run

# back up + redact secrets in place
hist clean

# back up + drop whole tainted lines
hist clean --drop-lines

# redact without leaving a plaintext backup (cannot be undone)
hist clean --no-backup

# age-encrypted backup instead of plaintext (*.histbak.*.age)
hist clean --backup-age-recipient age1...

# list detectors
hist detectors
```

Exit codes: `0` clean / nothing to do, `1` findings (scan) or runtime error.

## Safety notes

- `clean` writes a timestamped backup next to the original (restore manually
  if a false positive eats a line), rewrites the file atomically, and keeps
  whitespace/line-ending style. `--no-backup` skips the backup entirely.
  Symlinks are refused; history files over 20 MiB are refused.
- Patterns are deliberately conservative (`--api-key VALUE` with a space is *not* flagged; `=`/`:` assignments are). A missed secret is cheaper than a nuked history.
- Findings print detector ids and redacted previews only. The backup file **does** contain the original secrets — delete old `*.histbak.*` files or store them securely.
- Close the shell before cleaning: shells may rewrite history on exit and resurrect redacted lines. Best order: `hist clean` → close shell.

## Development

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace   # from repo root
```

Layout: `src/lib.rs` + modules (`history`, `scan`, `clean`, `finding`, `cli`); detectors live in the shared [`secdetect`](../Secdetect/) crate. `src/main.rs` is a thin wrapper. Fixtures with fake secrets live in `tests/fixtures/`.

## License

MIT OR Apache-2.0. See `LICENSE-MIT`, `LICENSE-APACHE`.
