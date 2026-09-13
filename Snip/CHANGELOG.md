# Changelog

All notable changes to `snip` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

- SQLite file restricted to `0600` on unix (best-effort); snippet field
  bounds validated on `add`/`import` (name 128, command 64K, description 8K,
  tags 32×64).
- `import` refuses inputs over 10 MiB / 10 000 items.
- `exec` warns when the snippet looks like it contains secrets;
  `export` warns when the export contains secret-looking snippets.
- `export --age-recipient age1...` writes an age-encrypted blob;
  `import` auto-detects age blobs and decrypts via `--age-identity`
  (identity files must be `0600` on unix) or a terminal passphrase prompt
  for scrypt files.
- `#![warn(missing_docs)]`; `cargo doc` added to CI.
## [0.1.0] — 2026-09-13

- Initial release: `init`, `add`, `get`, `list`, `search`, `exec`, `rm`,
  `export`, `import`.
- Secret gate on `add` and `import` (shared `secdetect`); `--force` override.
- SQLite store, fuzzy search, redacted list/search previews.
- Unit + black-box CLI tests.
