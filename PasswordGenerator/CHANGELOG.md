# Changelog

All notable changes to `password-generator` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

## [0.2.0] — 2026-09-11

### Changed
- Crate renamed to kebab-case `password-generator` (binary
  `password-generator`), edition 2024, `rand` 0.8 → 0.9.
- `--no-ambiguous` renamed to `--include-ambiguous`; the old name works as
  an alias with identical (include) semantics.
- Passphrases use the full EFF large wordlist (7776 words, ~12.9 bits/word)
  instead of the 52-word demo list.

### Added
- Unicode-safe `--custom` sets, `--capitalize`, `--with-number`,
  `--show-entropy`, `--no-print`, `--clear-after`.
- Secrets held in `zeroize::Zeroizing`.
- Library layout (`src/lib.rs` + `charset`/`cli`/`password`/`passphrase`/
  `clipboard`/`words` modules); `main.rs` is a thin wrapper.
- Integration tests (`tests/cli.rs`), wordlist integrity tests
  (`tests/wordlist.rs`, SHA-256 enforced), property tests (proptest).
- CI: fmt, clippy, tests on 3 OS, MSRV 1.85 check, `cargo deny`,
  `cargo audit`, LLVM coverage.
- `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, dual license
  MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).

### Fixed
- `--count 0` rejected instead of silent no-op / clipboard index panic.
- `--custom` conflicts with `-a/-u/-d/-s` (was silently ignored).
- `--custom` with non-ASCII no longer fails randomly (chars, not bytes).

## [0.1.0] — 2026-09-05

- Initial release: random passwords + 52-word demo passphrases, clipboard
  copy, basic unit tests.
