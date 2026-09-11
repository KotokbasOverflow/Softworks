# Contributing

## Workflow

1. Keep it small and focused; one concern per PR.
2. This is a security tool — any change to generation logic, the RNG, the
   wordlist, or clipboard handling must call that out in the PR
   description and extend tests.
3. Update `CHANGELOG.md` (`[Unreleased]`) for user-visible changes.

## Checks (must pass locally and in CI)

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo deny check   # from repo root (deny.toml lives there); requires cargo-deny
cargo audit        # requires cargo-audit
```

MSRV is 1.85 (`rust-version` in `Cargo.toml`); do not use newer-only APIs
in `src/` (dev-dependencies are exempt — the MSRV job runs `cargo check`,
not `test`).

## Wordlist

`src/words.rs` embeds EFF `eff_large_wordlist.txt` verbatim. Never edit
words by hand — regenerate instead:

```powershell
python3 scripts/fetch_wordlist.py
```

The script downloads upstream https://www.eff.org/dice, verifies 7776
entries, prints the SHA-256, and rewrites `src/words.rs`. If the output
differs from the committed file, upstream changed: update the SHA-256 in
`src/words.rs`, `tests/wordlist.rs`, and `README.md`, and call it out in
the PR. `tests/wordlist.rs` enforces size, uniqueness, and checksum.

## Security issues

Do not file public issues for vulnerabilities — see `SECURITY.md`.
