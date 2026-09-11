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
cargo test
cargo deny check   # requires cargo-deny
cargo audit        # requires cargo-audit
```

MSRV is 1.85 (`rust-version` in `Cargo.toml`); do not use newer-only APIs
in `src/` (dev-dependencies are exempt — the MSRV job runs `cargo check`,
not `test`).

## Wordlist

`src/words.rs` embeds EFF `eff_large_wordlist.txt` verbatim. Never edit
words by hand: any change must re-verify against upstream
https://www.eff.org/dice, update the SHA-256 in `src/words.rs`, and make
`tests/wordlist.rs` pass.

## Security issues

Do not file public issues for vulnerabilities — see `SECURITY.md`.
