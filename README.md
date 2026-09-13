# Softworks

Utility monorepo (cargo workspace, lockfile at root). Crates:

- [`PasswordGenerator/`](PasswordGenerator/) — `password-generator`: CLI for passwords and EFF Diceware passphrases (Rust, CSPRNG, clipboard).
- [`Hist/`](Hist/) — `hist`: find and redact leaked secrets in shell history (PSReadLine, bash, zsh).
- [`Secdetect/`](Secdetect/) — `secdetect`: shared secret detectors + redaction (library used by hist and snip).
- [`Snip/`](Snip/) — `snip`: shell snippet manager with a secret-redaction gate (SQLite, fuzzy search).

```powershell
cargo run -p password-generator -- -l 16
cargo run -p hist -- scan
cargo run -p snip -- list
cargo test --workspace
```

Docs and threat models live in each crate's `README.md` / `SECURITY.md`.
CI: `cargo fmt --check`, `clippy -D warnings`, `cargo test --locked`, MSRV check,
`cargo deny`, `cargo audit`, LLVM coverage (wordlist excluded from the line gate).
