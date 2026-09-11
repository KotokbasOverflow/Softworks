# Softworks

Utility monorepo (cargo workspace, lockfile at root). First crate:

- [`PasswordGenerator/`](PasswordGenerator/) — `password-generator`: CLI for passwords and EFF Diceware passphrases (Rust, CSPRNG, clipboard).

```powershell
cargo run -p password-generator -- -l 16
cargo test --workspace
```

Docs and threat model live in `PasswordGenerator/README.md`.
CI: `cargo fmt --check`, `clippy -D warnings`, `cargo test`, MSRV check,
`cargo deny`, `cargo audit`, LLVM coverage.
