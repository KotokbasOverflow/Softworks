# Softworks

Utility monorepo. First crate:

- [`PasswordGenerator/`](PasswordGenerator/) — `password-generator`: CLI for passwords and EFF Diceware passphrases (Rust, CSPRNG, clipboard).

```powershell
cargo run -p password-generator -- -l 16
```

Docs and threat model live in `PasswordGenerator/README.md`.
CI: `cargo fmt --check`, `clippy -D warnings`, `cargo test`, `cargo audit`.
