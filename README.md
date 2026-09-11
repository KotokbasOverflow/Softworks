# Softworks

Монорепо утилит. Первый крейт:

- [`PasswordGenerator/`](PasswordGenerator/) — `password-generator`: CLI для паролей и EFF Diceware-фраз (Rust, CSPRNG, clipboard).

```powershell
cargo run -p password-generator -- -l 16
```

Документация и threat model — в `PasswordGenerator/README.md`.
CI: `cargo fmt --check`, `clippy -D warnings`, `cargo test`, `cargo audit`.
