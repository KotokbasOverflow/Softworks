# password-generator

Generate secure passwords and EFF Diceware passphrases from the command line.

- CSPRNG (`rand::rng()`, seeded from the OS)
- Excludes ambiguous characters by default (`l,1,O,0,I,|,...`), opt-in via `--include-ambiguous`
- Guarantees ≥1 char from each selected set when `length >= number of sets`
- Unicode-safe `--custom` sets (each scalar value = 1 character)
- Passphrases use the full EFF large wordlist (7776 words, ~12.9 bits/word)
- Secrets held in `zeroize::Zeroizing`, optional `--no-print` + `--clear-after` for clipboard hygiene
- `--show-entropy` prints an estimate to stderr

## Install

```powershell
cargo install --path .
# or
cargo build --release
```

Binary: `password-generator` (`target/release/password-generator`).

## Usage

```powershell
# 16-char password (all sets, unambiguous by default)
password-generator -l 16

# 69 chars, show entropy
password-generator -l 69 --show-entropy

# only lowercase + digits
password-generator -l 20 -a -d

# include ambiguous chars (old name --no-ambiguous still works as alias)
password-generator -l 20 --include-ambiguous

# custom set (Unicode-safe)
password-generator --custom "abc123éü" -l 12

# Diceware passphrase, 4 EFF words
password-generator -p

# 6 words, capitalized + trailing digit (helps password policies)
password-generator -p -w 6 --capitalize --with-number --separator "-" --show-entropy

# copy to clipboard without printing (avoids shell history leak), clear after 30s
password-generator -l 24 --copy --no-print --clear-after 30
```

Full flags: `password-generator --help`.

## Security notes

- Passphrase strength: 4 EFF words ≈ 52 bits; for ≥80 bits use `-w 6` or more
  (+ `--with-number` adds ~3.3 bits). The old 52-word demo list was removed —
  do not use short wordlists for real secrets.
- `stdout` leaks: terminals, `history`, logs. Prefer `--copy --no-print` for
  high-value secrets.
- Clipboard is shared system state: use `--clear-after N`; lock your screen.
- Memory is zeroized on drop (`Zeroizing`), but no tool protects against
  swap/hibernation dumps or a compromised machine — treat endpoint security
  as out of scope.
- Ambiguous sets: filtered `LOWER` excludes `l`, `UPPER` excludes `O,I`,
  `DIGITS` excludes `0,1`, `SYMBOLS` excludes quotes/backticks/backslash for
  shell safety. Use `--include-ambiguous` for the full printable ranges.

## Character sets

| Flag | Filtered (default) | With `--include-ambiguous` |
|---|---|---|
| `-a` lower | `abcdefghijkmnopqrstuvwxyz` (no `l`) | `a-z` |
| `-u` upper | `ABCDEFGHJKLMNPQRSTUVWXYZ` (no `O,I`) | `A-Z` |
| `-d` digits | `23456789` (no `0,1`) | `0-9` |
| `-s` symbols | `!@#$%^&*()-_=+[]{};:,.<>?/~` | full `!"#$%&'()*+,-./:;<=>?@[\]^_`{\|}~` |

No charset flag = all four sets. `--custom` conflicts with `-a/-u/-d/-s`.

## Entropy

- Password: `length × log2(charset_size)`. Example: 16 chars × 84 symbols ≈ 102 bits.
- Passphrase: `words × 12.92 + (3.32 if --with-number)`.

## Development

Layout: `src/lib.rs` + modules (`charset`, `cli`, `password`,
`passphrase`, `clipboard`, `words`); `src/main.rs` is a thin wrapper.
Tests: unit + proptest in modules, `tests/cli.rs` (black-box CLI),
`tests/wordlist.rs` (SHA-256 integrity).

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace   # from repo root
cargo deny check   # from repo root; requires cargo-deny
cargo audit        # requires cargo-audit
```

MSRV 1.85. Coverage: `cargo llvm-cov --workspace` (see CI).
Contributing: see `CONTRIBUTING.md`; vulnerabilities: see `SECURITY.md`.

Wordlist: `src/words.rs` (`EFF_WORDS`, 7776 entries, embedded verbatim in
upstream order).
Source: EFF `eff_large_wordlist.txt` from https://www.eff.org/dice,
© Electronic Frontier Foundation, used under Creative Commons Attribution
(CC BY) — see https://www.eff.org/copyright.
Integrity: SHA-256 of the `\n`-joined list is
`6d557f06…743bc522` (full value in `src/words.rs`, enforced by
`tests/wordlist.rs`).
Note: 4 words contain a hyphen (`drop-down`, `felt-tip`, `t-shirt`,
`yo-yo`) — with the default `-` separator, split-on-`-` word counting can
be off; use another separator if that matters.

## License

MIT OR Apache-2.0. See `LICENSE-MIT`.
