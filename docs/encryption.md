# RFC: encryption at rest for Softworks

Status: **v1 + v2 implemented** (opt-in flags below). Remaining: OS
keychain for key storage (deferred, on user demand). Goal: close the main residual risk —
plaintext `snip` databases, `hist` backups (`*.histbak.*`) and `snip`
exports. All encryption features are **opt-in**; plaintext stays the default
so scripts and existing flows keep working.

Implemented:

- `hist clean --backup-age-recipient age1...` → `*.histbak.*.age`
  (conflicts with `--no-backup`); wrong recipient rejected before any write.
- `snip export --age-recipient age1...` → age blob (file or stdout).
- `snip import` auto-detects age blobs: `--age-identity` file
  (`AGE-SECRET-KEY-...`, `0600`-enforced on unix) or terminal passphrase
  prompt for scrypt files; key-encrypted blobs without an identity fail
  closed with a pointer to `--age-identity`.
- Shared primitives live in `secdetect::age_crypt` (roundtrip + wrong-key +
  no-residue + permission tests), plus the `AgeKey` abstraction.
- Encrypted live DB (v2, implemented): `snip init --age-recipient age1...`
  or `init --age-passphrase`; auto-detection on open; global
  `--age-identity` (terminal passphrase prompt for scrypt DBs); per-session
  `0600` tempfile with atomic re-encrypt on close even on command failure
  (`Drop` best-effort net); pid-tagged `<db>.lock` against concurrent
  sessions (stale Linux locks cleared, elsewhere manual removal);
  plaintext DBs reject keys loudly — migrate via `export` + `import`.

## Decision: `age` as the default primitive

- `age` (rage/regex-free pure-Rust `age` crate): cross-platform, no daemons,
  passphrase mode uses scrypt/argon2id KDF out of the box, small reviewable
  crypto core (X25519 + ChaCha20-Poly1305). No new C dependencies
  (unlike SQLCipher), so the 3-OS CI matrix and MSRV stay cheap.
- OS keychain (DPAPI / macOS Keychain / Secret Service) as a *later* option
  for key storage, not for bulk data. Deferred: three platform backends,
  headless-CI pain, big scope. Revisit if users ask for unlock-without-prompt.

## Scope v1 (completed)

1. `hist clean --backup-age-recipient <age-recipient>`: the `*.histbak.*`
   copy is written encrypted (`*.histbak.age`); the plaintext original is
   still redacted in place. Combines with `--no-backup` (no backup at all).
2. `snip export --age-recipient <age-recipient>`: stdout/file output is an
   age-encrypted blob instead of raw JSON.
3. `snip import --age-identity <file>`: accept an age-encrypted export
   (auto-detected: age magic header → decrypt with passphrase prompt or
   `--age-identity` key file).

## Scope v2 (completed)

4. `snip --db` encrypted store: decrypt-to-tempfile on open, re-encrypt on
   close (`Drop` best-effort), pid-tagged lock, plaintext+key reject.
   Implemented in `snip/src/store.rs` (`EncryptedStore`).

## Key management & UX rules

- Passphrase via interactive prompt (hidden input, `rpassword`-style) or
  `--age-identity` file (0600 enforced on unix, refused when group/other
  readable). Never via argv (leaks to process list) — document loudly.
- Lost passphrase = lost data. Print this warning at encryption time and in
  `--help` epilogues. No recovery, no backdoor, by design.
- Wrong passphrase / corrupt blob → hard error before any write (never
  truncate the DB/history on decrypt failure).

## Supply-chain & CI impact

- New deps: `age` (+ `rpassword` or `dialoguer` for prompts). Both pure Rust.
- `deny.toml`: `age` is MIT/Apache-2.0 (allowlisted); add explicit approval
  note in the PR. `cargo audit`/`deny` gates already cover new crates.
- MSRV 1.85: verify `age`'s rust-version before merging; pin if it moves.
- Tests required: encrypt/decrypt roundtrip per command, wrong-passphrase
  refusal, no-plaintext-residue assertion (scan the output dir for the
  known secret), 0600 enforcement test (unix).

## Explicit non-goals

- Transparent/always-on encryption, key escrow, cloud KMS, encrypting the
  live SQLite file in v1, hiding *which* snippets exist (metadata stays).
- Endpoint threats (memory dumps, compromised OS) — still out of scope,
  see workspace `SECURITY.md`.
