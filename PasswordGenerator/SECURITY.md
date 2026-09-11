# Security Policy

`password-generator` is a security tool: vulnerabilities here directly affect
the secrets of its users. Please report responsibly.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a vulnerability

- **Do not** open a public issue for anything that weakens generated
  secrets (predictable output, RNG misuse, wordlist tampering, clipboard
  leaks, secret exfiltration).
- Open a
  [private security advisory](https://github.com/KotokbasOverflow/Softworks/security/advisories/new)
  or contact the maintainers privately.
- Include: affected version, platform, reproduction steps, and impact
  assessment if you have one.

We will acknowledge receipt within 72 hours, assess, fix, and publish a
patched release with a `CHANGELOG.md` entry. Credit is given on request.

## Scope notes (known non-goals)

- Endpoint security (swap/hibernation dumps, compromised OS, shoulder
  surfing) is out of scope — see `PasswordGenerator/README.md`.
- Clipboard is shared system state by design; use `--clear-after N` and
  `--no-print`. A clipboard history manager can still retain copies —
  that is platform behavior, not a vulnerability in this tool.

## Supply chain

- Dependencies are pinned via `Cargo.lock` and gated by `cargo audit`
  and `cargo deny check` in CI.
- The EFF wordlist is embedded verbatim; `tests/wordlist.rs` enforces its
  SHA-256 checksum. Any wordlist change must update the checksum in
  `src/words.rs` and be called out in the PR.
