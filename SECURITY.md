# Security Policy

Workspace policy for the Softworks monorepo (`password-generator`, `hist`,
`secdetect`, `snip`). Per-crate threat models live in each crate's
`SECURITY.md`; this file defines reporting and shared expectations.

## Supported versions

| Crate              | Version | Supported          |
| ------------------ | ------- | ------------------ |
| password-generator | 0.2.x   | :white_check_mark: |
| hist               | 0.1.x   | :white_check_mark: |
| secdetect          | 0.1.x   | :white_check_mark: |
| snip               | 0.1.x   | :white_check_mark: |
| anything older     | < above | :x:                |

## Reporting a vulnerability

- **Do not** open a public issue for anything that weakens user secrets
  (predictable RNG output, detector bypasses leaking secrets into previews,
  redaction failures, secret exfiltration, DB/history handling flaws).
- Open a
  [private security advisory](https://github.com/KotokbasOverflow/Softworks/security/advisories/new)
  or contact the maintainers privately. There is currently no PGP contact —
  the private advisory channel is the preferred route.
- Include: affected crate and version, platform, reproduction steps, and
  impact assessment if you have one.

We will acknowledge receipt within 72 hours, assess, fix, and publish a
patched release with a `CHANGELOG.md` entry. Credit is given on request.

## Shared scope notes (known non-goals)

- Endpoint security (swap/hibernation dumps, compromised OS, shoulder
  surfing) is out of scope for all crates.
- Secret detectors (`secdetect`) are best-effort heuristics: they favor
  avoiding destructive false positives over exhaustive coverage. High-entropy
  / JWT / age-key formats not in the documented detector list are currently
  out of scope.
- `hist clean` backups (`*.histbak.*`) and `snip` databases/exports store
  the ORIGINAL secrets in plaintext by design (chmod 0600 on unix,
  best-effort). Their lifecycle — verify, then delete backups; protect
  exports — is the operator's responsibility.
- Clipboard is shared system state; a clipboard-history manager can retain
  copies regardless of `--clear-after`. That is platform behavior, not a
  vulnerability in these tools.

## Supply chain

- Dependencies are pinned via the workspace `Cargo.lock` and gated by
  `cargo audit` and `cargo deny check` in CI (`deny.toml` allowlists
  licenses and denies wildcard/unknown registries).
- The EFF wordlist is embedded verbatim; `PasswordGenerator/tests/wordlist.rs`
  enforces its SHA-256 checksum.
