# Changelog

All notable changes to `hist` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

- Detectors extracted to shared workspace crate `secdetect` (used by `hist` and `snip`).
- `clean` rewrites atomically (temp file + fsync + rename); preserves
  whitespace/line-ending style and the trailing-newline state.
- Backups use nanosecond + pid names (no per-second collisions), get `0600`
  on unix, and symlinks are refused.
- History files over 20 MiB are refused (DoS guard).
- New `--no-backup` flag: redact without leaving a plaintext `*.histbak.*`.
- New `--backup-age-recipient age1...`: age-encrypted backup
  (`*.histbak.*.age`) instead of plaintext; conflicts with `--no-backup`.
- `clean` warns that the backup holds the original secrets.
- `clean --dry-run` counting locked to distinct lines (one finding per line).
- `#![warn(missing_docs)]`; `cargo doc` added to CI.
## [0.1.0] — 2026-09-11

- Initial release: `scan`, `clean` (`--dry-run`, `--drop-lines`), `detectors`.
- 10 detectors (AWS, GitHub, Slack, Stripe, OpenAI, Google, PEM keys,
  Bearer, URL credentials, assignments); conservative by design.
- Readers for PowerShell PSReadLine, bash, zsh + auto-discovery.
- Backups (`*.histbak.*`), redacted-only output, exit 1 on findings.
- Library layout, unit + black-box CLI tests on fixtures.
