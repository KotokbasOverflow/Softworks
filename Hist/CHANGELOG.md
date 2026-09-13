# Changelog

All notable changes to `hist` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

- Detectors extracted to shared workspace crate `secdetect` (used by `hist` and `snip`).

## [0.1.0] — 2026-09-11

- Initial release: `scan`, `clean` (`--dry-run`, `--drop-lines`), `detectors`.
- 10 detectors (AWS, GitHub, Slack, Stripe, OpenAI, Google, PEM keys,
  Bearer, URL credentials, assignments); conservative by design.
- Readers for PowerShell PSReadLine, bash, zsh + auto-discovery.
- Backups (`*.histbak.*`), redacted-only output, exit 1 on findings.
- Library layout, unit + black-box CLI tests on fixtures.
