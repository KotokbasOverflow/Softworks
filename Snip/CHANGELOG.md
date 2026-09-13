# Changelog

All notable changes to `snip` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-09-13

- Initial release: `init`, `add`, `get`, `list`, `search`, `exec`, `rm`,
  `export`, `import`.
- Secret gate on `add` and `import` (shared `secdetect`); `--force` override.
- SQLite store, fuzzy search, redacted list/search previews.
- Unit + black-box CLI tests.
