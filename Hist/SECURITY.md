# Security Policy

`hist` handles leaked secrets by design: it reads files that may contain
live credentials. Report vulnerabilities responsibly.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a vulnerability

- **Do not** open a public issue for anything that exposes secrets
  (printing unredacted matches, backup mishandling, detector bypasses
  with real-world impact).
- Open a
  [private security advisory](https://github.com/KotokbasOverflow/Softworks/security/advisories/new)
  or contact the maintainers privately.

## Scope notes (known non-goals)

- Detector coverage is best-effort, not exhaustive — absence of findings
  is not proof of a clean history.
- Backup files (`*.histbak.*`) intentionally contain the original secrets;
  their lifecycle is the user's responsibility.
- A shell may rewrite history on exit; close it before/after cleaning.
- Supply chain: pinned via workspace `Cargo.lock`, gated by `cargo audit`
  and `cargo deny check` in CI.
