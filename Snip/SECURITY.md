# Security Policy

`snip` stores and may execute shell commands. Report vulnerabilities that
bypass the redaction gate, leak secrets through list/search, or enable
unexpected command execution.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a vulnerability

- **Do not** open a public issue for gate bypasses or secret leakage with
  real-world impact.
- Open a
  [private security advisory](https://github.com/KotokbasOverflow/Softworks/security/advisories/new)
  or contact the maintainers privately.

## Scope notes (known non-goals)

- Detector coverage is best-effort — same shared `secdetect` patterns as
  `hist`. False negatives are expected for unusual formats.
- `get` / `export` emit raw commands by design; treat export files as
  secret material.
- `exec` runs user-stored shell commands; `--yes` skips confirmation by
  design. Compromised local DB access is out of scope for remote attack
  scenarios.
- Supply chain: pinned via workspace `Cargo.lock`, gated by `cargo audit`
  and `cargo deny check` in CI.
