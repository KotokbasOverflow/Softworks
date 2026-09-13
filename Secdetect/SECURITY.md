# Security Policy

`secdetect` provides shared regex detectors used by Softworks CLIs. Report
issues that cause unredacted secret leakage in dependents, catastrophic
false positives with real-world impact, or ReDoS in detector patterns.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a vulnerability

- **Do not** open a public issue for detector bypasses or leakage with
  real-world impact.
- Open a
  [private security advisory](https://github.com/KotokbasOverflow/Softworks/security/advisories/new)
  or contact the maintainers privately.

## Scope notes (known non-goals)

- Coverage is best-effort, not exhaustive. Absence of a match is not proof
  a string is safe.
- Conservative matching is intentional (noise over misses for assignment
  detectors).
- Supply chain: pinned via workspace `Cargo.lock`, gated by `cargo audit`
  and `cargo deny check` in CI.
