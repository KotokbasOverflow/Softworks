# Changelog

All notable changes to `secdetect` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

- Tightened detectors: AWS covers `ASIA` temporary keys; Stripe covers
  `sk_test_`; GitHub/Slack tokens need minimum lengths; Bearer needs a word
  boundary; Google keys accept 35+ chars.
- Exemplar + proptest coverage: every detector id has fake-secret exemplars
  asserting detect/redact/fixpoint, plus `prop_redact_never_leaks`
  (redaction in random context never leaks, `proptest` dev-dependency).
- `#![warn(missing_docs)]`.
## [0.1.0] — 2026-09-13

- Initial library release: shared detectors + `detect` / `redact` for Softworks.
- Extracted from `hist` for reuse by `snip`.
