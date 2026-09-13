# secdetect

Shared secret detectors and redaction for the Softworks suite.

Used by:

- [`hist`](../Hist/) — scan/clean shell history
- [`snip`](../Snip/) — refuse to store (or import) commands containing secrets

Library only (no binary). Patterns are deliberately conservative: a false
positive that nukes a history line is worse than a miss.

## API

```rust
use secdetect::{detect, redact, DETECTORS, REDACTED};

let ids = detect("password=hunter2");
let (line, matched) = redact("export TOKEN=ghp_abcDEF123456");
assert!(line.contains(REDACTED));
assert!(!DETECTORS.is_empty());
```

## Detectors

AWS access keys, GitHub/Slack/Stripe/OpenAI/Google tokens, PEM private keys,
Bearer tokens, URL credentials, password/secret/token assignments.

Space-separated forms like `--api-key VALUE` are intentionally not flagged.

## Development

```powershell
cargo test -p secdetect
```

## License

MIT OR Apache-2.0. See `LICENSE-MIT`, `LICENSE-APACHE`.
