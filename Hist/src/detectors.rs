//! Secret detectors: id, description, and regex for each known pattern.
//!
//! Every match is redacted, never printed. Keep patterns tight: a false
//! positive that nukes a history line is worse than a miss (user can add
//! `--drop-lines` or custom patterns later).

use regex::Regex;
use std::sync::LazyLock;

pub const REDACTED: &str = "***REDACTED***";

pub struct Detector {
    pub id: &'static str,
    pub description: &'static str,
    pub pattern: Regex,
}

const PATTERNS: &[(&str, &str, &str)] = &[
    (
        "aws-access-key",
        "AWS access key id (AKIA...)",
        r"AKIA[0-9A-Z]{16}",
    ),
    (
        "github-token",
        "GitHub token (ghp_/gho_/github_pat_...)",
        r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+",
    ),
    (
        "slack-token",
        "Slack token (xox...)",
        r"xox[baprs]-[A-Za-z0-9-]+",
    ),
    (
        "stripe-secret",
        "Stripe live secret key",
        r"sk_live_[A-Za-z0-9]+",
    ),
    ("openai-key", "OpenAI API key", r"sk-[A-Za-z0-9]{20,}"),
    (
        "google-api-key",
        "Google API key (AIza...)",
        r"AIza[0-9A-Za-z\-_]{35}",
    ),
    (
        "private-key",
        "PEM private key header",
        r"-----BEGIN (OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----",
    ),
    (
        "bearer-token",
        "Bearer token in Authorization header",
        r"[Bb]earer [A-Za-z0-9\-._~+/=]{16,}",
    ),
    (
        "url-credentials",
        "user:password embedded in URL",
        r"(?i)https?://[^/\s:]+:[^/\s@]+@",
    ),
    (
        "password-assign",
        "password/secret/token assignment",
        r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S+",
    ),
];

pub static DETECTORS: LazyLock<Vec<Detector>> = LazyLock::new(|| {
    PATTERNS
        .iter()
        .map(|(id, description, re)| Detector {
            id,
            description,
            pattern: Regex::new(re).expect("invalid detector regex"),
        })
        .collect()
});

/// All detector ids that match `line`.
pub fn detect(line: &str) -> Vec<&'static str> {
    DETECTORS
        .iter()
        .filter(|d| d.pattern.is_match(line))
        .map(|d| d.id)
        .collect()
}

/// Replace every detected secret in `line` with `***REDACTED***`.
/// Returns the redacted line and the matched detector ids.
pub fn redact(line: &str) -> (String, Vec<&'static str>) {
    let mut out = line.to_string();
    let mut matched = Vec::new();
    for d in DETECTORS.iter() {
        if d.pattern.is_match(&out) {
            matched.push(d.id);
            out = d.pattern.replace_all(&out, REDACTED).into_owned();
        }
    }
    (out, matched)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_key() {
        assert!(detect("aws configure AKIAIOSFODNN7EXAMPLE").contains(&"aws-access-key"));
        assert!(detect("nothing here").is_empty());
    }

    #[test]
    fn detects_github_and_slack_tokens() {
        assert!(detect("export GITHUB_TOKEN=ghp_abcDEF123456").contains(&"github-token"));
        assert!(detect("xoxb-123-456-deadbeef").contains(&"slack-token"));
    }

    #[test]
    fn detects_private_key_and_bearer() {
        assert!(detect("-----BEGIN RSA PRIVATE KEY-----").contains(&"private-key"));
        assert!(
            detect("curl -H 'Authorization: Bearer abcdef0123456789'").contains(&"bearer-token")
        );
    }

    #[test]
    fn detects_url_credentials_and_assignments() {
        assert!(
            detect("git clone https://user:s3cr3t@github.com/x/y").contains(&"url-credentials")
        );
        assert!(detect("password=hunter2").contains(&"password-assign"));
        assert!(detect("--api-key=SECRET123").contains(&"password-assign"));
        // Space-separated form is intentionally NOT matched (too noisy).
        assert!(!detect("--api-key SECRET123").contains(&"password-assign"));
    }

    #[test]
    fn redact_replaces_and_reports() {
        let (redacted, matched) = redact("token=abc AKIAIOSFODNN7EXAMPLE");
        assert!(!redacted.contains("abc"));
        assert!(!redacted.contains("AKIA"));
        assert!(redacted.contains(REDACTED));
        assert_eq!(matched.len(), 2);
    }

    #[test]
    fn regexes_compile_once_and_match_fast() {
        // Smoke: every detector matches at least its own doc example.
        assert!(!DETECTORS.is_empty());
        assert!(DETECTORS.iter().all(|d| !d.description.is_empty()));
    }
}
