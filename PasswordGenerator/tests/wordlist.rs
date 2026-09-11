//! EFF wordlist integrity: size, uniqueness, shape, checksum.
//!
//! Canonical form: UTF-8 bytes of the words joined with `\n` plus a trailing
//! newline. Expected SHA-256 is documented in `src/words.rs`.

use password_generator::words::EFF_WORDS;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const EXPECTED_SHA256: &str = "6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522";

fn canonical_bytes() -> Vec<u8> {
    let mut out = String::new();
    for w in EFF_WORDS {
        out.push_str(w);
        out.push('\n');
    }
    out.into_bytes()
}

#[test]
fn wordlist_has_7776_entries() {
    // 7776 = 6^5, the Diceware standard.
    assert_eq!(EFF_WORDS.len(), 7776);
}

#[test]
fn wordlist_has_no_duplicates() {
    let unique: HashSet<&&str> = EFF_WORDS.iter().collect();
    assert_eq!(unique.len(), EFF_WORDS.len(), "duplicate words found");
}

#[test]
fn wordlist_words_are_lowercase_ascii_or_hyphen() {
    for w in EFF_WORDS {
        assert!(
            w.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
            "unexpected word shape: {w}"
        );
    }
}

#[test]
fn wordlist_checksum_matches_upstream() {
    let digest = Sha256::digest(canonical_bytes());
    assert_eq!(format!("{digest:x}"), EXPECTED_SHA256);
}
