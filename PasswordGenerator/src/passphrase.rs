//! Diceware passphrase generation over the embedded EFF wordlist.

use anyhow::{Result, bail};
use rand::Rng;

use crate::words::EFF_WORDS;

// log2(7776) ~= 12.92 bits per word
pub const BITS_PER_EFF_WORD: f64 = 12.92;

pub fn capitalize_word(w: &str) -> String {
    let mut chars = w.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

pub fn generate_passphrase(
    words: usize,
    separator: &str,
    capitalize: bool,
    with_number: bool,
) -> Result<String> {
    if words == 0 {
        bail!("Number of words must be positive");
    }
    if EFF_WORDS.is_empty() {
        bail!("Wordlist is empty");
    }
    let mut rng = rand::rng();
    let mut phrase: Vec<String> = Vec::with_capacity(words);
    for _ in 0..words {
        let idx = rng.random_range(0..EFF_WORDS.len());
        let w = EFF_WORDS[idx];
        if capitalize {
            phrase.push(capitalize_word(w));
        } else {
            phrase.push(w.to_string());
        }
    }
    let mut out = phrase.join(separator);
    if with_number {
        let d: u8 = rng.random_range(0..10);
        out.push_str(separator);
        out.push((b'0' + d) as char);
    }
    Ok(out)
}

pub fn passphrase_entropy_bits(words: usize, with_number: bool) -> f64 {
    let mut bits = words as f64 * BITS_PER_EFF_WORD;
    if with_number {
        bits += (10f64).log2(); // ~3.32
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: tests use " " as separator on purpose — 4 of the 7776 EFF words
    // contain a hyphen, so splitting on "-" is not a reliable word counter.

    #[test]
    fn test_passphrase() {
        let phrase = generate_passphrase(4, " ", false, false).unwrap();
        assert_eq!(phrase.split(' ').count(), 4);
    }

    #[test]
    fn test_passphrase_zero_words_rejected() {
        assert!(generate_passphrase(0, "-", false, false).is_err());
    }

    #[test]
    fn test_passphrase_words_from_eff_list() {
        let phrase = generate_passphrase(6, " ", false, false).unwrap();
        for w in phrase.split(' ') {
            assert!(EFF_WORDS.contains(&w), "word not in EFF list: {w}");
        }
    }

    #[test]
    fn test_passphrase_capitalize_and_number() {
        let phrase = generate_passphrase(3, " ", true, true).unwrap();
        // 3 words + 1 digit = 4 parts
        let parts: Vec<&str> = phrase.split(' ').collect();
        assert_eq!(parts.len(), 4);
        assert!(
            parts[..3]
                .iter()
                .all(|w| w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false))
        );
        assert!(parts[3].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_hyphenated_words_documented() {
        // Upstream EFF list contains exactly these hyphenated entries.
        for w in ["drop-down", "felt-tip", "t-shirt", "yo-yo"] {
            assert!(EFF_WORDS.contains(&w), "missing hyphenated word: {w}");
        }
    }

    #[test]
    fn test_entropy_helpers_sane() {
        let e4 = passphrase_entropy_bits(4, false);
        assert!((e4 - 4.0 * BITS_PER_EFF_WORD).abs() < 0.01);
        assert!(passphrase_entropy_bits(4, true) > e4);
    }
}
