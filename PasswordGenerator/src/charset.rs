//! Character sets for password generation.
//!
//! The filtered sets exclude ambiguous characters (`l`, `O`, `I`, `0`, `1`,
//! quotes, backticks, backslash, …) for readability and shell safety.
//! The `ALL_*` variants cover the full printable ASCII ranges.

/// Lowercase letters without ambiguous `l`.
pub const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
/// Uppercase letters without ambiguous `I`/`O`.
pub const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
/// Digits without ambiguous `0`/`1`.
pub const DIGITS: &str = "23456789";
/// Shell-friendlier symbol subset (no quotes, backtick, backslash, `|`).
pub const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/~";

/// Full lowercase ASCII range (ambiguous included).
pub const ALL_LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
/// Full uppercase ASCII range (ambiguous included).
pub const ALL_UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Full digit range (ambiguous included).
pub const ALL_DIGITS: &str = "0123456789";
/// Full printable-ASCII symbol range (ambiguous included).
pub const ALL_SYMBOLS: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/// Deduplicate a string into its unique characters, preserving order.
///
/// Working with `char`s (not bytes) keeps `--custom` sets Unicode-safe:
/// each Unicode scalar value counts as one character.
pub fn unique_chars(s: &str) -> Vec<char> {
    let mut out = Vec::new();
    for c in s.chars() {
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unique_chars() {
        assert_eq!(unique_chars("aabc"), vec!['a', 'b', 'c']);
        assert_eq!(unique_chars("ééü").len(), 2);
    }

    #[test]
    fn test_filtered_sets_exclude_ambiguous() {
        assert!(!LOWER.contains('l'));
        assert!(!UPPER.contains('O') && !UPPER.contains('I'));
        assert!(!DIGITS.contains('0') && !DIGITS.contains('1'));
        assert!(ALL_LOWER.contains('l') && ALL_UPPER.contains('O'));
    }
}
