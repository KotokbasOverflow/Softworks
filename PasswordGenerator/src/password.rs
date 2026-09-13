//! Random password generation (CSPRNG) and entropy estimation.

use anyhow::{Result, bail};
use rand::{Rng, seq::SliceRandom};
use zeroize::Zeroizing;

use crate::charset::{
    ALL_DIGITS, ALL_LOWER, ALL_SYMBOLS, ALL_UPPER, DIGITS, LOWER, SYMBOLS, UPPER, unique_chars,
};
use crate::cli::Cli;

/// Bounds: passwords are short secrets, not documents.
pub const MAX_PASSWORD_LEN: usize = 4096;
pub const MAX_CUSTOM_CHARS: usize = 1024;

/// Generate a password of `length` characters.
///
/// When no charset flag is set, all four sets are used. Guarantees at least
/// one character from each selected set when `length >= number of sets`;
/// shorter lengths fall back to pure random sampling (the guarantee is
/// then impossible).
pub fn generate_password(
    length: usize,
    mut use_lower: bool,
    mut use_upper: bool,
    mut use_digits: bool,
    mut use_symbols: bool,
    include_ambiguous: bool,
    custom: Option<&str>,
) -> Result<Zeroizing<String>> {
    if length == 0 {
        bail!("Length must be positive");
    }
    if length > MAX_PASSWORD_LEN {
        bail!("Length exceeds {MAX_PASSWORD_LEN}");
    }

    // Custom set path (Unicode-safe: work with chars, not bytes).
    if let Some(custom_chars) = custom {
        if custom_chars.chars().count() > MAX_CUSTOM_CHARS {
            bail!("Custom set exceeds {MAX_CUSTOM_CHARS} chars");
        }
        let charset = unique_chars(custom_chars);
        if charset.is_empty() {
            bail!("Custom set cannot be empty");
        }
        let mut rng = rand::rng();
        let mut password: Vec<char> = Vec::with_capacity(length);
        while password.len() < length {
            let idx = rng.random_range(0..charset.len());
            password.push(charset[idx]);
        }
        password.shuffle(&mut rng);
        return Ok(Zeroizing::new(password.into_iter().collect()));
    }

    if !use_lower && !use_upper && !use_digits && !use_symbols {
        // Default: all sets
        use_lower = true;
        use_upper = true;
        use_digits = true;
        use_symbols = true;
    }

    let lower_set = if include_ambiguous { ALL_LOWER } else { LOWER };
    let upper_set = if include_ambiguous { ALL_UPPER } else { UPPER };
    let digits_set = if include_ambiguous {
        ALL_DIGITS
    } else {
        DIGITS
    };
    let symbols_set = if include_ambiguous {
        ALL_SYMBOLS
    } else {
        SYMBOLS
    };

    let mut charset: Vec<char> = Vec::new();
    if use_lower {
        charset.extend(lower_set.chars());
    }
    if use_upper {
        charset.extend(upper_set.chars());
    }
    if use_digits {
        charset.extend(digits_set.chars());
    }
    if use_symbols {
        charset.extend(symbols_set.chars());
    }
    if charset.is_empty() {
        bail!("At least one character set must be enabled");
    }

    let mut rng = rand::rng();
    let mut password: Vec<char> = Vec::with_capacity(length);

    // Guarantee at least one char from each selected set when length allows.
    // If length < number of sets, the guarantee is impossible — document and
    // fall back to pure random sampling.
    let mut sets_used: Vec<Vec<char>> = Vec::new();
    if use_lower {
        sets_used.push(lower_set.chars().collect());
    }
    if use_upper {
        sets_used.push(upper_set.chars().collect());
    }
    if use_digits {
        sets_used.push(digits_set.chars().collect());
    }
    if use_symbols {
        sets_used.push(symbols_set.chars().collect());
    }

    if length >= sets_used.len() {
        for set in &sets_used {
            let idx = rng.random_range(0..set.len());
            password.push(set[idx]);
        }
    }

    while password.len() < length {
        let idx = rng.random_range(0..charset.len());
        password.push(charset[idx]);
    }

    password.shuffle(&mut rng);

    Ok(Zeroizing::new(password.into_iter().collect()))
}

/// Shannon entropy estimate: `length × log2(charset_size)` bits.
pub fn password_entropy_bits(charset_size: usize, length: usize) -> f64 {
    if charset_size <= 1 {
        return 0.0;
    }
    length as f64 * (charset_size as f64).log2()
}

/// Effective charset size for the given CLI flags (for `--show-entropy`).
pub fn charset_size_for_cli(cli: &Cli) -> usize {
    if let Some(custom) = &cli.custom {
        return unique_chars(custom).len();
    }
    let (mut lo, mut up, mut di, mut sy) = (
        cli.use_lower,
        cli.use_upper,
        cli.use_digits,
        cli.use_symbols,
    );
    if !lo && !up && !di && !sy {
        lo = true;
        up = true;
        di = true;
        sy = true;
    }
    let lower = if cli.include_ambiguous {
        ALL_LOWER.chars().count()
    } else {
        LOWER.chars().count()
    };
    let upper = if cli.include_ambiguous {
        ALL_UPPER.chars().count()
    } else {
        UPPER.chars().count()
    };
    let digits = if cli.include_ambiguous {
        ALL_DIGITS.chars().count()
    } else {
        DIGITS.chars().count()
    };
    let symbols = if cli.include_ambiguous {
        ALL_SYMBOLS.chars().count()
    } else {
        SYMBOLS.chars().count()
    };
    (if lo { lower } else { 0 })
        + (if up { upper } else { 0 })
        + (if di { digits } else { 0 })
        + (if sy { symbols } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cli(use_upper_only: bool, include_ambiguous: bool) -> Cli {
        Cli {
            length: Some(10),
            passphrase: false,
            words: 4,
            separator: "-".into(),
            capitalize: false,
            with_number: false,
            count: 1,
            copy: false,
            no_print: false,
            clear_after: 0,
            show_entropy: false,
            use_lower: false,
            use_upper: use_upper_only,
            use_digits: false,
            use_symbols: false,
            include_ambiguous,
            custom: None,
        }
    }

    #[test]
    fn test_password_length() {
        let pw = generate_password(16, true, true, true, true, false, None).unwrap();
        assert_eq!(pw.chars().count(), 16);
    }

    #[test]
    fn test_password_uses_sets() {
        let pw = generate_password(100, true, true, true, true, false, None).unwrap();
        let s = pw.as_str();
        assert!(s.chars().any(|c| c.is_lowercase()));
        assert!(s.chars().any(|c| c.is_uppercase()));
        assert!(s.chars().any(|c| c.is_ascii_digit()));
        assert!(s.chars().any(|c| !c.is_alphanumeric()));
    }

    #[test]
    fn test_password_zero_length_rejected() {
        assert!(generate_password(0, true, true, true, true, false, None).is_err());
    }

    #[test]
    fn test_password_custom_empty_rejected() {
        assert!(generate_password(10, false, false, false, false, false, Some("")).is_err());
    }

    #[test]
    fn test_custom_charset_unicode() {
        // Regression: old byte-based code returned Err on multi-byte custom sets.
        let pw = generate_password(20, false, false, false, false, false, Some("éüäöåβ✓")).unwrap();
        assert_eq!(pw.chars().count(), 20);
        assert!(pw.chars().all(|c| "éüäöåβ✓".contains(c)));
    }

    #[test]
    fn test_custom_charset_ascii() {
        let pw = generate_password(10, false, false, false, false, false, Some("abc123")).unwrap();
        assert!(pw.chars().all(|c| "abc123".contains(c)));
    }

    #[test]
    fn test_custom_dedup_does_not_panic() {
        let pw = generate_password(8, false, false, false, false, false, Some("aaa")).unwrap();
        assert_eq!(pw.as_str(), "aaaaaaaa");
    }

    #[test]
    fn test_short_length_no_guarantee_but_correct_len() {
        // length < num sets: cannot cover all sets, but must still return `length` chars.
        let pw = generate_password(2, true, true, true, true, false, None).unwrap();
        assert_eq!(pw.chars().count(), 2);
    }

    #[test]
    fn test_include_ambiguous_expands_charset() {
        let filtered = generate_password(200, false, true, false, false, false, None).unwrap();
        assert!(filtered.chars().all(|c| c.is_ascii_uppercase()));
        assert!(
            charset_size_for_cli(&test_cli(true, true))
                > charset_size_for_cli(&test_cli(true, false))
        );
    }

    #[test]
    fn test_entropy_helpers_sane() {
        assert!(password_entropy_bits(70, 16) > 90.0);
        assert_eq!(password_entropy_bits(1, 16), 0.0);
    }

    #[test]
    fn test_default_charset_is_all_sets() {
        let all = charset_size_for_cli(&test_cli(false, false));
        let only_upper = charset_size_for_cli(&test_cli(true, false));
        assert!(all > only_upper);
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn prop_length_invariant(
                len in 1usize..128,
                lo in proptest::bool::ANY,
                up in proptest::bool::ANY,
                di in proptest::bool::ANY,
                sy in proptest::bool::ANY,
            ) {
                // At least one set must be active for generation to succeed;
                // skip the all-off combination (it means "all sets" anyway).
                let pw = generate_password(len, lo, up, di, sy, false, None).unwrap();
                prop_assert_eq!(pw.chars().count(), len);
            }

            #[test]
            fn prop_custom_membership(
                len in 1usize..32,
                set in "[a-zA-Z0-9!@#]{1,16}",
            ) {
                let pw = generate_password(len, false, false, false, false, false, Some(&set)).unwrap();
                prop_assert_eq!(pw.chars().count(), len);
                prop_assert!(pw.chars().all(|c| set.contains(c)));
            }

            #[test]
            fn prop_unicode_custom_never_errors(
                len in 1usize..32,
            ) {
                // Multi-byte set that broke the old byte-based implementation.
                let pw = generate_password(len, false, false, false, false, false, Some("éüäöåβ✓")).unwrap();
                prop_assert_eq!(pw.chars().count(), len);
            }
        }
    }
}
