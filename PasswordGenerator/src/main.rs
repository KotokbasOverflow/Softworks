mod words;

use anyhow::{Context, Result, bail};
use arboard::Clipboard;
use clap::Parser;
use rand::{Rng, seq::SliceRandom};
use words::EFF_WORDS;
use zeroize::Zeroizing;

const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &str = "23456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/~";

const ALL_LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const ALL_UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALL_DIGITS: &str = "0123456789";
const ALL_SYMBOLS: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

// log2(7776) ~= 12.92 bits per word
const BITS_PER_EFF_WORD: f64 = 12.92;

#[derive(Parser)]
#[command(
    name = "password-generator",
    version,
    about = "Generate secure passwords and Diceware passphrases (CSPRNG)"
)]
struct Cli {
    /// Length of the password (required unless --passphrase is used)
    #[arg(short = 'l', long = "length", required_unless_present = "passphrase")]
    length: Option<usize>,

    /// Generate a passphrase instead of a random password
    #[arg(short = 'p', long = "passphrase", conflicts_with = "length")]
    passphrase: bool,

    /// Number of words in passphrase (only with --passphrase)
    #[arg(
        short = 'w',
        long = "words",
        default_value_t = 4,
        requires = "passphrase"
    )]
    words: usize,

    /// Separator between words in passphrase
    #[arg(
        short = 'e',
        long = "separator",
        default_value = "-",
        requires = "passphrase"
    )]
    separator: String,

    /// Capitalize first letter of each passphrase word (+~1 bit/word, helps password policies)
    #[arg(long = "capitalize", requires = "passphrase")]
    capitalize: bool,

    /// Append a random digit to the passphrase (+~3.3 bits, helps password policies)
    #[arg(long = "with-number", requires = "passphrase")]
    with_number: bool,

    /// Number of passwords to generate
    #[arg(short = 'c', long = "count", default_value_t = 1)]
    count: usize,

    /// Copy the generated password to clipboard (only with --count 1)
    #[arg(short = 'y', long = "copy")]
    copy: bool,

    /// Do not print to stdout (useful with --copy to avoid shell history leaks)
    #[arg(long = "no-print", requires = "copy")]
    no_print: bool,

    /// Clear clipboard N seconds after copying (0 = do not clear)
    #[arg(long = "clear-after", default_value_t = 0, requires = "copy")]
    clear_after: u64,

    /// Print estimated entropy (bits) to stderr
    #[arg(long = "show-entropy")]
    show_entropy: bool,

    /// Use lowercase letters (default when no charset flag is given: all sets)
    #[arg(short = 'a', long = "lower", conflicts_with = "passphrase")]
    use_lower: bool,

    /// Use uppercase letters
    #[arg(short = 'u', long = "upper", conflicts_with = "passphrase")]
    use_upper: bool,

    /// Use digits
    #[arg(short = 'd', long = "digits", conflicts_with = "passphrase")]
    use_digits: bool,

    /// Use symbols
    #[arg(short = 's', long = "symbols", conflicts_with = "passphrase")]
    use_symbols: bool,

    /// Include ambiguous characters (l,1,O,0,I,|,`,',", etc.). Default: excluded.
    /// Old confusing name --no-ambiguous is kept as a hidden alias and behaves the same.
    #[arg(
        long = "include-ambiguous",
        alias = "no-ambiguous",
        conflicts_with = "passphrase"
    )]
    include_ambiguous: bool,

    /// Use custom character set (overrides -a/-u/-d/-s; supports Unicode).
    /// NOTE: each Unicode scalar value counts as one character.
    #[arg(
        long = "custom",
        conflicts_with = "passphrase",
        conflicts_with_all = ["use_lower", "use_upper", "use_digits", "use_symbols"]
    )]
    custom: Option<String>,
}

fn unique_chars(s: &str) -> Vec<char> {
    let mut out = Vec::new();
    for c in s.chars() {
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

fn generate_password(
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

    // Custom set path (Unicode-safe: work with chars, not bytes).
    if let Some(custom_chars) = custom {
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

fn password_entropy_bits(charset_size: usize, length: usize) -> f64 {
    if charset_size <= 1 {
        return 0.0;
    }
    length as f64 * (charset_size as f64).log2()
}

fn charset_size_for_cli(cli: &Cli) -> usize {
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

fn capitalize_word(w: &str) -> String {
    let mut chars = w.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

fn generate_passphrase(
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

fn passphrase_entropy_bits(words: usize, with_number: bool) -> f64 {
    let mut bits = words as f64 * BITS_PER_EFF_WORD;
    if with_number {
        bits += (10f64).log2(); // ~3.32
    }
    bits
}

fn copy_to_clipboard(text: &str) -> Result<()> {
    let mut clipboard = Clipboard::new().context("Failed to access clipboard")?;
    clipboard
        .set_text(text.to_string())
        .context("Failed to set clipboard text")?;
    Ok(())
}

fn clear_clipboard() -> Result<()> {
    let mut clipboard = Clipboard::new().context("Failed to access clipboard")?;
    clipboard
        .set_text(String::new())
        .context("Failed to clear clipboard")?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.count == 0 {
        bail!("--count must be positive");
    }
    if cli.copy && cli.count > 1 {
        bail!(
            "Copying multiple passwords to clipboard is ambiguous. Use --count 1 or copy manually."
        );
    }
    if cli.no_print && !cli.copy {
        bail!("--no-print requires --copy (otherwise there would be no output)");
    }

    let mut generated: Vec<Zeroizing<String>> = Vec::with_capacity(cli.count);

    for _ in 0..cli.count {
        let password = if cli.passphrase {
            Zeroizing::new(generate_passphrase(
                cli.words,
                &cli.separator,
                cli.capitalize,
                cli.with_number,
            )?)
        } else {
            let length = cli.length.expect("length required unless passphrase");
            generate_password(
                length,
                cli.use_lower,
                cli.use_upper,
                cli.use_digits,
                cli.use_symbols,
                cli.include_ambiguous,
                cli.custom.as_deref(),
            )?
        };
        generated.push(password);
    }

    if cli.show_entropy {
        if cli.passphrase {
            let bits = passphrase_entropy_bits(cli.words, cli.with_number);
            eprintln!(
                "Estimated entropy: {:.1} bits ({} EFF words, ~{:.1} bits/word{})",
                bits,
                cli.words,
                BITS_PER_EFF_WORD,
                if cli.with_number { " + digit" } else { "" }
            );
        } else if let Some(length) = cli.length {
            let cs = charset_size_for_cli(&cli);
            let bits = password_entropy_bits(cs, length);
            eprintln!(
                "Estimated entropy: {:.1} bits (length {} x charset {})",
                bits, length, cs
            );
        }
    }

    // Output generated passwords (suppressed with --no-print).
    if !cli.no_print {
        for pw in &generated {
            println!("{}", pw.as_str());
        }
    }

    if cli.copy {
        copy_to_clipboard(generated[0].as_str())?;
        if cli.no_print {
            eprintln!("Password copied to clipboard (not printed).");
        } else {
            eprintln!("Password copied to clipboard.");
        }
        if cli.clear_after > 0 {
            eprintln!(
                "Clearing clipboard in {}s... (Ctrl+C to keep)",
                cli.clear_after
            );
            std::thread::sleep(std::time::Duration::from_secs(cli.clear_after));
            clear_clipboard()?;
            eprintln!("Clipboard cleared.");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Filtered UPPER excludes O/I; unfiltered includes them. Over 200 chars the
        // unfiltered set is very likely to contain at least one of O/I — but to avoid
        // flakiness, assert on charset size helper instead.
        assert!(filtered.chars().all(|c| c.is_ascii_uppercase()));
        assert!(
            charset_size_for_cli(&Cli {
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
                use_upper: true,
                use_digits: false,
                use_symbols: false,
                include_ambiguous: true,
                custom: None,
            }) > charset_size_for_cli(&Cli {
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
                use_upper: true,
                use_digits: false,
                use_symbols: false,
                include_ambiguous: false,
                custom: None,
            })
        );
    }

    #[test]
    fn test_passphrase() {
        let phrase = generate_passphrase(4, "-", false, false).unwrap();
        assert_eq!(phrase.split('-').count(), 4);
    }

    #[test]
    fn test_passphrase_zero_words_rejected() {
        assert!(generate_passphrase(0, "-", false, false).is_err());
    }

    #[test]
    fn test_passphrase_words_from_eff_list() {
        let phrase = generate_passphrase(6, "-", false, false).unwrap();
        for w in phrase.split('-') {
            assert!(EFF_WORDS.contains(&w), "word not in EFF list: {w}");
        }
    }

    #[test]
    fn test_passphrase_capitalize_and_number() {
        let phrase = generate_passphrase(3, "-", true, true).unwrap();
        // 3 words + 1 digit = 4 parts
        let parts: Vec<&str> = phrase.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert!(
            parts[..3]
                .iter()
                .all(|w| w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false))
        );
        assert!(parts[3].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_eff_wordlist_size() {
        // 7776 = 6^5, the Diceware standard. Guards against accidental truncation.
        assert_eq!(EFF_WORDS.len(), 7776);
    }

    #[test]
    fn test_entropy_helpers_sane() {
        assert!(password_entropy_bits(70, 16) > 90.0);
        assert_eq!(password_entropy_bits(1, 16), 0.0);
        let e4 = passphrase_entropy_bits(4, false);
        assert!((e4 - 4.0 * BITS_PER_EFF_WORD).abs() < 0.01);
        assert!(passphrase_entropy_bits(4, true) > e4);
    }

    #[test]
    fn test_unique_chars() {
        assert_eq!(unique_chars("aabc"), vec!['a', 'b', 'c']);
        assert_eq!(unique_chars("ééü").len(), 2);
    }
}
