use anyhow::{Context, Result, bail};
use arboard::Clipboard;
use clap::Parser;
use rand::{Rng, rngs::OsRng, seq::SliceRandom};

const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &[u8] = b"23456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/~";

const ALL_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const ALL_UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALL_DIGITS: &[u8] = b"0123456789";
const ALL_SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

const WORDS: &[&str] = &[
    "apple",
    "banana",
    "cherry",
    "date",
    "elder",
    "fig",
    "grape",
    "honey",
    "ice",
    "jazz",
    "kiwi",
    "lemon",
    "mango",
    "nectarine",
    "orange",
    "peach",
    "quince",
    "raspberry",
    "strawberry",
    "tangerine",
    "ugli",
    "vanilla",
    "watermelon",
    "xigua",
    "yam",
    "zucchini",
    "alpha",
    "bravo",
    "charlie",
    "delta",
    "echo",
    "foxtrot",
    "golf",
    "hotel",
    "india",
    "juliet",
    "kilo",
    "lima",
    "mike",
    "november",
    "oscar",
    "papa",
    "quebec",
    "romeo",
    "sierra",
    "tango",
    "uniform",
    "victor",
    "whiskey",
    "xray",
    "yankee",
    "zulu",
];

#[derive(Parser)]
#[command(
    name = "password_generator",
    version,
    about = "Generate secure passwords"
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

    /// Number of passwords to generate
    #[arg(short = 'c', long = "count", default_value_t = 1)]
    count: usize,

    /// Copy the generated password(s) to clipboard
    #[arg(short = 'y', long = "copy")]
    copy: bool,

    /// Use lowercase letters
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

    /// Exclude ambiguous characters (default: true; use --no-ambiguous to include them)
    #[arg(long = "no-ambiguous", conflicts_with = "passphrase")]
    no_ambiguous: bool,

    /// Use custom character set (overrides other sets)
    #[arg(long = "custom", conflicts_with = "passphrase")]
    custom: Option<String>,
}

fn generate_password(
    length: usize,
    mut use_lower: bool,
    mut use_upper: bool,
    mut use_digits: bool,
    mut use_symbols: bool,
    no_ambiguous: bool,
    custom: Option<&str>,
) -> Result<String> {
    if length == 0 {
        bail!("Length must be positive");
    }

    // Determine which character sets to use
    let mut charset = Vec::new();

    if let Some(custom_chars) = custom {
        if custom_chars.is_empty() {
            bail!("Custom set cannot be empty");
        }
        charset.extend_from_slice(custom_chars.as_bytes());
    } else {
        if !use_lower && !use_upper && !use_digits && !use_symbols {
            // Default: all sets
            use_lower = true;
            use_upper = true;
            use_digits = true;
            use_symbols = true;
        }

        let lower_set = if no_ambiguous { LOWER } else { ALL_LOWER };
        let upper_set = if no_ambiguous { UPPER } else { ALL_UPPER };
        let digits_set = if no_ambiguous { DIGITS } else { ALL_DIGITS };
        let symbols_set = if no_ambiguous { SYMBOLS } else { ALL_SYMBOLS };

        if use_lower {
            charset.extend_from_slice(lower_set);
        }
        if use_upper {
            charset.extend_from_slice(upper_set);
        }
        if use_digits {
            charset.extend_from_slice(digits_set);
        }
        if use_symbols {
            charset.extend_from_slice(symbols_set);
        }

        if charset.is_empty() {
            bail!("At least one character set must be enabled");
        }
    }

    let mut rng = OsRng;
    let mut password = Vec::with_capacity(length);

    // Ensure at least one character from each selected set if length allows and no custom set
    if custom.is_none() {
        let mut sets_used: Vec<&[u8]> = Vec::new();
        if use_lower {
            sets_used.push(if no_ambiguous { LOWER } else { ALL_LOWER });
        }
        if use_upper {
            sets_used.push(if no_ambiguous { UPPER } else { ALL_UPPER });
        }
        if use_digits {
            sets_used.push(if no_ambiguous { DIGITS } else { ALL_DIGITS });
        }
        if use_symbols {
            sets_used.push(if no_ambiguous { SYMBOLS } else { ALL_SYMBOLS });
        }

        if length >= sets_used.len() {
            for set in &sets_used {
                password.push(set[rng.gen_range(0..set.len())]);
            }
        }
    }

    while password.len() < length {
        password.push(charset[rng.gen_range(0..charset.len())]);
    }

    password.shuffle(&mut rng);

    String::from_utf8(password).map_err(|_| anyhow::anyhow!("Invalid UTF-8 in generated password"))
}

fn generate_passphrase(words: usize, separator: &str) -> Result<String> {
    if words == 0 {
        bail!("Number of words must be positive");
    }
    let mut rng = OsRng;
    let mut phrase = Vec::with_capacity(words);
    for _ in 0..words {
        let idx = rng.gen_range(0..WORDS.len());
        phrase.push(WORDS[idx]);
    }
    Ok(phrase.join(separator))
}

fn copy_to_clipboard(text: &str) -> Result<()> {
    let mut clipboard = Clipboard::new().context("Failed to access clipboard")?;
    clipboard
        .set_text(text.to_string())
        .context("Failed to set clipboard text")?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut generated = Vec::new();

    for _ in 0..cli.count {
        let password = if cli.passphrase {
            generate_passphrase(cli.words, &cli.separator)?
        } else {
            let length = cli.length.expect("length required unless passphrase");
            generate_password(
                length,
                cli.use_lower,
                cli.use_upper,
                cli.use_digits,
                cli.use_symbols,
                !cli.no_ambiguous,
                cli.custom.as_deref(),
            )?
        };
        generated.push(password);
    }

    // Output generated passwords
    for pw in &generated {
        println!("{}", pw);
    }

    if cli.copy {
        if generated.len() > 1 {
            bail!(
                "Copying multiple passwords to clipboard is ambiguous. Use --count 1 or copy manually."
            );
        }
        copy_to_clipboard(&generated[0])?;
        eprintln!("Password copied to clipboard.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_length() {
        let pw = generate_password(16, true, true, true, true, true, None).unwrap();
        assert_eq!(pw.len(), 16);
    }

    #[test]
    fn test_password_uses_sets() {
        let pw = generate_password(100, true, true, true, true, true, None).unwrap();
        assert!(pw.chars().any(|c| c.is_lowercase()));
        assert!(pw.chars().any(|c| c.is_uppercase()));
        assert!(pw.chars().any(|c| c.is_digit(10)));
        assert!(pw.chars().any(|c| !c.is_alphanumeric()));
    }

    #[test]
    fn test_passphrase() {
        let phrase = generate_passphrase(4, "-").unwrap();
        assert_eq!(phrase.split('-').count(), 4);
    }

    #[test]
    fn test_custom_charset() {
        let pw = generate_password(10, false, false, false, false, true, Some("abc123")).unwrap();
        assert!(pw.chars().all(|c| "abc123".contains(c)));
    }
}
