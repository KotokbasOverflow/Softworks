//! `password-generator` library: secure passwords and EFF Diceware passphrases.
//!
//! The binary (`src/main.rs`) is a thin CLI wrapper; all generation logic
//! lives here so it can be unit-tested and reused.

pub mod charset;
pub mod cli;
pub mod clipboard;
pub mod passphrase;
pub mod password;
pub mod words;

pub use cli::Cli;

use anyhow::Result;
use zeroize::Zeroizing;

/// Validate flags and generate `count` secrets (passwords or passphrases).
pub fn generate_all(cli: &Cli) -> Result<Vec<Zeroizing<String>>> {
    cli.validate()?;

    let mut generated = Vec::with_capacity(cli.count);
    for _ in 0..cli.count {
        let secret = if cli.passphrase {
            Zeroizing::new(passphrase::generate_passphrase(
                cli.words,
                &cli.separator,
                cli.capitalize,
                cli.with_number,
            )?)
        } else {
            let length = cli.length.expect("length required unless passphrase");
            password::generate_password(
                length,
                cli.use_lower,
                cli.use_upper,
                cli.use_digits,
                cli.use_symbols,
                cli.include_ambiguous,
                cli.custom.as_deref(),
            )?
        };
        generated.push(secret);
    }
    Ok(generated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli_with_length(length: usize) -> Cli {
        Cli {
            length: Some(length),
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
            use_upper: false,
            use_digits: false,
            use_symbols: false,
            include_ambiguous: false,
            custom: None,
        }
    }

    #[test]
    fn test_generate_all_count() {
        let mut cli = cli_with_length(12);
        cli.count = 3;
        let out = generate_all(&cli).unwrap();
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|s| s.chars().count() == 12));
    }

    #[test]
    fn test_generate_all_rejects_zero_count() {
        let mut cli = cli_with_length(12);
        cli.count = 0;
        assert!(generate_all(&cli).is_err());
    }

    #[test]
    fn test_generate_all_passphrase() {
        let cli = Cli {
            length: None,
            passphrase: true,
            words: 5,
            separator: " ".into(),
            capitalize: false,
            with_number: false,
            count: 2,
            copy: false,
            no_print: false,
            clear_after: 0,
            show_entropy: false,
            use_lower: false,
            use_upper: false,
            use_digits: false,
            use_symbols: false,
            include_ambiguous: false,
            custom: None,
        };
        let out = generate_all(&cli).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|s| s.split(' ').count() == 5));
    }
}
