//! Command-line interface definition and validation.

use anyhow::{Result, bail};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "password-generator",
    version,
    about = "Generate secure passwords and Diceware passphrases (CSPRNG)"
)]
/// Command-line interface definition and validation.
pub struct Cli {
    /// Length of the password (required unless --passphrase is used)
    #[arg(short = 'l', long = "length", required_unless_present = "passphrase")]
    pub length: Option<usize>,

    /// Generate a passphrase instead of a random password
    #[arg(short = 'p', long = "passphrase", conflicts_with = "length")]
    pub passphrase: bool,

    /// Number of words in passphrase (only with --passphrase)
    #[arg(
        short = 'w',
        long = "words",
        default_value_t = 4,
        requires = "passphrase"
    )]
    pub words: usize,

    /// Separator between words in passphrase
    #[arg(
        short = 'e',
        long = "separator",
        default_value = "-",
        requires = "passphrase"
    )]
    pub separator: String,

    /// Capitalize first letter of each passphrase word (+~1 bit/word, helps password policies)
    #[arg(long = "capitalize", requires = "passphrase")]
    pub capitalize: bool,

    /// Append a random digit to the passphrase (+~3.3 bits, helps password policies)
    #[arg(long = "with-number", requires = "passphrase")]
    pub with_number: bool,

    /// Number of passwords to generate
    #[arg(short = 'c', long = "count", default_value_t = 1)]
    pub count: usize,

    /// Copy the generated password to clipboard (only with --count 1)
    #[arg(short = 'y', long = "copy")]
    pub copy: bool,

    /// Do not print to stdout (useful with --copy to avoid shell history leaks)
    #[arg(long = "no-print", requires = "copy")]
    pub no_print: bool,

    /// Clear clipboard N seconds after copying (0 = do not clear)
    #[arg(long = "clear-after", default_value_t = 0, requires = "copy")]
    pub clear_after: u64,

    /// Print estimated entropy (bits) to stderr
    #[arg(long = "show-entropy")]
    pub show_entropy: bool,

    /// Use lowercase letters (default when no charset flag is given: all sets)
    #[arg(short = 'a', long = "lower", conflicts_with = "passphrase")]
    pub use_lower: bool,

    /// Use uppercase letters
    #[arg(short = 'u', long = "upper", conflicts_with = "passphrase")]
    pub use_upper: bool,

    /// Use digits
    #[arg(short = 'd', long = "digits", conflicts_with = "passphrase")]
    pub use_digits: bool,

    /// Use symbols
    #[arg(short = 's', long = "symbols", conflicts_with = "passphrase")]
    pub use_symbols: bool,

    /// Include ambiguous characters (l,1,O,0,I,|,`,',", etc.). Default: excluded.
    /// Old confusing name --no-ambiguous is kept as a hidden alias and behaves the same.
    #[arg(
        long = "include-ambiguous",
        alias = "no-ambiguous",
        conflicts_with = "passphrase"
    )]
    pub include_ambiguous: bool,

    /// Use custom character set (overrides -a/-u/-d/-s; supports Unicode).
    /// NOTE: each Unicode scalar value counts as one character.
    #[arg(
        long = "custom",
        conflicts_with = "passphrase",
        conflicts_with_all = ["use_lower", "use_upper", "use_digits", "use_symbols"]
    )]
    pub custom: Option<String>,
}

impl Cli {
    /// Cross-flag validation that clap's declarative rules cannot express.
    /// (Also enforces the DoS bounds from `password`/`passphrase`.)
    pub fn validate(&self) -> Result<()> {
        if self.count == 0 {
            bail!("--count must be positive");
        }
        if self.count > 1024 {
            bail!("--count exceeds 1024");
        }
        if let Some(length) = self.length {
            if length > crate::password::MAX_PASSWORD_LEN {
                bail!("--length exceeds {}", crate::password::MAX_PASSWORD_LEN);
            }
        }
        if self.passphrase {
            if self.words > crate::passphrase::MAX_WORDS {
                bail!("--words exceeds {}", crate::passphrase::MAX_WORDS);
            }
            if self.separator.chars().count() > crate::passphrase::MAX_SEPARATOR_CHARS {
                bail!(
                    "--separator exceeds {} chars",
                    crate::passphrase::MAX_SEPARATOR_CHARS
                );
            }
        }
        if self.copy && self.count > 1 {
            bail!(
                "Copying multiple passwords to clipboard is ambiguous. Use --count 1 or copy manually."
            );
        }
        if self.no_print && !self.copy {
            bail!("--no-print requires --copy (otherwise there would be no output)");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cli() -> Cli {
        Cli {
            length: Some(16),
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
    fn test_validate_ok() {
        assert!(base_cli().validate().is_ok());
    }

    #[test]
    fn test_validate_zero_count_rejected() {
        let mut cli = base_cli();
        cli.count = 0;
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_validate_copy_multiple_rejected() {
        let mut cli = base_cli();
        cli.copy = true;
        cli.count = 2;
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_validate_no_print_without_copy_rejected() {
        let mut cli = base_cli();
        cli.no_print = true;
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_validate_copy_no_print_ok() {
        let mut cli = base_cli();
        cli.copy = true;
        cli.no_print = true;
        assert!(cli.validate().is_ok());
    }
}
