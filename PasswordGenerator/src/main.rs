//! Thin CLI wrapper: parse flags, generate via the library, print/copy.

use anyhow::Result;
use clap::Parser;
use password_generator::{
    Cli,
    clipboard::{clear_clipboard, copy_to_clipboard},
    generate_all,
    passphrase::{BITS_PER_EFF_WORD, passphrase_entropy_bits},
    password::{charset_size_for_cli, password_entropy_bits},
};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let generated = generate_all(&cli)?;

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

    // Output generated secrets (suppressed with --no-print).
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
