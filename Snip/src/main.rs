//! Thin CLI wrapper: parse flags, call the library, report.

use anyhow::{Context, Result, bail};
use clap::Parser;
use std::io::{self, Read, Write};

use snip::cli::{Cli, Commands};
use snip::store::{self, Snippet};

fn confirm(prompt: &str, yes: bool) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    eprint!("{prompt} [y/N] ");
    io::stderr().flush().ok();
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .context("cannot read stdin")?;
    Ok(line.trim().eq_ignore_ascii_case("y"))
}

fn run_shell(command: &str) -> Result<bool> {
    #[cfg(windows)]
    let mut cmd = {
        let mut c = std::process::Command::new("powershell");
        c.args(["-NoProfile", "-Command", command]);
        c
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let mut c = std::process::Command::new("sh");
        c.args(["-c", command]);
        c
    };
    let status = cmd.status().context("cannot spawn shell")?;
    Ok(status.success())
}

/// Decrypt an age-encrypted import: identity file when `--age-identity` is
/// given, otherwise a terminal passphrase prompt for scrypt blobs.
fn decrypt_import(blob: &[u8], identity_path: Option<&std::path::Path>) -> Result<Vec<u8>> {
    if identity_path.is_some() || !secdetect::age_crypt::is_passphrase_blob(blob).unwrap_or(false) {
        return secdetect::age_crypt::decrypt_import_blob(blob, identity_path, None);
    }
    let passphrase = rpassword::prompt_password("age passphrase: ")
        .context("cannot read passphrase (not a terminal?)")?;
    secdetect::age_crypt::decrypt_import_blob(blob, None, Some(&passphrase))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let db_path = snip::resolve_db(cli.db.as_ref())?;
    let conn = store::open(&db_path)?;

    match cli.command {
        Commands::Init => {
            println!("initialized {}", db_path.display());
            Ok(())
        }
        Commands::Add {
            name,
            desc,
            tags,
            force,
            command,
        } => {
            let command = command.join(" ");
            if command.trim().is_empty() {
                bail!("command must not be empty");
            }
            if !force {
                snip::gate::gate(&command)?;
            }
            let now = store::now_unix();
            store::add(
                &conn,
                &Snippet {
                    name: name.clone(),
                    command,
                    description: desc,
                    tags,
                    created_at: now,
                    updated_at: now,
                    use_count: 0,
                },
            )?;
            println!("stored {name:?}");
            Ok(())
        }
        Commands::Get { name } => match store::get(&conn, &name)? {
            Some(s) => {
                println!("{}", s.command);
                Ok(())
            }
            None => bail!("no snippet named {name:?}"),
        },
        Commands::List { json } => {
            let all = store::list(&conn)?;
            if json {
                let redacted: Vec<serde_json::Value> = all
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "name": s.name,
                            "command": snip::gate::preview(&s.command, 120),
                            "description": s.description,
                            "tags": s.tags,
                            "use_count": s.use_count,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&redacted)?);
            } else {
                for s in &all {
                    println!("{}\t{}", s.name, snip::gate::preview(&s.command, 80));
                }
            }
            Ok(())
        }
        Commands::Search { query, limit, json } => {
            let all = store::list(&conn)?;
            let hits = snip::search(&all, &query, limit);
            if json {
                let out: Vec<serde_json::Value> = hits
                    .iter()
                    .map(|(s, score)| {
                        serde_json::json!({
                            "name": s.name,
                            "command": snip::gate::preview(&s.command, 120),
                            "score": score,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                for (s, _) in &hits {
                    println!("{}\t{}", s.name, snip::gate::preview(&s.command, 80));
                }
            }
            Ok(())
        }
        Commands::Exec { name, yes, dry_run } => {
            let Some(s) = store::get(&conn, &name)? else {
                bail!("no snippet named {name:?}");
            };
            if dry_run {
                println!("{}", s.command);
                return Ok(());
            }
            // The gate is bypassed for `--force`-stored secrets: warn loudly.
            let hits = secdetect::detect(&s.command);
            if !hits.is_empty() {
                eprintln!(
                    "warning: snippet {name:?} looks like it contains secret(s) [{}]; running it may leak them (shell history, process list)",
                    hits.join(",")
                );
            }
            if !confirm(&format!("run {:?}?", s.command), yes)? {
                bail!("aborted");
            }
            let ok = run_shell(&s.command)?;
            if ok {
                store::bump_use_count(&conn, &name)?;
            }
            if !ok {
                bail!("command exited non-zero");
            }
            Ok(())
        }
        Commands::Rm { name, yes } => {
            if store::get(&conn, &name)?.is_none() {
                bail!("no snippet named {name:?}");
            }
            if !confirm(&format!("delete snippet {name:?}?"), yes)? {
                bail!("aborted");
            }
            store::remove(&conn, &name)?;
            println!("removed {name:?}");
            Ok(())
        }
        Commands::Export {
            file,
            age_recipient,
        } => {
            let all = store::list(&conn)?;
            let risky = all
                .iter()
                .filter(|s| !secdetect::detect(&s.command).is_empty())
                .count();
            if risky > 0 {
                eprintln!(
                    "warning: exporting {risky} snippet(s) that look like they contain secrets — the export is RAW, treat it as sensitive"
                );
            }
            let json = serde_json::to_string_pretty(&all)?;
            if let Some(recipient) = age_recipient {
                let blob = secdetect::age_crypt::encrypt_to_recipient(json.as_bytes(), &recipient)?;
                match file {
                    Some(p) => {
                        std::fs::write(&p, &blob)
                            .with_context(|| format!("cannot write {}", p.display()))?;
                        println!(
                            "exported {} snippet(s), age-encrypted, to {}",
                            all.len(),
                            p.display()
                        );
                    }
                    None => {
                        use std::io::Write as _;
                        std::io::stdout()
                            .lock()
                            .write_all(&blob)
                            .context("cannot write stdout")?;
                    }
                }
                return Ok(());
            }
            match file {
                Some(p) => {
                    std::fs::write(&p, &json)
                        .with_context(|| format!("cannot write {}", p.display()))?;
                    println!("exported {} snippet(s) to {}", all.len(), p.display());
                }
                None => println!("{json}"),
            }
            Ok(())
        }
        Commands::Import {
            file,
            overwrite,
            force,
            age_identity,
        } => {
            let raw = match file {
                Some(p) => {
                    // DoS guard: refuse multi-hundred-MB "exports".
                    const MAX_IMPORT_BYTES: u64 = 10 * 1024 * 1024;
                    if let Ok(meta) = std::fs::metadata(&p) {
                        if meta.len() > MAX_IMPORT_BYTES {
                            bail!(
                                "import file {} is {} bytes (limit {MAX_IMPORT_BYTES})",
                                p.display(),
                                meta.len()
                            );
                        }
                    }
                    std::fs::read(&p).with_context(|| format!("cannot read {}", p.display()))?
                }
                None => {
                    let mut buf = Vec::new();
                    // Cap stdin as well (take 1 byte past the limit to detect overflow).
                    const MAX_IMPORT_BYTES: usize = 10 * 1024 * 1024;
                    io::stdin()
                        .take((MAX_IMPORT_BYTES + 1) as u64)
                        .read_to_end(&mut buf)
                        .context("cannot read stdin")?;
                    if buf.len() > MAX_IMPORT_BYTES {
                        bail!("import from stdin exceeds {MAX_IMPORT_BYTES} bytes");
                    }
                    buf
                }
            };
            let json = if secdetect::age_crypt::is_age_blob(&raw) {
                let plain = decrypt_import(&raw, age_identity.as_deref())?;
                String::from_utf8(plain).context("decrypted import is not valid UTF-8")?
            } else {
                if age_identity.is_some() {
                    eprintln!("note: --age-identity ignored: the import is not age-encrypted");
                }
                String::from_utf8(raw).context("import is not valid UTF-8")?
            };
            let items: Vec<Snippet> = serde_json::from_str(&json).context("invalid JSON export")?;
            if items.len() > 10_000 {
                bail!("import has {} items (limit 10000)", items.len());
            }
            let (mut added, mut skipped) = (0usize, 0usize);
            for item in items {
                if !force {
                    snip::gate::gate(&item.command)?;
                }
                if store::get(&conn, &item.name)?.is_some() {
                    if overwrite {
                        store::remove(&conn, &item.name)?;
                    } else {
                        skipped += 1;
                        continue;
                    }
                }
                store::add(&conn, &item)?;
                added += 1;
            }
            println!("imported {added}, skipped {skipped}");
            Ok(())
        }
    }
}
