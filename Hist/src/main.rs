//! Thin CLI wrapper: parse flags, call the library, report.

use anyhow::{Context, Result, bail};
use clap::Parser;
use std::path::{Path, PathBuf};

use hist::cli::{Cli, Commands, FormatOpt, ShellOpt};
use hist::detectors::DETECTORS;
use hist::history::{self, HistoryFile, Shell};

fn resolve_targets(explicit: &[PathBuf], shell: Option<ShellOpt>) -> Result<Vec<HistoryFile>> {
    let mut out = Vec::new();
    if explicit.is_empty() {
        for (sh, path) in history::default_paths() {
            out.push(history::load(sh, path)?);
        }
        if out.is_empty() {
            bail!("no history files found; pass --history <path> explicitly");
        }
        return Ok(out);
    }
    for path in explicit {
        let sh = match shell {
            Some(ShellOpt::Powershell) => Shell::PowerShell,
            Some(ShellOpt::Bash) => Shell::Bash,
            Some(ShellOpt::Zsh) => Shell::Zsh,
            None => guess_shell(path),
        };
        out.push(history::load(sh, path.clone())?);
    }
    Ok(out)
}

fn guess_shell(path: &Path) -> Shell {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name.contains("zsh") {
        Shell::Zsh
    } else if name.contains("bash") {
        Shell::Bash
    } else {
        // PowerShell and bash share the one-command-per-line format.
        Shell::PowerShell
    }
}

fn print_scan(findings: &[hist::Finding], format: FormatOpt) -> Result<()> {
    match format {
        FormatOpt::Text => {
            for f in findings {
                println!(
                    "{}:{} [{}] [{}] {}",
                    f.file.display(),
                    f.line_no,
                    f.shell,
                    f.detectors.join(","),
                    f.preview
                );
            }
            eprintln!(
                "{} file(s), {} finding(s)",
                unique_files(findings),
                findings.len()
            );
        }
        FormatOpt::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(findings).context("cannot render JSON")?
            );
        }
    }
    Ok(())
}

fn unique_files(findings: &[hist::Finding]) -> usize {
    let mut files: Vec<&PathBuf> = findings.iter().map(|f| &f.file).collect();
    files.sort();
    files.dedup();
    files.len()
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan {
            history,
            shell,
            format,
        } => {
            let targets = resolve_targets(&history, shell)?;
            let mut findings = Vec::new();
            for t in &targets {
                findings.extend(hist::scan::scan_history(t));
            }
            print_scan(&findings, format)?;
            if findings.is_empty() {
                Ok(())
            } else {
                // Exit 1 on findings (like grep): scriptable in CI/hooks.
                std::process::exit(1);
            }
        }
        Commands::Clean {
            history,
            shell,
            dry_run,
            drop_lines,
        } => {
            let targets = resolve_targets(&history, shell)?;
            let mut total_changed = 0usize;
            for t in &targets {
                if dry_run {
                    let findings = hist::scan::scan_history(t);
                    println!(
                        "{}: {} line(s) would change ({} finding(s))",
                        t.path.display(),
                        findings
                            .iter()
                            .map(|f| f.line_no)
                            .collect::<std::collections::HashSet<_>>()
                            .len(),
                        findings.len()
                    );
                    total_changed += findings.len();
                    continue;
                }
                let stats = hist::clean::clean_history(t, drop_lines)?;
                println!(
                    "{}: {}/{} lines changed, backup at {}",
                    t.path.display(),
                    stats.lines_changed,
                    stats.lines_total,
                    stats.backup_path.display()
                );
                total_changed += stats.lines_changed;
            }
            eprintln!("total changed lines: {total_changed}");
            Ok(())
        }
        Commands::Detectors => {
            for d in DETECTORS.iter() {
                println!("{}\t{}", d.id, d.description);
            }
            Ok(())
        }
    }
}
