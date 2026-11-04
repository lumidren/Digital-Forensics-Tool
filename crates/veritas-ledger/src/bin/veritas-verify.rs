//! `veritas-verify`: independent chain-of-custody verifier.
//!
//! Usage:
//!   veritas-verify export custody.json            # self-contained signed export
//!   veritas-verify ledger ledger.jsonl --registry keys.json [--anchors anchors.jsonl]
//!
//! Prints PASS or FAIL and exits 0 or 1. THREAT:T2.5
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use veritas_ledger::anchor::load_anchors;
use veritas_ledger::verify::{verify_export, verify_ledger, Report, Verdict};
use veritas_ledger::{CustodyExport, KeyRegistry, Ledger};

#[derive(Parser)]
#[command(
    name = "veritas-verify",
    version,
    about = "Re-validate a Veritas custody ledger from scratch"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Emit the full report as JSON instead of text.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify a signed custody export produced by the platform.
    Export { path: PathBuf },
    /// Verify a raw JSON Lines ledger against a key registry.
    Ledger {
        path: PathBuf,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        anchors: Option<PathBuf>,
    },
}

fn print_report(report: &Report, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).unwrap_or_default()
        );
        return;
    }
    println!("entries checked:    {}", report.entries_checked);
    println!("signatures checked: {}", report.signatures_checked);
    println!("anchors checked:    {}", report.anchors_checked);
    println!("chain head:         {}", report.head_hash);
    for f in &report.failures {
        match f.seq {
            Some(s) => println!("  FAIL seq {:>6} {:<18} {}", s, f.check, f.detail),
            None => println!("  FAIL {:<25} {}", f.check, f.detail),
        }
    }
    println!(
        "{}",
        if report.verdict == Verdict::Pass {
            "PASS"
        } else {
            "FAIL"
        }
    );
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result: Result<Report, String> = match cli.cmd {
        Cmd::Export { path } => std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {}", path.display(), e))
            .and_then(|t| {
                serde_json::from_str::<CustodyExport>(&t)
                    .map_err(|e| format!("not a custody export: {}", e))
            })
            .map(|export| verify_export(&export)),
        Cmd::Ledger {
            path,
            registry,
            anchors,
        } => (|| {
            let ledger = Ledger::load(&path).map_err(|e| e.to_string())?;
            let reg: KeyRegistry = serde_json::from_str(
                &std::fs::read_to_string(&registry).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            let anchors = match anchors {
                Some(p) => load_anchors(&p).map_err(|e| e.to_string())?,
                None => Vec::new(),
            };
            Ok(verify_ledger(&ledger.entries, &reg, &anchors))
        })(),
    };
    match result {
        Ok(report) => {
            print_report(&report, cli.json);
            if report.verdict == Verdict::Pass {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("error: {}", e);
            println!("FAIL");
            ExitCode::from(2)
        }
    }
}
