//! `ewf-tool`: write, inspect, verify and dump EWF-E01 images. Output is JSON on stdout.
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use veritas_ewf::{Compression, EwfOptions, EwfReader, EwfWriter};

#[derive(Parser)]
#[command(name = "ewf-tool", version, about = "EWF-E01 writer, reader and verifier")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write <input> into an E01 segment set at <out_base>.E01, .E02, ...
    Write {
        input: PathBuf,
        out_base: PathBuf,
        #[arg(long)]
        segment_size: Option<u64>,
        #[arg(long, default_value = "fast")]
        compression: String,
        #[arg(long, default_value = "")]
        case: String,
        #[arg(long, default_value = "")]
        evidence: String,
        #[arg(long, default_value = "")]
        examiner: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long, default_value = "")]
        notes: String,
    },
    /// Print segment, volume, header and stored-hash information.
    Info { e01: PathBuf },
    /// Re-hash the media and compare with the stored hashes (exit 1 on mismatch).
    Verify { e01: PathBuf },
    /// Write the media bytes to <out_raw> (refuses to overwrite).
    Dump { e01: PathBuf, out_raw: PathBuf },
}

fn run(cli: Cli) -> Result<bool, Box<dyn std::error::Error>> {
    match cli.cmd {
        Cmd::Write { input, out_base, segment_size, compression, case, evidence, examiner, description, notes } => {
            let mut opts = EwfOptions::default();
            if let Some(s) = segment_size {
                opts.segment_size = s;
            }
            opts.compression = Compression::parse(&compression).ok_or("compression must be none, fast or best")?;
            opts.header.case_number = case;
            opts.header.evidence_number = evidence;
            opts.header.examiner_name = examiner;
            opts.header.description = description;
            opts.header.notes = notes;
            let mut w = EwfWriter::create(&out_base, opts)?;
            let mut f = File::open(&input)?;
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                w.write(&buf[..n])?;
            }
            let summary = w.finish()?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(true)
        }
        Cmd::Info { e01 } => {
            let r = EwfReader::open(&e01)?;
            println!("{}", serde_json::to_string_pretty(&r.info())?);
            Ok(true)
        }
        Cmd::Verify { e01 } => {
            let mut r = EwfReader::open(&e01)?;
            let report = r.verify()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(report.verified)
        }
        Cmd::Dump { e01, out_raw } => {
            let mut r = EwfReader::open(&e01)?;
            let out = OpenOptions::new().write(true).create_new(true).open(&out_raw)?;
            let mut out = BufWriter::new(out);
            let mut buf = vec![0u8; 1 << 20];
            let mut total = 0u64;
            loop {
                let n = r.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n])?;
                total += n as u64;
            }
            out.flush()?;
            println!("{}", serde_json::json!({ "bytes": total, "out": out_raw }));
            Ok(true)
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("{}", serde_json::json!({ "error": e.to_string() }));
            ExitCode::from(2)
        }
    }
}
