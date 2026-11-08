//! `aff4-tool`: write, inspect, verify and dump AFF4 disk images. Output is JSON on stdout.
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use veritas_aff4::{Aff4Options, Aff4Reader, Aff4Writer, Compression};

#[derive(Parser)]
#[command(
    name = "aff4-tool",
    version,
    about = "AFF4 (Standard v1.0 ImageStream) writer, reader and verifier"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write <input> into a new AFF4 container <out> (refuses to overwrite).
    Write {
        input: PathBuf,
        out: PathBuf,
        /// stored | deflate | raw-deflate | snappy
        #[arg(long, default_value = "deflate")]
        compression: String,
        #[arg(long, default_value_t = veritas_aff4::DEFAULT_CHUNK_SIZE)]
        chunk_size: u32,
        #[arg(long, default_value_t = veritas_aff4::DEFAULT_CHUNKS_PER_SEGMENT)]
        chunks_per_segment: u32,
        /// zlib level for deflate (0-9).
        #[arg(long, default_value_t = 6)]
        level: u32,
        /// Fixed creation time (RFC 3339); makes the output reproducible.
        #[arg(long)]
        fixed_time: Option<String>,
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
    /// Print volume, image, stream, map and stored-hash information.
    Info { aff4: PathBuf },
    /// Re-hash the media and compare with the stored hashes (exit 1 on mismatch).
    Verify { aff4: PathBuf },
    /// Write the media bytes to <out_raw> (refuses to overwrite).
    Dump { aff4: PathBuf, out_raw: PathBuf },
}

fn run(cli: Cli) -> Result<bool, Box<dyn std::error::Error>> {
    match cli.cmd {
        Cmd::Write {
            input,
            out,
            compression,
            chunk_size,
            chunks_per_segment,
            level,
            fixed_time,
            case,
            evidence,
            examiner,
            description,
            notes,
        } => {
            let mut opts = Aff4Options {
                chunk_size,
                chunks_per_segment,
                level,
                compression: Compression::parse(&compression)
                    .ok_or("compression must be stored, deflate, raw-deflate or snappy")?,
                ..Default::default()
            };
            if let Some(t) = fixed_time {
                opts.creation_time =
                    Some(chrono::DateTime::parse_from_rfc3339(&t)?.with_timezone(&chrono::Utc));
            }
            opts.case.case_number = case;
            opts.case.evidence_number = evidence;
            opts.case.examiner = examiner;
            opts.case.description = description;
            opts.case.notes = notes;
            let mut w = Aff4Writer::create(&out, opts)?;
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
        Cmd::Info { aff4 } => {
            let r = Aff4Reader::open(&aff4)?;
            println!("{}", serde_json::to_string_pretty(&r.info())?);
            Ok(true)
        }
        Cmd::Verify { aff4 } => {
            let mut r = Aff4Reader::open(&aff4)?;
            let report = r.verify()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(report.verified)
        }
        Cmd::Dump { aff4, out_raw } => {
            let mut r = Aff4Reader::open(&aff4)?;
            let out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&out_raw)?;
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
