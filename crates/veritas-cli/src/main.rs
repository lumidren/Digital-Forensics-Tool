//! `veritas`: umbrella command-line tool.
//!
//! Subcommands that need a specialised parser run the sibling binaries (`fs-tool`,
//! `veritas-artifacts-dump`, `ewf-tool`, `veritas-verify`, `veritas-agent`) found next to this
//! executable, so every tool keeps a single, separately hashed implementation.
#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Instant;
use veritas_store::crypto::{CaseKeyring, MasterKey};
use veritas_store::{ContentStore, LocalStore};

#[derive(Parser)]
#[command(name = "veritas", version, about = "Veritas DFIR command-line tool")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// MD5 + SHA-256 + SHA3-256 of a file (or an E01 image's media with --media).
    Hash {
        path: PathBuf,
        /// Hash the media inside an E01/raw-segmented image instead of the container file.
        #[arg(long)]
        media: bool,
    },
    /// Evidence store operations.
    Store {
        #[command(subcommand)]
        cmd: StoreCmd,
    },
    /// Parse an artifact or image to timeline events (JSON lines on stdout).
    Parse {
        /// evtx | evt | prefetch | lnk | jumplist | journald | plist | taskjob | taskxml | registry | fs | mft | usn | logfile
        kind: String,
        path: PathBuf,
    },
    /// Merge JSON-lines event files into one deterministically ordered timeline.
    Timeline {
        inputs: Vec<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a custody export (delegates to veritas-verify).
    Verify { export: PathBuf },
    /// Measure hashing and parsing throughput on local files.
    Bench {
        /// Files or images to process.
        inputs: Vec<PathBuf>,
        /// Repeat each measurement N times and report the median.
        #[arg(long, default_value_t = 3)]
        repeat: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum StoreCmd {
    /// Add a file to the store.
    Put {
        root: PathBuf,
        #[arg(long)]
        case: String,
        file: PathBuf,
    },
    /// List object addresses.
    List { root: PathBuf },
    /// Re-hash every object and compare with the hashes recorded at ingest.
    Verify { root: PathBuf },
}

fn sibling(name: &str) -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().context("executable has no parent directory")?;
    let file = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let p = dir.join(&file);
    if p.exists() {
        return Ok(p);
    }
    if let Ok(d) = std::env::var("VERITAS_BIN_DIR") {
        let p = Path::new(&d).join(&file);
        if p.exists() {
            return Ok(p);
        }
    }
    bail!("{name} not found next to veritas or in VERITAS_BIN_DIR")
}

fn keyring() -> Result<Option<CaseKeyring>> {
    match std::env::var("VERITAS_MASTER_KEY") {
        Ok(hex) => Ok(Some(CaseKeyring::new(
            MasterKey::from_hex(&hex).map_err(|e| anyhow::anyhow!("{e}"))?,
        ))),
        Err(_) => Ok(None),
    }
}

fn open_store(root: &Path) -> Result<LocalStore> {
    let s = LocalStore::open(root)?;
    Ok(match keyring()? {
        Some(k) => s.with_keyring(k),
        None => s,
    })
}

fn run_sibling(name: &str, args: &[&std::ffi::OsStr]) -> Result<i32> {
    let status = Command::new(sibling(name)?).args(args).status()?;
    Ok(status.code().unwrap_or(1))
}

#[derive(Serialize)]
struct BenchRow {
    input: String,
    bytes: u64,
    operation: String,
    median_seconds: f64,
    mb_per_s: f64,
    gb_per_hour: f64,
    events: Option<u64>,
}

fn time_median<F: FnMut() -> Result<Option<u64>>>(
    repeat: usize,
    mut f: F,
) -> Result<(f64, Option<u64>)> {
    let mut times = Vec::with_capacity(repeat);
    let mut events = None;
    for _ in 0..repeat.max(1) {
        let t = Instant::now();
        events = f()?;
        times.push(t.elapsed().as_secs_f64());
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Ok((times[times.len() / 2], events))
}

fn count_lines_of(cmd: &mut Command) -> Result<u64> {
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let out = child.stdout.take().context("no stdout")?;
    let n = BufReader::new(out).lines().count() as u64;
    let st = child.wait()?;
    if !st.success() {
        bail!("parser exited with {st}");
    }
    Ok(n)
}

fn parse_args(kind: &str, path: &Path) -> Result<(String, Vec<String>)> {
    let p = path.to_string_lossy().to_string();
    Ok(match kind {
        "fs" => ("fs-tool".into(), vec!["events".into(), p]),
        "mft" | "usn" | "logfile" => ("fs-tool".into(), vec![kind.into(), p, "--events".into()]),
        "evtx" | "evt" | "prefetch" | "lnk" | "jumplist" | "journald" | "plist" | "taskjob"
        | "taskxml" | "registry" => (
            "veritas-artifacts-dump".into(),
            vec![kind.into(), p, "--events".into()],
        ),
        other => bail!("unknown parse kind {other}"),
    })
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn real_main() -> Result<i32> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Hash { path, media } => {
            let h = if media {
                let lower = path.to_string_lossy().to_lowercase();
                if lower.ends_with(".e01") {
                    let r = veritas_ewf::reader::EwfReader::open(&path)?;
                    veritas_hash::hash_reader(r, |_| {})?
                } else {
                    let r = veritas_ewf::raw::RawSegmented::open(&path)?;
                    veritas_hash::hash_reader(r, |_| {})?
                }
            } else {
                veritas_hash::hash_reader(std::fs::File::open(&path)?, |_| {})?
            };
            println!("{}", serde_json::to_string_pretty(&h)?);
            Ok(0)
        }
        Cmd::Store { cmd } => match cmd {
            StoreCmd::Put { root, case, file } => {
                let store = open_store(&root)?;
                let mut f = std::fs::File::open(&file)?;
                let meta = store.put(&case, &mut f, file.file_name().and_then(|n| n.to_str()))?;
                println!("{}", serde_json::to_string_pretty(&meta)?);
                Ok(0)
            }
            StoreCmd::List { root } => {
                for a in open_store(&root)?.list()? {
                    println!("{a}");
                }
                Ok(0)
            }
            StoreCmd::Verify { root } => {
                // THREAT:T1.5 re-hash every stored object and compare with its ingest hashes.
                let results = open_store(&root)?.verify_all()?;
                let mut bad = 0;
                for r in &results {
                    match r {
                        Ok(a) => println!("OK   {a}"),
                        Err(e) => {
                            bad += 1;
                            println!("FAIL {e}");
                        }
                    }
                }
                println!("{} objects, {} failures", results.len(), bad);
                println!("{}", if bad == 0 { "PASS" } else { "FAIL" });
                Ok(if bad == 0 { 0 } else { 1 })
            }
        },
        Cmd::Parse { kind, path } => {
            let (bin, args) = parse_args(&kind, &path)?;
            let os: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
            let refs: Vec<&std::ffi::OsStr> = os.iter().map(|s| s.as_os_str()).collect();
            run_sibling(&bin, &refs)
        }
        Cmd::Timeline { inputs, out } => {
            let mut events: Vec<veritas_timeline::Event> = Vec::new();
            for p in &inputs {
                let f = BufReader::new(
                    std::fs::File::open(p).with_context(|| format!("open {}", p.display()))?,
                );
                for (i, line) in f.lines().enumerate() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    events.push(
                        serde_json::from_str(&line)
                            .with_context(|| format!("{}:{}", p.display(), i + 1))?,
                    );
                }
            }
            let mut sink: Box<dyn Write> = match out {
                Some(p) => Box::new(std::io::BufWriter::new(std::fs::File::create(p)?)),
                None => Box::new(std::io::BufWriter::new(std::io::stdout().lock())),
            };
            veritas_timeline::write_jsonl(&mut events, &mut sink)?;
            sink.flush()?;
            eprintln!("{} events", events.len());
            Ok(0)
        }
        Cmd::Verify { export } => {
            run_sibling("veritas-verify", &["export".as_ref(), export.as_os_str()])
        }
        Cmd::Bench {
            inputs,
            repeat,
            json,
        } => {
            let mut rows = Vec::new();
            for p in &inputs {
                let bytes = std::fs::metadata(p)?.len();
                let (secs, _) = time_median(repeat, || {
                    let mut f = std::fs::File::open(p)?;
                    let mut buf = vec![0u8; 4 << 20];
                    let mut h = veritas_hash::MultiHasher::new();
                    loop {
                        let n = f.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        h.update(&buf[..n]);
                    }
                    let _ = h.finalize();
                    Ok(None)
                })?;
                rows.push(row(p, bytes, "hash (md5+sha256+sha3)", secs, None));
                let name = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                let kind = if name.ends_with(".evtx") {
                    Some("evtx")
                } else if name.ends_with(".pf") {
                    Some("prefetch")
                } else if name == "mft" || name == "$mft" {
                    Some("mft")
                } else if [
                    "ntuser.dat",
                    "system",
                    "software",
                    "sam",
                    "usrclass.dat",
                    "amcache.hve",
                ]
                .contains(&name.as_str())
                {
                    Some("registry")
                } else if name.ends_with(".raw") || name.ends_with(".dd") || name.ends_with(".img")
                {
                    Some("fs")
                } else {
                    None
                };
                if let Some(kind) = kind {
                    let (bin, args) = parse_args(kind, p)?;
                    let exe = sibling(&bin)?;
                    let (secs, events) = time_median(repeat, || {
                        Ok(Some(count_lines_of(Command::new(&exe).args(&args))?))
                    })?;
                    rows.push(row(p, bytes, &format!("parse {kind}"), secs, events));
                }
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                println!(
                    "{:<40} {:>12} {:<26} {:>10} {:>10} {:>10}",
                    "input", "bytes", "operation", "MB/s", "GB/h", "events"
                );
                for r in &rows {
                    println!(
                        "{:<40} {:>12} {:<26} {:>10.1} {:>10.1} {:>10}",
                        r.input,
                        r.bytes,
                        r.operation,
                        r.mb_per_s,
                        r.gb_per_hour,
                        r.events.map(|e| e.to_string()).unwrap_or_default()
                    );
                }
            }
            Ok(0)
        }
    }
}

fn row(p: &Path, bytes: u64, op: &str, secs: f64, events: Option<u64>) -> BenchRow {
    let mbs = if secs > 0.0 {
        bytes as f64 / 1e6 / secs
    } else {
        0.0
    };
    BenchRow {
        input: p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string(),
        bytes,
        operation: op.to_string(),
        median_seconds: secs,
        mb_per_s: mbs,
        gb_per_hour: mbs * 3600.0 / 1000.0,
        events,
    }
}
