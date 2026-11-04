//! `veritas-agent` command line. Results go to stdout as JSON; progress goes to stderr as JSON
//! lines. Key passphrases come from `--passphrase-file` or `VERITAS_KEY_PASSPHRASE`, never from a
//! command-line argument (which would be recorded in the ledger's command line and process lists).
#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use veritas_agent::image::{self, ImageOptions, OutputFormat};
use veritas_agent::memory::{self, MemoryConfig, MemoryTool, SystemRunner};
use veritas_agent::transfer::{TlsConfig, UploadClient, UploadManifest};
use veritas_agent::triage::{self, Profile, TriageOptions};
use veritas_agent::{ledger_hook, writeblock};
use veritas_ewf::Compression;
use veritas_ledger::keys::ExaminerKey;
use veritas_ledger::DeviceInfo;

#[derive(Parser)]
#[command(
    name = "veritas-agent",
    version,
    about = "Veritas DFIR acquisition agent"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args, Clone)]
struct LedgerArgs {
    /// JSON Lines custody ledger to append an Acquire entry to.
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// Encrypted operator key (from `veritas-agent keygen`).
    #[arg(long)]
    key: Option<PathBuf>,
    /// File holding the key passphrase (default: VERITAS_KEY_PASSPHRASE).
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
    #[arg(long, default_value = "")]
    case: String,
    #[arg(long, default_value = "")]
    evidence: String,
    #[arg(long, default_value = "")]
    examiner: String,
    /// Skip the SNTP clock measurement.
    #[arg(long)]
    no_ntp: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Live triage into a ZIP bundle with a hashed manifest.
    Triage {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "quick")]
        profile: String,
        /// Per-file size cap in bytes.
        #[arg(long, default_value_t = 512 * 1024 * 1024)]
        max_file_bytes: u64,
        /// Comma-separated collector names to run (default: all).
        #[arg(long)]
        only: Option<String>,
        #[command(flatten)]
        ledger: LedgerArgs,
    },
    /// Image a device or file to E01 or raw.
    Image {
        #[arg(long)]
        source: PathBuf,
        /// Output path without extension.
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "e01")]
        format: String,
        #[arg(long)]
        segment_size: Option<u64>,
        #[arg(long, default_value_t = 512)]
        sector_size: u32,
        /// Source size override in bytes.
        #[arg(long)]
        size: Option<u64>,
        #[arg(long, default_value = "fast")]
        compression: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long, default_value = "")]
        notes: String,
        /// Resume from the state file `<out>.state.json` (raw format).
        #[arg(long)]
        resume: bool,
        #[command(flatten)]
        ledger: LedgerArgs,
    },
    /// Capture physical memory with WinPmem, LiME or osxpmem.
    Memory {
        #[arg(long)]
        tool: Option<String>,
        /// Path to the tool binary (or lime.ko).
        #[arg(long)]
        binary: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
        #[command(flatten)]
        ledger: LedgerArgs,
    },
    /// Upload segments listed in a manifest over mTLS, resuming where a previous run stopped.
    Upload {
        #[arg(long)]
        server: String,
        #[arg(long)]
        client_cert: Option<PathBuf>,
        #[arg(long)]
        client_key: Option<PathBuf>,
        #[arg(long)]
        ca: Option<PathBuf>,
        manifest: PathBuf,
    },
    /// Generate an encrypted operator signing key.
    Keygen {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
}

fn passphrase(file: Option<&Path>) -> Result<String> {
    if let Some(f) = file {
        let s = std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
        return Ok(s.trim_end_matches(['\r', '\n']).to_string());
    }
    std::env::var("VERITAS_KEY_PASSPHRASE")
        .map_err(|_| anyhow!("set VERITAS_KEY_PASSPHRASE or pass --passphrase-file"))
}

fn progress_line(v: serde_json::Value) {
    eprintln!("{}", v);
}

fn ledger_append(
    args: &LedgerArgs,
    hashes: veritas_hash::Hashes,
    device: DeviceInfo,
    purpose: &str,
    details: BTreeMap<String, serde_json::Value>,
) -> Result<Option<serde_json::Value>> {
    let (Some(ledger), Some(key_path)) = (&args.ledger, &args.key) else {
        if args.ledger.is_some() || args.key.is_some() {
            bail!("--ledger and --key must be given together");
        }
        return Ok(None);
    };
    let key = ExaminerKey::load_encrypted(key_path, &passphrase(args.passphrase_file.as_deref())?)?;
    let acq = ledger_hook::Acquisition {
        case_id: args.case.clone(),
        evidence_id: if args.evidence.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            args.evidence.clone()
        },
        actor: if args.examiner.is_empty() {
            std::env::var("USERNAME")
                .or_else(|_| std::env::var("USER"))
                .unwrap_or_default()
        } else {
            args.examiner.clone()
        },
        purpose: purpose.to_string(),
        hashes,
        device,
        details,
    };
    let entry = ledger_hook::record_acquisition(ledger, &key, &acq, !args.no_ntp)?;
    Ok(Some(
        json!({ "ledger": ledger, "seq": entry.body.seq, "entry_hash": entry.entry_hash }),
    ))
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Keygen {
            out,
            passphrase_file,
        } => {
            let pass = passphrase(passphrase_file.as_deref())?;
            if pass.len() < 12 {
                bail!("passphrase must be at least 12 characters");
            }
            if out.exists() {
                bail!("refusing to overwrite {}", out.display());
            }
            let key = ExaminerKey::generate();
            key.save_encrypted(&out, &pass)?;
            println!(
                "{}",
                json!({ "key_id": key.key_id(), "public_key": key.public_key_hex(), "out": out })
            );
        }
        Cmd::Triage {
            out,
            profile,
            max_file_bytes,
            only,
            ledger,
        } => {
            let profile = match profile.as_str() {
                "quick" => Profile::Quick,
                "full" => Profile::Full,
                p => bail!("unknown profile {}", p),
            };
            let opts = TriageOptions {
                profile,
                max_file_bytes,
                only: only.map(|s| s.split(',').map(|x| x.trim().to_string()).collect()),
                ..Default::default()
            };
            let manifest = triage::run_triage(&out, &opts, &mut |name, i, n| {
                progress_line(json!({ "event": "collector", "name": name, "index": i, "total": n }))
            })?;
            let hashes = veritas_hash::hash_reader(std::fs::File::open(&out)?, |_| {})?;
            let device = DeviceInfo {
                description: "live triage bundle".into(),
                host: ledger_hook::host_name(),
                ..Default::default()
            };
            let mut details = BTreeMap::new();
            details.insert("bundle".into(), json!(out));
            details.insert("profile".into(), json!(profile.as_str()));
            details.insert("files".into(), json!(manifest.files.len()));
            details.insert("errors".into(), json!(manifest.errors.len()));
            let ledger_out =
                ledger_append(&ledger, hashes.clone(), device, "live triage", details)?;
            println!(
                "{}",
                json!({ "bundle": out, "files": manifest.files.len(), "errors": manifest.errors.len(), "hashes": hashes, "ledger": ledger_out })
            );
        }
        Cmd::Image {
            source,
            out,
            format,
            segment_size,
            sector_size,
            size,
            compression,
            description,
            notes,
            resume,
            ledger,
        } => {
            let format =
                OutputFormat::parse(&format).ok_or_else(|| anyhow!("format must be e01 or raw"))?;
            let wb = writeblock::check(&source);
            progress_line(json!({ "event": "writeblock", "status": wb }));
            let mut opts = ImageOptions::new(format, &out);
            opts.segment_size = segment_size;
            opts.sector_size = sector_size;
            opts.size = size;
            opts.compression = Compression::parse(&compression)
                .ok_or_else(|| anyhow!("compression must be none, fast or best"))?;
            let src_s = source.to_string_lossy().to_ascii_lowercase();
            opts.physical = src_s.starts_with(r"\\.\physicaldrive") || src_s.starts_with("/dev/");
            opts.case_number = ledger.case.clone();
            opts.evidence_number = ledger.evidence.clone();
            opts.examiner = ledger.examiner.clone();
            opts.description = description;
            opts.notes = notes;
            let state = PathBuf::from(format!("{}.state.json", out.display()));
            if state.exists() && !resume {
                bail!(
                    "{} exists from an interrupted run; pass --resume to continue",
                    state.display()
                );
            }
            opts.state_file = Some(state);
            let mut last = std::time::Instant::now();
            let result = image::image_path(&source, &opts, &mut |p| {
                if last.elapsed() >= Duration::from_secs(1) {
                    progress_line(
                        json!({ "event": "progress", "bytes": p.bytes_done, "total": p.total, "bad_sectors": p.bad_sectors, "segment": p.segment }),
                    );
                    last = std::time::Instant::now();
                }
                true
            })?;
            let evidence_id = if ledger.evidence.is_empty() {
                uuid::Uuid::new_v4().to_string()
            } else {
                ledger.evidence.clone()
            };
            let manifest = UploadManifest::from_segments(
                &evidence_id,
                if ledger.case.is_empty() {
                    None
                } else {
                    Some(&ledger.case)
                },
                &result.segments,
            );
            let manifest_path = PathBuf::from(format!("{}.manifest.json", out.display()));
            std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
            let device = DeviceInfo {
                description: source.display().to_string(),
                serial: None,
                model: None,
                size_bytes: Some(result.bytes),
                sector_size: Some(result.sector_size),
                write_blocked: wb.read_only,
                host: ledger_hook::host_name(),
            };
            let mut details = BTreeMap::new();
            details.insert("format".into(), json!(format));
            details.insert("segments".into(), json!(result.segments));
            details.insert("bad_sectors".into(), json!(result.bad_sectors));
            details.insert("writeblock".into(), json!(wb));
            if let Some(e) = &result.ewf {
                details.insert("ewf_sha1".into(), json!(e.sha1));
                details.insert("ewf_media_md5".into(), json!(e.hashes.md5));
            }
            let mut largs = ledger.clone();
            largs.evidence = evidence_id;
            let ledger_out =
                ledger_append(&largs, result.hashes.clone(), device, "disk image", details)?;
            println!(
                "{}",
                json!({ "result": result, "manifest": manifest_path, "ledger": ledger_out })
            );
        }
        Cmd::Memory {
            tool,
            binary,
            out,
            ledger,
        } => {
            let tool = match tool {
                Some(t) => MemoryTool::parse(&t)
                    .ok_or_else(|| anyhow!("tool must be winpmem, lime or osxpmem"))?,
                None => MemoryTool::default_for_os()
                    .ok_or_else(|| anyhow!("no memory tool for this OS"))?,
            };
            let cap = memory::capture(
                &MemoryConfig {
                    tool,
                    binary,
                    output: out.clone(),
                    extra_args: vec![],
                },
                &SystemRunner,
            )?;
            let device = DeviceInfo {
                description: "physical memory".into(),
                host: ledger_hook::host_name(),
                size_bytes: Some(cap.hashes.length),
                ..Default::default()
            };
            let mut details = BTreeMap::new();
            details.insert("capture".into(), serde_json::to_value(&cap)?);
            let ledger_out = ledger_append(
                &ledger,
                cap.hashes.clone(),
                device,
                "memory capture",
                details,
            )?;
            println!("{}", json!({ "capture": cap, "ledger": ledger_out }));
        }
        Cmd::Upload {
            server,
            client_cert,
            client_key,
            ca,
            manifest,
        } => {
            let tls = match (client_cert, client_key, ca) {
                (Some(c), Some(k), Some(a)) => Some(TlsConfig {
                    client_cert: c,
                    client_key: k,
                    ca: a,
                }),
                (None, None, None) => None,
                _ => bail!("--client-cert, --client-key and --ca must be given together"),
            };
            let mut m = UploadManifest::load(&manifest)?;
            m.resolve_paths(&manifest);
            let client = UploadClient::new(&server, tls.as_ref())?;
            let state = PathBuf::from(format!("{}.upload-state.json", manifest.display()));
            let report = client.upload(&m, Some(&state), &mut |i, s| {
                progress_line(json!({ "event": "segment", "index": i, "status": s }))
            })?;
            println!("{}", serde_json::to_string(&report)?);
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!(
                "{}",
                json!({ "event": "error", "error": format!("{:#}", e) })
            );
            ExitCode::from(1)
        }
    }
}
