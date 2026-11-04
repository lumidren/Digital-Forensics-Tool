//! fs-tool: debug / pipeline CLI for veritas-fs. All JSON output is deterministic (sorted records,
//! fixed field order).
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use veritas_fs::image::{self, AnyFs, FsKind, ImageVolume};
use veritas_fs::io::{read_vec_padded, Source};
use veritas_fs::ntfs::{self, Ntfs};
use veritas_fs::{carve, events, harvest, recover, vss, FsError};

#[derive(Parser)]
#[command(name = "fs-tool", about = "Veritas file-system parser debug tool")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List partitions (MBR/GPT) as JSON lines.
    Partitions { image: PathBuf },
    /// Volume / file-system summary (incl. APFS volumes and snapshots, ext journal).
    Info { image: PathBuf },
    /// List entries as JSON lines (native per-file-system records with an added `fs_type`).
    Ls {
        image: PathBuf,
        #[arg(long)]
        partition: Option<usize>,
        #[arg(long, default_value = "/")]
        path: String,
        #[arg(short, long)]
        recursive: bool,
        /// Include deleted entries.
        #[arg(long)]
        deleted: bool,
        /// NTFS only: print the $I30 index of `path` including slack entries.
        #[arg(long)]
        index: bool,
    },
    /// Extract one file (NTFS accepts `path:stream`).
    Cat {
        image: PathBuf,
        path: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        partition: Option<usize>,
    },
    /// MFT records (raw `$MFT` extract or NTFS image) as JSON lines.
    Mft {
        input: PathBuf,
        #[arg(long)]
        partition: Option<usize>,
        /// Emit timeline events instead of native records.
        #[arg(long)]
        events: bool,
    },
    /// USN records (raw `$J` extract or NTFS image) as JSON lines.
    Usn {
        input: PathBuf,
        #[arg(long)]
        partition: Option<usize>,
        /// Emit timeline events instead of native records.
        #[arg(long)]
        events: bool,
    },
    /// $LogFile restart areas and log records (raw extract or NTFS image) as JSON.
    Logfile {
        input: PathBuf,
        #[arg(long)]
        partition: Option<usize>,
        /// Emit timeline events instead of native records.
        #[arg(long)]
        events: bool,
    },
    /// Timeline events as JSON lines (sorted).
    Events {
        image: PathBuf,
        #[arg(long)]
        partition: Option<usize>,
    },
    /// Carve files from the raw image.
    Carve {
        image: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Volume shadow copy stores as JSON lines.
    Vss {
        image: PathBuf,
        #[arg(long)]
        partition: Option<usize>,
        /// Also hash every full store (slow on large volumes).
        #[arg(long)]
        full_hash: bool,
    },
    /// Timestomping findings as JSON lines.
    Timestomp {
        image: PathBuf,
        #[arg(long)]
        partition: Option<usize>,
    },
    /// Recover deleted files (NTFS, FAT).
    Recover {
        image: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        partition: Option<usize>,
    },
    /// Extract known forensic artifacts and write manifest.jsonl.
    Harvest {
        image: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        partition: Option<usize>,
        /// Per-file size cap in bytes.
        #[arg(long, default_value_t = harvest::DEFAULT_MAX_FILE_SIZE)]
        max_file_size: u64,
    },
}

type R<T> = Result<T, Box<dyn std::error::Error>>;

fn open(p: &Path) -> R<Source> {
    Ok(veritas_fs::io::open_evidence(p)?)
}

fn jl<T: Serialize>(out: &mut impl Write, v: &T) -> R<()> {
    serde_json::to_writer(&mut *out, v)?;
    out.write_all(b"\n")?;
    Ok(())
}

fn with_fs<T: Serialize>(fs_type: &str, v: &T) -> R<Value> {
    let mut val = serde_json::to_value(v)?;
    if let Value::Object(m) = &mut val {
        let mut n = serde_json::Map::new();
        n.insert("fs_type".into(), Value::String(fs_type.into()));
        for (k, x) in std::mem::take(m) {
            n.insert(k, x);
        }
        *m = n;
    }
    Ok(val)
}

fn in_scope(path: &str, base: &str, recursive: bool) -> bool {
    let base = if base == "/" {
        ""
    } else {
        base.trim_end_matches('/')
    };
    let Some(rest) = path.strip_prefix(base) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix('/') else {
        return false;
    };
    !rest.is_empty() && (recursive || !rest.contains('/'))
}

fn ntfs_volume(src: Source, partition: Option<usize>) -> R<(ImageVolume, Ntfs)> {
    let vols = image::volumes(src)?;
    let v = vols
        .into_iter()
        .find(|v| v.fs == FsKind::Ntfs && partition.is_none_or(|p| p == v.index))
        .ok_or_else(|| FsError::NotFound("NTFS volume".into()))?;
    let n = Ntfs::open(v.src.clone())?;
    Ok((v, n))
}

fn sha256_file(p: &Path) -> R<String> {
    let f = std::fs::File::open(p)?;
    Ok(veritas_hash::hash_reader(std::io::BufReader::new(f), |_| {})?.sha256)
}

fn run(cli: Cli) -> R<()> {
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    match cli.cmd {
        Cmd::Partitions { image } => {
            let src = open(&image)?;
            if let Some(vs) = veritas_fs::volume::detect(src.as_ref())? {
                for p in &vs.partitions {
                    jl(&mut out, p)?;
                }
                eprintln!(
                    "scheme={} header_crc_ok={:?} entries_crc_ok={:?}",
                    vs.scheme, vs.gpt_header_crc_ok, vs.gpt_entries_crc_ok
                );
            }
        }
        Cmd::Info { image } => {
            let src = open(&image)?;
            for v in image::volumes(src)? {
                let mut info = serde_json::json!({"partition": v.index, "offset": v.offset, "length": v.length, "description": v.description, "fs": v.fs.name()});
                if let Ok(fs) = AnyFs::open(&v) {
                    info["fs_type"] = Value::String(fs.type_name());
                    match &fs {
                        AnyFs::Apfs(a) => {
                            info["container"] = serde_json::to_value(&a.container)?;
                            let mut vols = Vec::new();
                            for (i, vi) in a.volumes.iter().enumerate() {
                                let mut j = serde_json::to_value(vi)?;
                                j["snapshots"] = match a.snapshots(i) {
                                    Ok(s) => serde_json::to_value(s)?,
                                    Err(e) => Value::String(format!("error: {e}")),
                                };
                                vols.push(j);
                            }
                            info["volumes"] = Value::Array(vols);
                        }
                        AnyFs::Ext(e) => {
                            info["superblock"] = serde_json::to_value(&e.sb)?;
                            if let Ok(j) = e.journal() {
                                info["journal"] = serde_json::json!({"block_size": j.block_size, "max_len": j.max_len, "sequence": j.sequence, "blocks": j.blocks});
                            }
                        }
                        AnyFs::Ntfs(n) => {
                            info["boot"] = serde_json::to_value(&n.boot)?;
                            info["vss"] = Value::Bool(vss::probe(v.src.as_ref()));
                        }
                        AnyFs::Fat(f) => {
                            info["fat"] = serde_json::json!({"type": f.kind.name(), "label": f.label, "cluster_size": f.cluster_size, "serial": f.serial});
                        }
                    }
                }
                jl(&mut out, &info)?;
            }
        }
        Cmd::Ls {
            image,
            partition,
            path,
            recursive,
            deleted,
            index,
        } => {
            let v = image::select_volume(open(&image)?, partition)?;
            let fs = AnyFs::open(&v)?;
            let t = fs.type_name();
            match &fs {
                AnyFs::Ntfs(n) if index => {
                    let id = n.lookup(&path)?;
                    for e in n.list_dir(id)? {
                        jl(&mut out, &with_fs(&t, &e)?)?;
                    }
                }
                AnyFs::Ntfs(n) => {
                    for e in n.entries()? {
                        if e.is_base()
                            && (deleted || e.in_use)
                            && e.path
                                .as_deref()
                                .is_some_and(|p| in_scope(p, &path, recursive))
                        {
                            jl(&mut out, &with_fs(&t, &e)?)?;
                        }
                    }
                }
                AnyFs::Fat(f) => {
                    for e in f.walk(deleted)? {
                        if in_scope(&e.path, &path, recursive) {
                            jl(&mut out, &with_fs(&t, &e)?)?;
                        }
                    }
                }
                AnyFs::Ext(x) => {
                    for e in x.walk(deleted)? {
                        if in_scope(&e.path, &path, recursive) {
                            jl(&mut out, &with_fs(&t, &e)?)?;
                        }
                    }
                }
                AnyFs::Apfs(a) => {
                    for vi in 0..a.volumes.len() {
                        for e in a.walk(vi)? {
                            if in_scope(&e.path, &path, recursive) {
                                let mut j = with_fs(&t, &e)?;
                                j["volume"] = Value::from(vi);
                                jl(&mut out, &j)?;
                            }
                        }
                    }
                }
            }
        }
        Cmd::Cat {
            image,
            path,
            out: dst,
            partition,
        } => {
            let v = image::select_volume(open(&image)?, partition)?;
            let fs = AnyFs::open(&v)?;
            let data = fs.read_path(&path)?;
            std::fs::write(&dst, &data)?;
            eprintln!("wrote {} bytes to {}", data.len(), dst.display());
        }
        Cmd::Mft {
            input,
            partition,
            events: as_events,
        } => {
            let head = read_vec_padded(open(&input)?.as_ref(), 0, 4)?;
            let mut entries = if head == b"FILE" {
                ntfs::parse_mft_file(&std::fs::read(&input)?)?
            } else {
                ntfs_volume(open(&input)?, partition)?.1.entries()?
            };
            entries.sort_by_key(|e| e.entry);
            if as_events {
                let ctx = events::Ctx {
                    evidence_sha256: sha256_file(&input)?,
                    volume_prefix: String::new(),
                };
                let mut evs = events::ntfs_entry_events(&ctx, &entries);
                veritas_timeline::write_jsonl(&mut evs, &mut out)?;
            } else {
                for e in &entries {
                    jl(&mut out, e)?;
                }
            }
        }
        Cmd::Usn {
            input,
            partition,
            events: as_events,
        } => {
            let src = open(&input)?;
            let recs = match ntfs_volume(src.clone(), partition) {
                Ok((_, n)) => n.usn_records()?,
                Err(_) => {
                    let d = std::fs::read(&input)?;
                    ntfs::usn::parse_usn_records(&d, 0)
                }
            };
            if as_events {
                let ctx = events::Ctx {
                    evidence_sha256: sha256_file(&input)?,
                    volume_prefix: String::new(),
                };
                let mut evs = events::usn_events(&ctx, &recs, "$Extend/$UsnJrnl:$J");
                veritas_timeline::write_jsonl(&mut evs, &mut out)?;
            } else {
                for r in &recs {
                    jl(&mut out, r)?;
                }
            }
        }
        Cmd::Logfile {
            input,
            partition,
            events: as_events,
        } => {
            let src = open(&input)?;
            let lf = match ntfs_volume(src.clone(), partition) {
                Ok((_, n)) => n.logfile()?,
                Err(_) => {
                    let d = std::fs::read(&input)?;
                    ntfs::logfile::parse_logfile(&d, 4096, 1024)?
                }
            };
            if as_events {
                let ctx = events::Ctx {
                    evidence_sha256: sha256_file(&input)?,
                    volume_prefix: String::new(),
                };
                let mut evs = events::logfile_events(&ctx, &lf.records);
                veritas_timeline::write_jsonl(&mut evs, &mut out)?;
            } else {
                jl(
                    &mut out,
                    &serde_json::json!({"page_size": lf.page_size, "record_pages": lf.record_pages, "restart_areas": lf.restart_areas}),
                )?;
                for r in &lf.records {
                    jl(&mut out, r)?;
                }
            }
        }
        Cmd::Events { image, partition } => {
            let sha = sha256_file(&image)?;
            let src = open(&image)?;
            let vols = image::volumes(src)?;
            let multi =
                vols.len() > 1 || vols.first().is_some_and(|v| v.description != "whole image");
            let mut evs = Vec::new();
            for v in vols {
                if partition.is_some_and(|p| p != v.index) || v.fs == FsKind::Unknown {
                    continue;
                }
                let ctx = events::Ctx {
                    evidence_sha256: sha.clone(),
                    volume_prefix: if multi {
                        format!("p{}", v.index)
                    } else {
                        String::new()
                    },
                };
                match events::volume_events(&ctx, &v) {
                    Ok(e) => evs.extend(e),
                    Err(e) => eprintln!("partition {}: {e}", v.index),
                }
            }
            veritas_timeline::write_jsonl(&mut evs, &mut out)?;
        }
        Cmd::Carve { image, out: dir } => {
            let src = open(&image)?;
            std::fs::create_dir_all(&dir)?;
            for h in carve::carve(src.as_ref())? {
                let name = format!("{:016x}.{}", h.offset, h.extension);
                let mut f = std::fs::File::create(dir.join(&name))?;
                let mut off = 0u64;
                let size = h.size.min(src.size().saturating_sub(h.offset));
                while off < size {
                    let n = (16u64 << 20).min(size - off);
                    f.write_all(&read_vec_padded(src.as_ref(), h.offset + off, n)?)?;
                    off += n;
                }
                let mut j = serde_json::to_value(&h)?;
                j["file"] = Value::String(name);
                jl(&mut out, &j)?;
            }
        }
        Cmd::Vss {
            image,
            partition,
            full_hash,
        } => {
            let vols = image::volumes(open(&image)?)?;
            let v = vols
                .into_iter()
                .find(|v| partition.is_none_or(|p| p == v.index) && vss::probe(v.src.as_ref()))
                .ok_or_else(|| FsError::NotFound("VSS volume header".into()))?;
            let vs = Arc::new(vss::Vss::open(v.src.clone())?);
            for s in &vs.stores {
                let mut j = serde_json::to_value(s)?;
                let first = vs.read_store(s.index, 0, (1u64 << 20).min(vs.volume_size))?;
                j["first_mib_sha256"] = Value::String(veritas_hash::sha256_hex(&first));
                if full_hash {
                    let mut h = veritas_hash::MultiHasher::new();
                    let mut off = 0;
                    while off < vs.volume_size {
                        let n = (16u64 << 20).min(vs.volume_size - off);
                        h.update(&vs.read_store(s.index, off, n)?);
                        off += n;
                    }
                    j["sha256"] = Value::String(h.finalize().sha256);
                }
                jl(&mut out, &j)?;
            }
        }
        Cmd::Timestomp { image, partition } => {
            let (_, n) = ntfs_volume(open(&image)?, partition)?;
            let usn = n.usn_records().unwrap_or_default();
            for f in ntfs::timestomp::detect(&n.entries()?, &usn) {
                jl(&mut out, &f)?;
            }
        }
        Cmd::Recover {
            image,
            out: dir,
            partition,
        } => {
            let v = image::select_volume(open(&image)?, partition)?;
            let items = match AnyFs::open(&v)? {
                AnyFs::Ntfs(n) => recover::recover_ntfs(&n)?,
                AnyFs::Fat(f) => recover::recover_fat(&f)?,
                _ => {
                    return Err(Box::new(FsError::Unsupported(
                        "recovery supports NTFS and FAT".into(),
                    )))
                }
            };
            recover::write_recovered(&dir, &items)?;
            for r in &items {
                jl(&mut out, r)?;
            }
        }
        Cmd::Harvest {
            image,
            out: dir,
            partition,
            max_file_size,
        } => {
            let rep = harvest::harvest(open(&image)?, &dir, partition, max_file_size)?;
            for e in &rep.errors {
                eprintln!("skipped partition {} {}: {}", e.partition, e.path, e.error);
            }
            eprintln!(
                "harvested {} files, {} skipped; manifest at {}",
                rep.manifest.len(),
                rep.errors.len(),
                dir.join("manifest.jsonl").display()
            );
        }
    }
    out.flush()?;
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
