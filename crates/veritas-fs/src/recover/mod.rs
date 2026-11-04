//! Deleted-file recovery: NTFS (unallocated MFT records whose data is resident or whose data runs are
//! intact) and FAT/exFAT (deleted directory entries with a first cluster). Each result carries a
//! `recovered_confidence` (0-100, integer); reuse of the file's clusters by allocated data lowers it.
use crate::error::Result;
use crate::fat::FatFs;
use crate::ntfs::Ntfs;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Largest file recovered.
pub const MAX_RECOVER_SIZE: u64 = 256 * 1024 * 1024;
/// Confidence for data stored inside the MFT record itself.
pub const CONF_RESIDENT: u8 = 95;
/// Confidence for intact, unreused clusters.
pub const CONF_CLUSTERS: u8 = 90;
/// Confidence floor applied when every cluster has been reused.
pub const CONF_REUSED_FLOOR: u8 = 10;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Recovered {
    pub fs_type: String,
    /// MFT entry (NTFS) or directory-entry offset (FAT).
    pub id: u64,
    pub name: String,
    pub path: String,
    pub size: u64,
    pub recovered_confidence: u8,
    pub total_clusters: u64,
    pub reused_clusters: u64,
    pub method: String,
    pub sha256: String,
    #[serde(skip)]
    pub data: Vec<u8>,
}

fn confidence(total: u64, reused: u64) -> u8 {
    if total == 0 {
        return CONF_CLUSTERS;
    }
    let span = (CONF_CLUSTERS - CONF_REUSED_FLOOR) as u64;
    (CONF_CLUSTERS as u64 - span * reused / total) as u8
}

/// Recover deleted NTFS files (unnamed $DATA stream).
pub fn recover_ntfs(fs: &Ntfs) -> Result<Vec<Recovered>> {
    let bitmap = fs.read_entry_data(6, "").unwrap_or_default();
    let allocated = |lcn: u64| bitmap.get((lcn / 8) as usize).is_some_and(|b| b & (1 << (lcn % 8)) != 0);
    let mut out = Vec::new();
    for e in fs.entries()? {
        if e.in_use || !e.is_base() || e.is_dir {
            continue;
        }
        let Some(d) = e.data() else { continue };
        if d.size == 0 || d.size > MAX_RECOVER_SIZE || d.is_encrypted() {
            continue;
        }
        let (conf, total, reused, method) = if d.resident {
            (CONF_RESIDENT, 0, 0, "resident")
        } else {
            let cs = fs.cluster_size();
            let needed = d.size.div_ceil(cs);
            let mut total = 0u64;
            let mut reused = 0u64;
            for r in &d.runs {
                let Some(lcn) = r.lcn else { continue };
                for k in 0..r.length {
                    if r.vcn + k >= needed {
                        break;
                    }
                    total += 1;
                    if allocated(lcn + k) {
                        reused += 1;
                    }
                }
            }
            (confidence(total, reused), total, reused, "data_runs")
        };
        let Ok(data) = fs.read_stream(d) else { continue };
        out.push(Recovered {
            fs_type: "NTFS".into(),
            id: e.entry,
            name: e.name().unwrap_or_default().to_string(),
            path: e.path.clone().unwrap_or_default(),
            size: d.size,
            recovered_confidence: conf,
            total_clusters: total,
            reused_clusters: reused,
            method: method.into(),
            sha256: veritas_hash::sha256_hex(&data),
            data,
        });
    }
    out.sort();
    Ok(out)
}

/// Recover deleted FAT/exFAT files by reading contiguous clusters from the first cluster.
pub fn recover_fat(fs: &FatFs) -> Result<Vec<Recovered>> {
    let mut out = Vec::new();
    for e in fs.walk(true)? {
        if !e.deleted || e.is_dir || e.size == 0 || e.first_cluster < 2 || e.size > MAX_RECOVER_SIZE {
            continue;
        }
        let n = e.size.div_ceil(fs.cluster_size);
        let reused = (0..n).filter(|k| fs.cluster_allocated(e.first_cluster.saturating_add(*k as u32))).count() as u64;
        let Ok(data) = fs.read_contiguous(e.first_cluster, e.size) else { continue };
        out.push(Recovered {
            fs_type: fs.kind.name().into(),
            id: e.dir_entry_offset,
            name: e.name.clone(),
            path: e.path.clone(),
            size: e.size,
            recovered_confidence: confidence(n, reused),
            total_clusters: n,
            reused_clusters: reused,
            method: if e.no_fat_chain { "contiguous_nofatchain".into() } else { "contiguous_from_first_cluster".into() },
            sha256: veritas_hash::sha256_hex(&data),
            data,
        });
    }
    out.sort();
    Ok(out)
}

/// Write recovered files to `out_dir` as `<id>_<sanitised name>`; returns the written paths.
pub fn write_recovered(out_dir: &Path, items: &[Recovered]) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(out_dir)?;
    let mut v = Vec::new();
    for r in items {
        let p = out_dir.join(format!("{}_{}", r.id, crate::harvest::sanitize_component(&r.name)));
        std::fs::write(&p, &r.data)?;
        v.push(p);
    }
    Ok(v)
}
