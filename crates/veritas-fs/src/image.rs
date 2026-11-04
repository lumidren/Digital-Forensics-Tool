//! Image-level helpers: enumerate volumes (partitions or the whole image), detect the file system on
//! each and expose a common entry view used by events, harvesting and the CLI.
use crate::apfs::Apfs;
use crate::error::{FsError, Result};
use crate::ext4::Ext4;
use crate::fat::FatFs;
use crate::io::{read_vec_padded, ReadAt, Source, SubSource};
use crate::ntfs::Ntfs;
use crate::volume;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum FsKind {
    Ntfs,
    Fat,
    Ext,
    Apfs,
    Unknown,
}

impl FsKind {
    pub fn name(&self) -> &'static str {
        match self {
            FsKind::Ntfs => "ntfs",
            FsKind::Fat => "fat",
            FsKind::Ext => "ext",
            FsKind::Apfs => "apfs",
            FsKind::Unknown => "unknown",
        }
    }
}

/// Detect the file system at the start of `src`.
pub fn detect_fs(src: &dyn ReadAt) -> FsKind {
    let Ok(b) = read_vec_padded(src, 0, 4096) else {
        return FsKind::Unknown;
    };
    if &b[3..11] == b"NTFS    " {
        return FsKind::Ntfs;
    }
    if crate::apfs::probe(&b) {
        return FsKind::Apfs;
    }
    if crate::fat::probe(&b) {
        return FsKind::Fat;
    }
    if crate::ext4::probe(&b[1024..2048]) {
        return FsKind::Ext;
    }
    FsKind::Unknown
}

#[derive(Clone)]
pub struct ImageVolume {
    /// Partition index (0 when the image holds a bare file system).
    pub index: usize,
    pub offset: u64,
    pub length: u64,
    pub description: String,
    pub fs: FsKind,
    pub src: Source,
}

/// Every volume of an image: partitions when a table exists, else the whole image.
pub fn volumes(src: Source) -> Result<Vec<ImageVolume>> {
    let mut out = Vec::new();
    if let Some(vs) = volume::detect(src.as_ref())? {
        for p in &vs.partitions {
            let s = SubSource::source(src.clone(), p.offset, p.length)?;
            out.push(ImageVolume {
                index: p.index,
                offset: p.offset,
                length: p.length,
                description: p.description.clone(),
                fs: detect_fs(s.as_ref()),
                src: s,
            });
        }
    }
    if out.is_empty() {
        out.push(ImageVolume {
            index: 0,
            offset: 0,
            length: src.size(),
            description: "whole image".into(),
            fs: detect_fs(src.as_ref()),
            src,
        });
    }
    Ok(out)
}

pub fn select_volume(src: Source, partition: Option<usize>) -> Result<ImageVolume> {
    let vols = volumes(src)?;
    match partition {
        Some(n) => vols
            .into_iter()
            .find(|v| v.index == n)
            .ok_or_else(|| FsError::NotFound(format!("partition {n}"))),
        None => vols
            .iter()
            .find(|v| v.fs != FsKind::Unknown)
            .cloned()
            .or_else(|| vols.into_iter().next())
            .ok_or_else(|| FsError::NotFound("volume".into())),
    }
}

pub enum AnyFs {
    Ntfs(Ntfs),
    Fat(FatFs),
    Ext(Ext4),
    Apfs(Apfs),
}

/// Common view of a file-system entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct GenericEntry {
    pub path: String,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// MFT entry, inode / APFS object id, or FAT directory-entry offset.
    pub id: u64,
    pub allocated: bool,
    pub crtime: Option<i64>,
    pub mtime: Option<i64>,
    pub atime: Option<i64>,
    pub ctime: Option<i64>,
}

impl AnyFs {
    pub fn open(v: &ImageVolume) -> Result<Self> {
        match v.fs {
            FsKind::Ntfs => Ok(AnyFs::Ntfs(Ntfs::open(v.src.clone())?)),
            FsKind::Fat => Ok(AnyFs::Fat(FatFs::open(v.src.clone())?)),
            FsKind::Ext => Ok(AnyFs::Ext(Ext4::open(v.src.clone())?)),
            FsKind::Apfs => Ok(AnyFs::Apfs(Apfs::open(v.src.clone())?)),
            FsKind::Unknown => Err(FsError::Unsupported(format!(
                "no supported file system in volume {}",
                v.index
            ))),
        }
    }

    pub fn type_name(&self) -> String {
        match self {
            AnyFs::Ntfs(_) => "NTFS".into(),
            AnyFs::Fat(f) => f.kind.name().into(),
            AnyFs::Ext(e) => {
                if e.sb.feature_incompat & 0x40 != 0 {
                    "EXT4".into()
                } else if e.sb.feature_compat & 0x4 != 0 {
                    "EXT3".into()
                } else {
                    "EXT2".into()
                }
            }
            AnyFs::Apfs(_) => "APFS".into(),
        }
    }

    /// The name used for the `id` field: `mft_entry`, `inode` or `dir_entry_offset`.
    pub fn id_name(&self) -> &'static str {
        match self {
            AnyFs::Ntfs(_) => "mft_entry",
            AnyFs::Fat(_) => "dir_entry_offset",
            AnyFs::Ext(_) | AnyFs::Apfs(_) => "inode",
        }
    }

    /// All entries, sorted by path. Deleted entries are included when `include_deleted`.
    pub fn entries(&self, include_deleted: bool) -> Result<Vec<GenericEntry>> {
        let mut v: Vec<GenericEntry> = match self {
            AnyFs::Ntfs(n) => n
                .entries()?
                .into_iter()
                .filter(|e| {
                    e.is_base()
                        && e.path.is_some()
                        && e.entry != crate::ntfs::ROOT_ENTRY
                        && (include_deleted || e.in_use)
                })
                .map(|e| {
                    let si = e.si.clone().unwrap_or_default();
                    GenericEntry {
                        path: e.path.clone().unwrap_or_default(),
                        name: e.name().unwrap_or_default().to_string(),
                        is_dir: e.is_dir,
                        size: e.size(),
                        id: e.entry,
                        allocated: e.in_use,
                        crtime: veritas_timeline::filetime_to_ns(si.crtime),
                        mtime: veritas_timeline::filetime_to_ns(si.mtime),
                        atime: veritas_timeline::filetime_to_ns(si.atime),
                        ctime: veritas_timeline::filetime_to_ns(si.ctime),
                    }
                })
                .collect(),
            AnyFs::Fat(f) => f
                .walk(include_deleted)?
                .into_iter()
                .map(|e| GenericEntry {
                    path: e.path,
                    name: e.name,
                    is_dir: e.is_dir,
                    size: e.size,
                    id: e.dir_entry_offset,
                    allocated: !e.deleted,
                    crtime: e.crtime,
                    mtime: e.mtime,
                    atime: e.atime,
                    ctime: None,
                })
                .collect(),
            AnyFs::Ext(x) => x
                .walk(include_deleted)?
                .into_iter()
                .map(|e| GenericEntry {
                    path: e.path,
                    name: e.name,
                    is_dir: e.kind == "dir",
                    size: e.size,
                    id: e.inode,
                    allocated: e.allocated && !e.deleted_name,
                    crtime: e.crtime,
                    mtime: e.mtime,
                    atime: e.atime,
                    ctime: e.ctime,
                })
                .collect(),
            AnyFs::Apfs(a) => {
                let mut all = Vec::new();
                for vi in 0..a.volumes.len() {
                    let prefix = if a.volumes.len() > 1 {
                        format!("/{}", a.volumes[vi].name)
                    } else {
                        String::new()
                    };
                    for e in a.walk(vi)? {
                        all.push(GenericEntry {
                            path: format!("{prefix}{}", e.path),
                            name: e.name,
                            is_dir: e.kind == "dir",
                            size: e.size,
                            id: e.id,
                            allocated: true,
                            crtime: e.crtime,
                            mtime: e.mtime,
                            atime: e.atime,
                            ctime: e.ctime,
                        });
                    }
                }
                all
            }
        };
        v.sort_by(|a, b| (&a.path, a.id).cmp(&(&b.path, b.id)));
        Ok(v)
    }

    /// Read a file by path (NTFS accepts `path:stream`).
    pub fn read_path(&self, path: &str) -> Result<Vec<u8>> {
        match self {
            AnyFs::Ntfs(n) => n.read_file(path),
            AnyFs::Fat(f) => f.read_file(path),
            AnyFs::Ext(e) => e.read_file(path),
            AnyFs::Apfs(a) => {
                if a.volumes.len() > 1 {
                    let p = path.trim_start_matches('/');
                    let (vname, rest) = p.split_once('/').unwrap_or((p, ""));
                    let vi = a
                        .volumes
                        .iter()
                        .position(|v| v.name == vname)
                        .ok_or_else(|| FsError::NotFound(path.into()))?;
                    a.read_file(vi, rest)
                } else {
                    a.read_file(0, path)
                }
            }
        }
    }
}
