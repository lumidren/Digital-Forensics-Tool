//! ext2/3/4: superblock, group descriptors (32/64-bit), inodes (incl. extra-isize nanosecond times
//! and crtime), extent trees and legacy block maps, directories (linear + htree read linearly,
//! deleted entries from record slack), symlinks, inode-bitmap deletion state and jbd2 journal.
pub mod journal;

use crate::error::{FsError, Result};
use crate::io::{read_vec, read_vec_padded, Source};
use crate::util::{need, u16_at, u32_at, u8_at, utf8z};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Maximum extent-tree depth followed.
pub const MAX_EXTENT_DEPTH: usize = 8;
/// Maximum extent / block-map nodes visited for one inode.
pub const MAX_MAP_NODES: usize = 65536;
/// Maximum file size read into memory.
pub const MAX_FILE_READ: u64 = 1 << 30;
/// Maximum directory depth walked.
pub const MAX_DIR_DEPTH: usize = 64;
/// Maximum entries returned by a walk.
pub const MAX_WALK_ENTRIES: usize = 1 << 20;
/// Maximum block groups accepted.
pub const MAX_GROUPS: u64 = 1 << 20;
/// Maximum inodes scanned when looking for deleted inodes.
pub const MAX_INODE_SCAN: u64 = 1 << 22;
/// Maximum directory size read.
pub const MAX_DIR_BYTES: u64 = 64 * 1024 * 1024;

const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_64BIT: u32 = 0x80;
const FL_INDEX: u32 = 0x1000;
const FL_EXTENTS: u32 = 0x8_0000;
const FL_INLINE_DATA: u32 = 0x1000_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Superblock {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub first_data_block: u32,
    pub block_size: u64,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub mount_time: u32,
    pub write_time: u32,
    pub rev_level: u32,
    pub inode_size: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: String,
    pub volume_name: String,
    pub last_mounted: String,
    pub journal_inum: u32,
    pub desc_size: u16,
    pub mkfs_time: u32,
    pub min_extra_isize: u16,
}

impl Superblock {
    pub fn parse(b: &[u8]) -> Result<Self> {
        let magic = u16_at(b, 0x38)?;
        if magic != 0xEF53 {
            return Err(FsError::sig(1024 + 0x38, "53EF", &magic.to_le_bytes()));
        }
        let log = u32_at(b, 0x18)?;
        if log > 6 {
            return Err(FsError::invalid(1024 + 0x18, "block size"));
        }
        let rev = u32_at(b, 0x4C)?;
        let incompat = u32_at(b, 0x60)?;
        let hi = if incompat & INCOMPAT_64BIT != 0 {
            u32_at(b, 0x150)? as u64
        } else {
            0
        };
        Ok(Superblock {
            inodes_count: u32_at(b, 0)?,
            blocks_count: (hi << 32) | u32_at(b, 4)? as u64,
            first_data_block: u32_at(b, 0x14)?,
            block_size: 1024u64 << log,
            blocks_per_group: u32_at(b, 0x20)?,
            inodes_per_group: u32_at(b, 0x28)?,
            mount_time: u32_at(b, 0x2C)?,
            write_time: u32_at(b, 0x30)?,
            rev_level: rev,
            inode_size: if rev == 0 { 128 } else { u16_at(b, 0x58)? },
            feature_compat: u32_at(b, 0x5C)?,
            feature_incompat: incompat,
            feature_ro_compat: u32_at(b, 0x64)?,
            uuid: crate::util::uuid_be(need(b, 0x68, 16)?)?,
            volume_name: utf8z(need(b, 0x78, 16)?),
            last_mounted: utf8z(need(b, 0x88, 64)?),
            journal_inum: u32_at(b, 0xE0)?,
            desc_size: u16_at(b, 0xFE)?,
            mkfs_time: u32_at(b, 0x108)?,
            min_extra_isize: u16_at(b, 0x15C)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupDesc {
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub inode_table: u64,
    pub flags: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Inode {
    pub ino: u64,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub links: u16,
    pub atime: Option<i64>,
    pub ctime: Option<i64>,
    pub mtime: Option<i64>,
    pub dtime: u32,
    pub crtime: Option<i64>,
    pub flags: u32,
    pub blocks: u64,
    pub file_acl: u64,
    pub generation: u32,
    pub extra_isize: u16,
    /// Inode bit set in the group's inode bitmap.
    pub allocated: bool,
    #[serde(skip)]
    pub block: Vec<u8>,
}

impl Inode {
    pub fn is_dir(&self) -> bool {
        self.mode & 0xF000 == 0x4000
    }
    pub fn is_reg(&self) -> bool {
        self.mode & 0xF000 == 0x8000
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & 0xF000 == 0xA000
    }
    pub fn kind(&self) -> &'static str {
        match self.mode & 0xF000 {
            0x1000 => "fifo",
            0x2000 => "char",
            0x4000 => "dir",
            0x6000 => "block",
            0x8000 => "file",
            0xA000 => "symlink",
            0xC000 => "socket",
            _ => "unknown",
        }
    }
}

/// seconds (signed 32) + extra (2 epoch bits, 30 nanosecond bits) -> epoch ns.
fn ext_time(secs: u32, extra: Option<u32>) -> Option<i64> {
    let mut s = secs as i32 as i64;
    let mut ns = 0u32;
    if let Some(x) = extra {
        s += ((x & 3) as i64) << 32;
        ns = x >> 2;
        if ns > 999_999_999 {
            ns = 0;
        }
    }
    veritas_timeline::unix_to_ns(s, ns)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirEntry {
    pub inode: u64,
    pub name: String,
    pub file_type: u8,
    /// Recovered from directory-record slack (unlinked entry).
    pub deleted: bool,
    /// Byte offset of the entry inside the directory stream.
    pub offset: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ExtEntry {
    pub path: String,
    pub name: String,
    pub inode: u64,
    pub parent_inode: u64,
    pub kind: String,
    pub mode: u16,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub links: u16,
    pub atime: Option<i64>,
    pub mtime: Option<i64>,
    pub ctime: Option<i64>,
    pub crtime: Option<i64>,
    pub dtime: u32,
    pub allocated: bool,
    /// Name came from a deleted directory record.
    pub deleted_name: bool,
    pub symlink_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Extent {
    pub logical: u64,
    pub physical: u64,
    pub length: u64,
    pub uninit: bool,
}

pub struct Ext4 {
    src: Source,
    pub sb: Superblock,
    pub groups: Vec<GroupDesc>,
}

impl Ext4 {
    pub fn open(src: Source) -> Result<Self> {
        let sbb = read_vec(src.as_ref(), 1024, 1024)?;
        let sb = Superblock::parse(&sbb)?;
        if sb.blocks_per_group == 0
            || sb.inodes_per_group == 0
            || sb.inode_size < 128
            || sb.inode_size as u64 > sb.block_size
        {
            return Err(FsError::invalid(1024, "ext superblock geometry"));
        }
        let ngroups = (sb.blocks_count.saturating_sub(sb.first_data_block as u64))
            .div_ceil(sb.blocks_per_group as u64);
        if ngroups == 0 || ngroups > MAX_GROUPS {
            return Err(FsError::invalid(1024, "group count"));
        }
        if sb.inodes_count as u64 != ngroups * sb.inodes_per_group as u64 {
            return Err(FsError::invalid(
                1024,
                "inodes_count != groups * inodes_per_group",
            ));
        }
        let ds = if sb.feature_incompat & INCOMPAT_64BIT != 0 && sb.desc_size >= 64 {
            sb.desc_size as u64
        } else {
            32
        };
        let gdt_off = (sb.first_data_block as u64 + 1) * sb.block_size;
        let gdt = read_vec_padded(src.as_ref(), gdt_off, ngroups * ds)?;
        let mut groups = Vec::with_capacity(ngroups as usize);
        for g in 0..ngroups as usize {
            let o = g * ds as usize;
            let hi = |off: usize| -> Result<u64> {
                if ds >= 64 {
                    Ok(u32_at(&gdt, o + off)? as u64)
                } else {
                    Ok(0)
                }
            };
            groups.push(GroupDesc {
                block_bitmap: (hi(0x20)? << 32) | u32_at(&gdt, o)? as u64,
                inode_bitmap: (hi(0x24)? << 32) | u32_at(&gdt, o + 4)? as u64,
                inode_table: (hi(0x28)? << 32) | u32_at(&gdt, o + 8)? as u64,
                flags: u16_at(&gdt, o + 0x12)?,
            });
        }
        Ok(Ext4 { src, sb, groups })
    }

    pub fn block_size(&self) -> u64 {
        self.sb.block_size
    }

    fn read_block(&self, b: u64) -> Result<Vec<u8>> {
        let off = b
            .checked_mul(self.sb.block_size)
            .ok_or_else(|| FsError::invalid(b, "block overflow"))?;
        read_vec_padded(self.src.as_ref(), off, self.sb.block_size)
    }

    pub fn inode_allocated(&self, ino: u64) -> bool {
        if ino == 0 || ino > self.sb.inodes_count as u64 {
            return false;
        }
        let g = ((ino - 1) / self.sb.inodes_per_group as u64) as usize;
        let idx = (ino - 1) % self.sb.inodes_per_group as u64;
        let Some(gd) = self.groups.get(g) else {
            return false;
        };
        if gd.flags & 0x1 != 0 {
            return false; // INODE_UNINIT
        }
        match self.read_block(gd.inode_bitmap) {
            Ok(bm) => bm
                .get((idx / 8) as usize)
                .is_some_and(|b| b & (1 << (idx % 8)) != 0),
            Err(_) => false,
        }
    }

    pub fn inode(&self, ino: u64) -> Result<Inode> {
        if ino == 0 || ino > self.sb.inodes_count as u64 {
            return Err(FsError::NotFound(format!("inode {ino}")));
        }
        let ipg = self.sb.inodes_per_group as u64;
        let g = ((ino - 1) / ipg) as usize;
        let idx = (ino - 1) % ipg;
        let gd = self
            .groups
            .get(g)
            .ok_or_else(|| FsError::NotFound(format!("group of inode {ino}")))?;
        let isz = self.sb.inode_size as u64;
        let off = gd
            .inode_table
            .checked_mul(self.sb.block_size)
            .and_then(|v| v.checked_add(idx * isz))
            .ok_or_else(|| FsError::invalid(ino, "inode offset overflow"))?;
        let d = read_vec(self.src.as_ref(), off, isz)?;
        let extra_isize = if isz > 128 { u16_at(&d, 0x80)? } else { 0 };
        let has = |end: usize| isz > 128 && (128 + extra_isize as usize) >= end && end <= d.len();
        let extra = |o: usize| if has(o + 4) { u32_at(&d, o).ok() } else { None };
        let crtime = if has(0x98) {
            ext_time(u32_at(&d, 0x90)?, extra(0x94))
        } else {
            None
        };
        let mode = u16_at(&d, 0)?;
        let size_hi = u32_at(&d, 0x6C)? as u64;
        Ok(Inode {
            ino,
            mode,
            uid: (u16_at(&d, 2)? as u32) | ((u16_at(&d, 0x78)? as u32) << 16),
            gid: (u16_at(&d, 0x18)? as u32) | ((u16_at(&d, 0x7A)? as u32) << 16),
            size: (size_hi << 32) | u32_at(&d, 4)? as u64,
            links: u16_at(&d, 0x1A)?,
            atime: ext_time(u32_at(&d, 0x08)?, extra(0x8C)),
            ctime: ext_time(u32_at(&d, 0x0C)?, extra(0x84)),
            mtime: ext_time(u32_at(&d, 0x10)?, extra(0x88)),
            dtime: u32_at(&d, 0x14)?,
            crtime,
            flags: u32_at(&d, 0x20)?,
            blocks: ((u16_at(&d, 0x74)? as u64) << 32) | u32_at(&d, 0x1C)? as u64,
            file_acl: ((u16_at(&d, 0x76)? as u64) << 32) | u32_at(&d, 0x68)? as u64,
            generation: u32_at(&d, 0x64)?,
            extra_isize,
            allocated: self.inode_allocated(ino),
            block: need(&d, 0x28, 60)?.to_vec(),
        })
    }

    /// Physical extents of an inode (extent tree or indirect block map), sorted by logical block.
    pub fn extents(&self, ino: &Inode) -> Result<Vec<Extent>> {
        let mut out = Vec::new();
        let mut nodes = 0usize;
        if ino.flags & FL_INLINE_DATA != 0 {
            return Ok(out);
        }
        if ino.flags & FL_EXTENTS != 0 {
            self.walk_extents(&ino.block, 0, &mut out, &mut nodes)?;
        } else {
            let nblocks = ino.size.div_ceil(self.sb.block_size);
            let ptrs: Vec<u32> = ino
                .block
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            let mut logical = 0u64;
            for &p in ptrs.iter().take(12) {
                if logical >= nblocks {
                    break;
                }
                if p != 0 {
                    out.push(Extent {
                        logical,
                        physical: p as u64,
                        length: 1,
                        uninit: false,
                    });
                }
                logical += 1;
            }
            for (lvl, &p) in ptrs.iter().skip(12).take(3).enumerate() {
                let per = self.sb.block_size / 4;
                let span = per.saturating_pow(lvl as u32 + 1);
                if logical >= nblocks {
                    break;
                }
                if p != 0 {
                    self.walk_indirect(p as u64, lvl, logical, nblocks, &mut out, &mut nodes)?;
                }
                logical = logical.saturating_add(span);
            }
        }
        out.sort_by_key(|e| e.logical);
        // Coalesce adjacent single-block runs.
        let mut merged: Vec<Extent> = Vec::new();
        for e in out {
            if let Some(l) = merged.last_mut() {
                if l.logical + l.length == e.logical
                    && l.physical + l.length == e.physical
                    && l.uninit == e.uninit
                {
                    l.length += e.length;
                    continue;
                }
            }
            merged.push(e);
        }
        Ok(merged)
    }

    fn walk_indirect(
        &self,
        blk: u64,
        level: usize,
        base: u64,
        nblocks: u64,
        out: &mut Vec<Extent>,
        nodes: &mut usize,
    ) -> Result<()> {
        *nodes += 1;
        if *nodes > MAX_MAP_NODES || level > 2 {
            return Err(FsError::Limit("block map too large".into()));
        }
        let per = self.sb.block_size / 4;
        let span = per.saturating_pow(level as u32);
        let d = self.read_block(blk)?;
        for (i, c) in d.chunks_exact(4).enumerate() {
            let p = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64;
            let logical = base.saturating_add(i as u64 * span);
            if logical >= nblocks {
                break;
            }
            if p == 0 {
                continue;
            }
            if level == 0 {
                out.push(Extent {
                    logical,
                    physical: p,
                    length: 1,
                    uninit: false,
                });
            } else {
                self.walk_indirect(p, level - 1, logical, nblocks, out, nodes)?;
            }
        }
        Ok(())
    }

    fn walk_extents(
        &self,
        node: &[u8],
        depth: usize,
        out: &mut Vec<Extent>,
        nodes: &mut usize,
    ) -> Result<()> {
        *nodes += 1;
        if depth > MAX_EXTENT_DEPTH || *nodes > MAX_MAP_NODES {
            return Err(FsError::Limit("extent tree too deep or large".into()));
        }
        if u16_at(node, 0)? != 0xF30A {
            return Err(FsError::sig(0, "0AF3", need(node, 0, 2)?));
        }
        let entries = u16_at(node, 2)? as usize;
        let tree_depth = u16_at(node, 6)?;
        for i in 0..entries {
            let o = 12 + i * 12;
            if tree_depth == 0 {
                let lb = u32_at(node, o)? as u64;
                let mut len = u16_at(node, o + 4)? as u64;
                let uninit = len > 32768;
                if uninit {
                    len -= 32768;
                }
                let start = ((u16_at(node, o + 6)? as u64) << 32) | u32_at(node, o + 8)? as u64;
                out.push(Extent {
                    logical: lb,
                    physical: start,
                    length: len,
                    uninit,
                });
            } else {
                let leaf = ((u16_at(node, o + 8)? as u64) << 32) | u32_at(node, o + 4)? as u64;
                let child = self.read_block(leaf)?;
                self.walk_extents(&child, depth + 1, out, nodes)?;
            }
        }
        Ok(())
    }

    /// Read the content of an inode (holes and uninitialised extents read as zeros).
    pub fn read_inode_data(&self, ino: &Inode) -> Result<Vec<u8>> {
        if ino.size > MAX_FILE_READ {
            return Err(FsError::Limit("file too large".into()));
        }
        let size = ino.size as usize;
        if ino.flags & FL_INLINE_DATA != 0
            || (ino.is_symlink()
                && ino.size < 60
                && ino.flags & FL_EXTENTS == 0
                && ino.blocks.saturating_sub(if ino.file_acl != 0 {
                    self.sb.block_size / 512
                } else {
                    0
                }) == 0)
        {
            let mut d = ino.block.clone();
            d.truncate(size.min(60));
            return Ok(d);
        }
        let mut out = vec![0u8; size];
        let bs = self.sb.block_size;
        for e in self.extents(ino)? {
            if e.uninit {
                continue;
            }
            let lo = e.logical.saturating_mul(bs);
            if lo >= ino.size {
                continue;
            }
            let len = e.length.saturating_mul(bs).min(ino.size - lo);
            let chunk = read_vec_padded(self.src.as_ref(), e.physical.saturating_mul(bs), len)?;
            out[lo as usize..lo as usize + chunk.len()].copy_from_slice(&chunk);
        }
        Ok(out)
    }

    pub fn symlink_target(&self, ino: &Inode) -> Result<String> {
        let d = self.read_inode_data(ino)?;
        Ok(String::from_utf8_lossy(&d).into_owned())
    }

    /// Directory entries (live and slack-recovered) of directory inode `ino`.
    pub fn list_dir(&self, ino: u64) -> Result<Vec<DirEntry>> {
        let inode = self.inode(ino)?;
        if !inode.is_dir() {
            return Err(FsError::invalid(ino, "not a directory"));
        }
        if inode.size > MAX_DIR_BYTES {
            return Err(FsError::Limit("directory too large".into()));
        }
        let data = self.read_inode_data(&inode)?;
        let htree = inode.flags & FL_INDEX != 0;
        let filetype = self.sb.feature_incompat & INCOMPAT_FILETYPE != 0;
        let bs = self.sb.block_size as usize;
        let mut out = Vec::new();
        let max_ino = self.sb.inodes_count as u64;
        let inline = inode.flags & FL_INLINE_DATA != 0;
        let block_len = if inline { data.len() } else { bs };
        for (bi, blk) in data.chunks(block_len.max(1)).enumerate() {
            let base = (bi * block_len) as u64;
            let mut pos = if inline { 4 } else { 0 }; // inline dirs start with the parent inode number
            if inline {
                if let Ok(p) = u32_at(blk, 0) {
                    out.push(DirEntry {
                        inode: p as u64,
                        name: "..".into(),
                        file_type: 2,
                        deleted: false,
                        offset: base,
                    });
                }
            }
            let dx_node = htree
                && (bi == 0
                    || (u32_at(blk, 0).unwrap_or(1) == 0
                        && u16_at(blk, 4).unwrap_or(0) as usize == bs));
            while pos + 8 <= blk.len() {
                let ino_n = u32_at(blk, pos)? as u64;
                let rec_len = u16_at(blk, pos + 4)? as usize;
                let name_len = if filetype {
                    u8_at(blk, pos + 6)? as usize
                } else {
                    u16_at(blk, pos + 6)? as usize & 0xFF
                };
                let ftype = if filetype { u8_at(blk, pos + 7)? } else { 0 };
                if rec_len < 8 || pos + rec_len > blk.len() {
                    break;
                }
                if ino_n != 0 && name_len > 0 && pos + 8 + name_len <= blk.len() {
                    let name =
                        String::from_utf8_lossy(&blk[pos + 8..pos + 8 + name_len]).into_owned();
                    out.push(DirEntry {
                        inode: ino_n,
                        name,
                        file_type: ftype,
                        deleted: false,
                        offset: base + pos as u64,
                    });
                }
                // Slack after the live record may hold unlinked entries.
                let used = (8 + name_len + 3) & !3;
                if !dx_node && ino_n != 0 && rec_len > used + 8 {
                    let mut p = pos + used;
                    while p + 8 < pos + rec_len {
                        let cand_ino = u32_at(blk, p)? as u64;
                        let cl = u8_at(blk, p + 6)? as usize;
                        let crl = u16_at(blk, p + 4)? as usize;
                        if cand_ino != 0
                            && cand_ino <= max_ino
                            && cl > 0
                            && p + 8 + cl <= pos + rec_len
                            && crl >= 8 + cl
                        {
                            let nb = &blk[p + 8..p + 8 + cl];
                            if nb.iter().all(|&c| c >= 0x20 && c != b'/' && c != 0x7F) {
                                out.push(DirEntry {
                                    inode: cand_ino,
                                    name: String::from_utf8_lossy(nb).into_owned(),
                                    file_type: if filetype { blk[p + 7] } else { 0 },
                                    deleted: true,
                                    offset: base + p as u64,
                                });
                                p += (8 + cl + 3) & !3;
                                continue;
                            }
                        }
                        p += 4;
                    }
                }
                pos += rec_len;
            }
        }
        Ok(out)
    }

    fn make_entry(
        &self,
        path: String,
        name: String,
        ino: u64,
        parent: u64,
        deleted_name: bool,
    ) -> Option<ExtEntry> {
        let i = self.inode(ino).ok()?;
        let symlink_target = if i.is_symlink() {
            self.symlink_target(&i).ok()
        } else {
            None
        };
        Some(ExtEntry {
            path,
            name,
            inode: ino,
            parent_inode: parent,
            kind: i.kind().into(),
            mode: i.mode,
            size: i.size,
            uid: i.uid,
            gid: i.gid,
            links: i.links,
            atime: i.atime,
            mtime: i.mtime,
            ctime: i.ctime,
            crtime: i.crtime,
            dtime: i.dtime,
            allocated: i.allocated,
            deleted_name,
            symlink_target,
        })
    }

    /// Recursive walk from the root (inode 2). Deleted names are included when `include_deleted`.
    pub fn walk(&self, include_deleted: bool) -> Result<Vec<ExtEntry>> {
        let mut out = Vec::new();
        let mut stack: Vec<(u64, String, usize)> = vec![(2, String::new(), 0)];
        let mut visited: BTreeSet<u64> = BTreeSet::new();
        visited.insert(2);
        while let Some((dir, prefix, depth)) = stack.pop() {
            let Ok(list) = self.list_dir(dir) else {
                continue;
            };
            for de in list {
                if de.name == "." || de.name == ".." || (de.deleted && !include_deleted) {
                    continue;
                }
                if out.len() >= MAX_WALK_ENTRIES {
                    break;
                }
                let path = format!("{}/{}", prefix, de.name);
                if let Some(e) =
                    self.make_entry(path.clone(), de.name.clone(), de.inode, dir, de.deleted)
                {
                    if e.kind == "dir"
                        && !de.deleted
                        && depth < MAX_DIR_DEPTH
                        && visited.insert(de.inode)
                    {
                        stack.push((de.inode, path, depth + 1));
                    }
                    out.push(e);
                }
            }
        }
        out.sort_by(|a, b| {
            (&a.path, a.inode, a.deleted_name).cmp(&(&b.path, b.inode, b.deleted_name))
        });
        Ok(out)
    }

    pub fn lookup(&self, path: &str) -> Result<u64> {
        let mut cur = 2u64;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            let list = self.list_dir(cur)?;
            cur = list
                .iter()
                .find(|d| !d.deleted && d.name == comp)
                .map(|d| d.inode)
                .ok_or_else(|| FsError::NotFound(path.to_string()))?;
        }
        Ok(cur)
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let ino = self.lookup(path)?;
        let i = self.inode(ino)?;
        if i.is_dir() {
            return Err(FsError::invalid(ino, "is a directory"));
        }
        self.read_inode_data(&i)
    }

    /// Inodes that are free in the bitmap but still carry metadata (deleted files).
    pub fn deleted_inodes(&self) -> Result<Vec<Inode>> {
        let mut out = Vec::new();
        let n = (self.sb.inodes_count as u64).min(MAX_INODE_SCAN);
        let ipg = self.sb.inodes_per_group as u64;
        let mut bitmaps: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
        for ino in 1..=n {
            let g = ((ino - 1) / ipg) as usize;
            let idx = (ino - 1) % ipg;
            let Some(gd) = self.groups.get(g) else { break };
            if gd.flags & 0x1 != 0 {
                continue;
            }
            if !bitmaps.contains_key(&g) {
                bitmaps.clear();
                bitmaps.insert(g, self.read_block(gd.inode_bitmap)?);
            }
            let alloc = bitmaps
                .get(&g)
                .and_then(|bm| bm.get((idx / 8) as usize))
                .is_some_and(|b| b & (1 << (idx % 8)) != 0);
            if alloc {
                continue;
            }
            if let Ok(i) = self.inode(ino) {
                if i.mode != 0 && (i.dtime != 0 || i.links == 0) {
                    out.push(i);
                }
            }
        }
        Ok(out)
    }

    pub fn journal(&self) -> Result<journal::Journal> {
        if self.sb.journal_inum == 0 {
            return Err(FsError::NotFound("no journal inode".into()));
        }
        let ji = self.inode(self.sb.journal_inum as u64)?;
        let data = self.read_inode_data(&ji)?;
        journal::parse(&data)
    }
}

/// True when `src` carries an ext superblock.
pub fn probe(sb: &[u8]) -> bool {
    sb.len() >= 0x3A && sb[0x38] == 0x53 && sb[0x39] == 0xEF
}
