//! jbd2 journal: superblock, and enumeration of descriptor / commit / revoke blocks (big-endian).
use crate::error::{FsError, Result};
use crate::util::{need, u16_be_at, u32_be_at, u64_be_at};
use serde::Serialize;

pub const JBD2_MAGIC: u32 = 0xC03B_3998;
/// Maximum journal blocks enumerated.
pub const MAX_JOURNAL_BLOCKS: usize = 1 << 22;
/// Maximum tags decoded from one descriptor block.
pub const MAX_TAGS: usize = 4096;

const INCOMPAT_64BIT: u32 = 0x2;
const INCOMPAT_CSUM_V2: u32 = 0x8;
const INCOMPAT_CSUM_V3: u32 = 0x10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JournalBlock {
    pub index: u64,
    pub block_type: u32,
    pub type_name: String,
    pub sequence: u32,
    /// Descriptor: file-system blocks logged in the following journal blocks.
    pub tags: Vec<u64>,
    /// Commit: commit time (ns since epoch).
    pub commit_time: Option<i64>,
    /// Revoke: revoked file-system blocks.
    pub revoked: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Journal {
    pub block_size: u32,
    pub max_len: u32,
    pub first: u32,
    pub sequence: u32,
    pub start: u32,
    pub version: u32,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: String,
    pub blocks: Vec<JournalBlock>,
}

fn type_name(t: u32) -> &'static str {
    match t {
        1 => "descriptor",
        2 => "commit",
        3 => "superblock_v1",
        4 => "superblock_v2",
        5 => "revoke",
        _ => "unknown",
    }
}

pub fn parse(d: &[u8]) -> Result<Journal> {
    if u32_be_at(d, 0)? != JBD2_MAGIC {
        return Err(FsError::sig(0, "C03B3998", need(d, 0, 4)?));
    }
    let bt = u32_be_at(d, 4)?;
    if bt != 3 && bt != 4 {
        return Err(FsError::invalid(4, "journal superblock type"));
    }
    let bs = u32_be_at(d, 0x0C)?;
    if !(1024..=65536).contains(&bs) || !bs.is_power_of_two() {
        return Err(FsError::invalid(0x0C, "journal block size"));
    }
    let (fc, fi, fr) = if bt == 4 { (u32_be_at(d, 0x24)?, u32_be_at(d, 0x28)?, u32_be_at(d, 0x2C)?) } else { (0, 0, 0) };
    let mut j = Journal {
        block_size: bs,
        max_len: u32_be_at(d, 0x10)?,
        first: u32_be_at(d, 0x14)?,
        sequence: u32_be_at(d, 0x18)?,
        start: u32_be_at(d, 0x1C)?,
        version: if bt == 4 { 2 } else { 1 },
        feature_compat: fc,
        feature_incompat: fi,
        feature_ro_compat: fr,
        uuid: crate::util::uuid_be(need(d, 0x30, 16)?)?,
        blocks: Vec::new(),
    };
    let is64 = fi & INCOMPAT_64BIT != 0;
    let v3 = fi & INCOMPAT_CSUM_V3 != 0;
    let tag_size = if v3 {
        if is64 { 16 } else { 12 }
    } else {
        8 + if is64 { 4 } else { 0 } + if fi & INCOMPAT_CSUM_V2 != 0 { 2 } else { 0 }
    };
    let bsz = bs as usize;
    for (i, blk) in d.chunks_exact(bsz).enumerate().skip(1) {
        if j.blocks.len() >= MAX_JOURNAL_BLOCKS {
            break;
        }
        if u32_be_at(blk, 0)? != JBD2_MAGIC {
            continue;
        }
        let t = u32_be_at(blk, 4)?;
        let seq = u32_be_at(blk, 8)?;
        let mut jb = JournalBlock { index: i as u64, block_type: t, type_name: type_name(t).into(), sequence: seq, tags: vec![], commit_time: None, revoked: vec![] };
        match t {
            1 => {
                let mut p = 12usize;
                while p + tag_size <= bsz && jb.tags.len() < MAX_TAGS {
                    let lo = u32_be_at(blk, p)? as u64;
                    let (hi, flags) = if v3 {
                        (if is64 { u32_be_at(blk, p + 8)? as u64 } else { 0 }, u32_be_at(blk, p + 4)?)
                    } else {
                        (if is64 { u32_be_at(blk, p + 8)? as u64 } else { 0 }, u16_be_at(blk, p + 6)? as u32)
                    };
                    jb.tags.push((hi << 32) | lo);
                    p += tag_size;
                    if flags & 0x2 == 0 {
                        p += 16; // UUID follows
                    }
                    if flags & 0x8 != 0 {
                        break;
                    }
                }
            }
            2 => {
                let s = u64_be_at(blk, 0x30)?;
                let ns = u32_be_at(blk, 0x38)?;
                if s != 0 {
                    jb.commit_time = veritas_timeline::unix_to_ns(s as i64, ns.min(999_999_999));
                }
            }
            5 => {
                let count = (u32_be_at(blk, 12)? as usize).min(bsz);
                let w = if is64 { 8 } else { 4 };
                let mut p = 16usize;
                while p + w <= count {
                    jb.revoked.push(if is64 { u64_be_at(blk, p)? } else { u32_be_at(blk, p)? as u64 });
                    p += w;
                }
            }
            _ => {}
        }
        j.blocks.push(jb);
    }
    Ok(j)
}
