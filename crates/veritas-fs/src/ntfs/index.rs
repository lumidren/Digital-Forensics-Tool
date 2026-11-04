//! $I30 directory indexes: $INDEX_ROOT, INDX buffers of $INDEX_ALLOCATION, and slack-space carving of
//! stale index entries (deleted or renamed files).
use super::record::{apply_fixups, split_ref, FileName};
use crate::error::{FsError, Result};
use crate::util::{need, u16_at, u32_at, u64_at};
use serde::Serialize;

/// Maximum index entries returned for a single directory (allocated + slack).
pub const MAX_INDEX_ENTRIES: usize = 1 << 20;
/// Lowest/highest FILETIME accepted for a carved slack entry (1980-01-01 .. 2100-01-01).
const FT_MIN: u64 = 119_600_064_000_000_000;
const FT_MAX: u64 = 157_469_184_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndexEntry {
    pub entry: u64,
    pub sequence: u16,
    pub file_name: FileName,
    /// Recovered from unused space of an index node rather than from its live entry list.
    pub slack: bool,
    /// Byte offset of the entry inside the index stream (root: offset in the attribute value).
    pub offset: u64,
    pub in_root: bool,
}

fn parse_entries(
    buf: &[u8],
    node_hdr: usize,
    base_offset: u64,
    in_root: bool,
    out: &mut Vec<IndexEntry>,
) -> Result<()> {
    let first = u32_at(buf, node_hdr)? as usize;
    let used = u32_at(buf, node_hdr + 4)? as usize;
    let alloc = u32_at(buf, node_hdr + 8)? as usize;
    let start = node_hdr
        .checked_add(first)
        .ok_or_else(|| FsError::invalid(node_hdr as u64, "entries offset"))?;
    let end_used = node_hdr.saturating_add(used).min(buf.len());
    let end_alloc = node_hdr.saturating_add(alloc).min(buf.len());
    let mut pos = start;
    while pos + 16 <= end_used && out.len() < MAX_INDEX_ENTRIES {
        let elen = u16_at(buf, pos + 8)? as usize;
        let klen = u16_at(buf, pos + 10)? as usize;
        let flags = u32_at(buf, pos + 12)?;
        if elen < 16 || pos + elen > end_used {
            break;
        }
        if flags & 2 == 0 && klen >= 0x42 {
            if let Ok(fname) = FileName::parse(need(buf, pos + 16, klen)?) {
                let (e, s) = split_ref(u64_at(buf, pos)?);
                out.push(IndexEntry {
                    entry: e,
                    sequence: s,
                    file_name: fname,
                    slack: false,
                    offset: base_offset + pos as u64,
                    in_root,
                });
            }
        }
        if flags & 2 != 0 {
            pos += elen;
            break;
        }
        pos += elen;
    }
    // Slack: scan 8-byte aligned positions after the live entries for plausible stale entries.
    let mut p = (pos + 7) & !7;
    while p + 0x52 <= end_alloc && out.len() < MAX_INDEX_ENTRIES {
        if let Some((ie, len)) = carve_entry(buf, p, end_alloc) {
            out.push(IndexEntry {
                offset: base_offset + p as u64,
                in_root,
                ..ie
            });
            p += (len + 7) & !7;
        } else {
            p += 8;
        }
    }
    Ok(())
}

fn plausible_time(t: u64) -> bool {
    (FT_MIN..FT_MAX).contains(&t)
}

fn carve_entry(buf: &[u8], p: usize, end: usize) -> Option<(IndexEntry, usize)> {
    let fref = u64_at(buf, p).ok()?;
    let klen = u16_at(buf, p + 10).ok()? as usize;
    if klen < 0x42 || klen > 0x242 {
        return None;
    }
    let key = need(buf, p + 16, 0x42).ok()?;
    let nlen = key[0x40] as usize;
    let ns = key[0x41];
    if nlen == 0 || ns > 3 || p + 16 + 0x42 + nlen * 2 > end {
        return None;
    }
    let fname = FileName::parse(need(buf, p + 16, 0x42 + nlen * 2).ok()?).ok()?;
    if !(plausible_time(fname.crtime)
        && plausible_time(fname.mtime)
        && plausible_time(fname.ctime)
        && plausible_time(fname.atime))
    {
        return None;
    }
    if fname.parent_entry == 0
        || fname.parent_entry > (1 << 40)
        || fname.real_size > fname.alloc_size.max(1 << 40)
    {
        return None;
    }
    if fname
        .name
        .chars()
        .any(|c| c == '\u{fffd}' || (c as u32) < 0x20)
    {
        return None;
    }
    let (e, s) = split_ref(fref);
    Some((
        IndexEntry {
            entry: e,
            sequence: s,
            file_name: fname,
            slack: true,
            offset: 0,
            in_root: false,
        },
        16 + 0x42 + nlen * 2,
    ))
}

/// Parse the value of an `$INDEX_ROOT` attribute. Returns entries and the index record size.
pub fn parse_index_root(value: &[u8]) -> Result<(Vec<IndexEntry>, u32)> {
    let rec_size = u32_at(value, 8)?;
    let mut out = Vec::new();
    parse_entries(value, 0x10, 0, true, &mut out)?;
    Ok((out, rec_size))
}

/// Parse the data of an `$INDEX_ALLOCATION` attribute as a sequence of INDX buffers.
pub fn parse_index_allocation(
    data: &[u8],
    rec_size: usize,
    sector: usize,
) -> Result<Vec<IndexEntry>> {
    if rec_size < 512 || rec_size > 65536 {
        return Err(FsError::invalid(0, "index record size"));
    }
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + rec_size <= data.len() && out.len() < MAX_INDEX_ENTRIES {
        let chunk = &data[off..off + rec_size];
        if &chunk[0..4] == b"INDX" {
            let mut b = chunk.to_vec();
            let _ = apply_fixups(&mut b, sector)?;
            let _ = parse_entries(&b, 0x18, off as u64, false, &mut out);
        }
        off += rec_size;
    }
    Ok(out)
}
