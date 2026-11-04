//! OLE Compound File (CFB, MS-CFB) reader: header, FAT/DIFAT, mini FAT, directory tree and
//! stream reading. All chains are cycle-checked and bounded by the sector count.
// `slice::as_chunks` needs Rust 1.88; the workspace MSRV is 1.80.
#![allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
use crate::error::{ParseError, Result};
use crate::shellitems::{decode_ansi, guid_string};
use crate::util::{need, u16_at, u32_at, u64_at, utf16le};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use veritas_timeline::filetime_to_ns;

pub const SIGNATURE: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const ENDOFCHAIN: u32 = 0xffff_fffe;
const FREESECT: u32 = 0xffff_ffff;
const NOSTREAM: u32 = 0xffff_ffff;
/// Directory entries above this count are refused.
const MAX_DIR_ENTRIES: usize = 1 << 20;

#[derive(Debug, Clone, Serialize)]
pub struct DirEntry {
    pub index: usize,
    pub name: String,
    pub entry_type: u8,
    pub left: u32,
    pub right: u32,
    pub child: u32,
    pub clsid: Option<String>,
    pub creation_ns: Option<i64>,
    pub modification_ns: Option<i64>,
    pub start_sector: u32,
    pub size: u64,
}

impl DirEntry {
    pub fn is_stream(&self) -> bool {
        self.entry_type == 2
    }
    pub fn is_storage(&self) -> bool {
        self.entry_type == 1 || self.entry_type == 5
    }
}

#[derive(Debug, Clone)]
pub struct Olecf<'a> {
    data: &'a [u8],
    pub major_version: u16,
    pub sector_size: usize,
    pub mini_sector_size: usize,
    pub mini_stream_cutoff: u32,
    fat: Vec<u32>,
    minifat: Vec<u32>,
    pub entries: Vec<DirEntry>,
    mini_stream: Vec<u8>,
}

pub fn is_olecf(data: &[u8]) -> bool {
    data.len() >= 8 && data[..8] == SIGNATURE
}

impl<'a> Olecf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let sig = need(data, 0, 8)?;
        if sig != SIGNATURE {
            return Err(ParseError::BadSignature { offset: 0, expected: hex::encode(SIGNATURE), found: hex::encode(sig) });
        }
        need(data, 0, 512)?;
        let major = u16_at(data, 0x1a)?;
        let sshift = u16_at(data, 0x1e)?;
        let mshift = u16_at(data, 0x20)?;
        if !(7..=16).contains(&sshift) || mshift > sshift {
            return Err(ParseError::Invalid { offset: 0x1e, reason: format!("sector shift {sshift}/{mshift}") });
        }
        let sector_size = 1usize << sshift;
        let mini_sector_size = 1usize << mshift;
        let num_fat = u32_at(data, 0x2c)? as usize;
        let first_dir = u32_at(data, 0x30)?;
        let cutoff = u32_at(data, 0x38)?;
        let first_minifat = u32_at(data, 0x3c)?;
        let first_difat = u32_at(data, 0x44)?;
        let num_difat = u32_at(data, 0x48)? as usize;
        let total_sectors = data.len() / sector_size;

        // DIFAT: 109 header entries plus chained DIFAT sectors.
        let mut fat_sectors = Vec::new();
        for i in 0..109 {
            let s = u32_at(data, 0x4c + i * 4)?;
            if s != FREESECT && s != ENDOFCHAIN {
                fat_sectors.push(s);
            }
        }
        let per = sector_size / 4 - 1;
        let mut ds = first_difat;
        let mut seen = 0usize;
        while ds != ENDOFCHAIN && ds != FREESECT && seen < num_difat.max(1).min(total_sectors + 1) {
            let off = sector_offset(ds, sector_size)?;
            let sec = need(data, off, sector_size)?;
            for i in 0..per {
                let s = u32_at(sec, i * 4)?;
                if s != FREESECT && s != ENDOFCHAIN {
                    fat_sectors.push(s);
                }
            }
            ds = u32_at(sec, per * 4)?;
            seen += 1;
        }
        if fat_sectors.len() > num_fat.max(1) * 2 + 1 && fat_sectors.len() > total_sectors + 1 {
            return Err(ParseError::Invalid { offset: 0x2c, reason: "FAT sector count exceeds file size".into() });
        }
        let mut fat = Vec::with_capacity(fat_sectors.len() * sector_size / 4);
        for s in fat_sectors.iter().take(total_sectors + 1) {
            let off = sector_offset(*s, sector_size)?;
            let sec = match need(data, off, sector_size) {
                Ok(s) => s,
                Err(_) => break, // tolerate truncated trailing FAT sectors
            };
            for c in sec.chunks_exact(4) {
                fat.push(u32::from_le_bytes([c[0], c[1], c[2], c[3]]));
            }
        }
        let mut o = Olecf {
            data,
            major_version: major,
            sector_size,
            mini_sector_size,
            mini_stream_cutoff: cutoff,
            fat,
            minifat: Vec::new(),
            entries: Vec::new(),
            mini_stream: Vec::new(),
        };
        // Directory.
        let dir = o.read_chain(first_dir, None)?;
        for (i, e) in dir.chunks_exact(128).enumerate() {
            if i >= MAX_DIR_ENTRIES {
                return Err(ParseError::Limit("too many directory entries".into()));
            }
            let name_len = (u16_at(e, 64)? as usize).min(64);
            let name = utf16le(&e[..name_len.saturating_sub(2)], true);
            let size = if major == 3 { u32_at(e, 120)? as u64 } else { u64_at(e, 120)? };
            o.entries.push(DirEntry {
                index: i,
                name,
                entry_type: e[66],
                left: u32_at(e, 68)?,
                right: u32_at(e, 72)?,
                child: u32_at(e, 76)?,
                clsid: guid_string(&e[80..96]).filter(|g| g != "00000000-0000-0000-0000-000000000000"),
                creation_ns: filetime_to_ns(u64_at(e, 100)?),
                modification_ns: filetime_to_ns(u64_at(e, 108)?),
                start_sector: u32_at(e, 116)?,
                size,
            });
        }
        if o.entries.is_empty() {
            return Err(ParseError::Invalid { offset: 0x30, reason: "empty directory".into() });
        }
        // Mini FAT and mini stream.
        if first_minifat != ENDOFCHAIN && first_minifat != FREESECT {
            let mf = o.read_chain(first_minifat, None)?;
            o.minifat = mf.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
        }
        let root = o.entries[0].clone();
        if root.start_sector != ENDOFCHAIN && root.start_sector != FREESECT && root.size > 0 {
            o.mini_stream = o.read_chain(root.start_sector, Some(root.size))?;
        }
        Ok(o)
    }

    fn read_chain(&self, start: u32, size: Option<u64>) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut s = start;
        let limit = self.fat.len().max(1);
        let mut steps = 0usize;
        while s != ENDOFCHAIN {
            if s == FREESECT || (s as usize) >= self.fat.len() && steps > 0 {
                break;
            }
            steps += 1;
            if steps > limit {
                return Err(ParseError::Invalid { offset: 0, reason: "FAT chain cycle".into() });
            }
            let off = sector_offset(s, self.sector_size)?;
            let sec = need(self.data, off, self.sector_size).or_else(|_| {
                // final partial sector at end of file
                if off < self.data.len() { Ok(&self.data[off..]) } else { Err(ParseError::Truncated { offset: off, needed: self.sector_size, available: 0 }) }
            })?;
            out.extend_from_slice(sec);
            if let Some(sz) = size {
                if out.len() as u64 >= sz {
                    break;
                }
            }
            s = match self.fat.get(s as usize) {
                Some(n) => *n,
                None => break,
            };
        }
        if let Some(sz) = size {
            if (out.len() as u64) < sz {
                return Err(ParseError::Truncated { offset: start as usize, needed: sz as usize, available: out.len() });
            }
            out.truncate(sz as usize);
        }
        Ok(out)
    }

    fn read_mini_chain(&self, start: u32, size: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut s = start;
        let mut steps = 0usize;
        while s != ENDOFCHAIN && (out.len() as u64) < size {
            steps += 1;
            if steps > self.minifat.len() + 1 {
                return Err(ParseError::Invalid { offset: 0, reason: "mini FAT chain cycle".into() });
            }
            let off = (s as usize).checked_mul(self.mini_sector_size).ok_or_else(|| ParseError::Invalid { offset: 0, reason: "mini sector overflow".into() })?;
            out.extend_from_slice(need(&self.mini_stream, off, self.mini_sector_size)?);
            s = match self.minifat.get(s as usize) {
                Some(n) => *n,
                None => break,
            };
        }
        if (out.len() as u64) < size {
            return Err(ParseError::Truncated { offset: start as usize, needed: size as usize, available: out.len() });
        }
        out.truncate(size as usize);
        Ok(out)
    }

    /// Read the full contents of a stream entry.
    pub fn read_stream(&self, idx: usize) -> Result<Vec<u8>> {
        let e = self.entries.get(idx).ok_or_else(|| ParseError::Invalid { offset: idx, reason: "no such directory entry".into() })?;
        if !e.is_stream() {
            return Err(ParseError::Invalid { offset: idx, reason: "not a stream".into() });
        }
        if e.size == 0 {
            return Ok(Vec::new());
        }
        if e.size > self.data.len() as u64 * 2 + 4096 {
            return Err(ParseError::Limit(format!("stream size {} exceeds file size", e.size)));
        }
        if e.size < self.mini_stream_cutoff as u64 {
            self.read_mini_chain(e.start_sector, e.size)
        } else {
            self.read_chain(e.start_sector, Some(e.size))
        }
    }

    /// Children of a storage entry, in red-black tree (in-order) order, cycle-protected.
    pub fn children(&self, idx: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let Some(e) = self.entries.get(idx) else { return out };
        let mut visited = vec![false; self.entries.len()];
        let mut stack: Vec<u32> = Vec::new();
        let mut cur = e.child;
        // iterative in-order traversal
        loop {
            while cur != NOSTREAM && (cur as usize) < self.entries.len() && !visited[cur as usize] {
                visited[cur as usize] = true;
                stack.push(cur);
                cur = self.entries[cur as usize].left;
            }
            let Some(n) = stack.pop() else { break };
            out.push(n as usize);
            cur = self.entries[n as usize].right;
        }
        out
    }

    pub fn root_children(&self) -> Vec<usize> {
        self.children(0)
    }

    /// Find a direct child of the root storage by name (case-insensitive).
    pub fn find_root_stream(&self, name: &str) -> Option<usize> {
        self.root_children().into_iter().find(|&i| self.entries[i].name.eq_ignore_ascii_case(name))
    }

    /// All entries as `(path, index)`, depth-first, sorted per storage by tree order.
    pub fn walk(&self) -> Vec<(String, usize)> {
        let mut out = Vec::new();
        let mut stack = vec![(String::new(), 0usize, 0usize)];
        let mut visited = vec![false; self.entries.len()];
        while let Some((prefix, idx, depth)) = stack.pop() {
            if depth > 64 || visited[idx] {
                continue;
            }
            visited[idx] = true;
            let kids = self.children(idx);
            for &k in kids.iter().rev() {
                let p = format!("{}/{}", prefix, self.entries[k].name);
                if self.entries[k].is_storage() {
                    stack.push((p.clone(), k, depth + 1));
                }
                out.push((p, k));
            }
        }
        out.sort();
        out
    }

    /// Generic `\x05SummaryInformation` / `\x05DocumentSummaryInformation` property sets.
    pub fn summary_information(&self) -> BTreeMap<String, Value> {
        let mut out = BTreeMap::new();
        for (sname, prefix) in [("\u{5}SummaryInformation", "summary"), ("\u{5}DocumentSummaryInformation", "document_summary")] {
            if let Some(i) = self.find_root_stream(sname) {
                if let Ok(d) = self.read_stream(i) {
                    for (k, v) in parse_property_set(&d, prefix == "summary") {
                        out.insert(format!("{prefix}.{k}"), v);
                    }
                }
            }
        }
        out
    }
}

fn sector_offset(s: u32, sector_size: usize) -> Result<usize> {
    (s as usize + 1).checked_mul(sector_size).ok_or_else(|| ParseError::Invalid { offset: 0, reason: "sector offset overflow".into() })
}

const SUMMARY_NAMES: &[(u32, &str)] = &[
    (1, "codepage"), (2, "title"), (3, "subject"), (4, "author"), (5, "keywords"), (6, "comments"), (7, "template"),
    (8, "last_saved_by"), (9, "revision_number"), (10, "edit_time"), (11, "last_printed"), (12, "creation_time"),
    (13, "last_save_time"), (14, "number_of_pages"), (15, "number_of_words"), (16, "number_of_characters"),
    (18, "application_name"), (19, "security"),
];

/// Parse the first section of an OLE property set stream (MS-OLEPS).
pub fn parse_property_set(d: &[u8], summary: bool) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    let Ok(sec_off) = u32_at(d, 44) else { return out };
    let sec_off = sec_off as usize;
    let Ok(count) = u32_at(d, sec_off + 4) else { return out };
    for i in 0..(count as usize).min(1024) {
        let (Ok(id), Ok(off)) = (u32_at(d, sec_off + 8 + i * 8), u32_at(d, sec_off + 12 + i * 8)) else { break };
        let vo = sec_off + off as usize;
        let Ok(vt) = u16_at(d, vo) else { continue };
        let v = match vt {
            0x02 => json!(u16_at(d, vo + 4).unwrap_or(0) as i16),
            0x03 => json!(u32_at(d, vo + 4).unwrap_or(0) as i32),
            0x13 => json!(u32_at(d, vo + 4).unwrap_or(0)),
            0x0b => json!(u16_at(d, vo + 4).unwrap_or(0) != 0),
            0x1e => {
                let n = u32_at(d, vo + 4).unwrap_or(0) as usize;
                let b = need(d, vo + 8, n).unwrap_or(&[]);
                json!(decode_ansi(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]))
            }
            0x1f => {
                let n = u32_at(d, vo + 4).unwrap_or(0) as usize;
                json!(utf16le(need(d, vo + 8, n.saturating_mul(2)).unwrap_or(&[]), true))
            }
            0x40 => {
                let ft = u64_at(d, vo + 4).unwrap_or(0);
                // edit_time (10) is a duration, others are timestamps
                if summary && id == 10 { json!({"duration_100ns": ft}) } else { json!({"filetime": ft, "ns": filetime_to_ns(ft)}) }
            }
            _ => json!({"vt": vt}),
        };
        let name = if summary { SUMMARY_NAMES.iter().find(|(k, _)| *k == id).map(|(_, n)| n.to_string()) } else { None };
        out.insert(name.unwrap_or_else(|| format!("prop_{id}")), v);
    }
    out
}
