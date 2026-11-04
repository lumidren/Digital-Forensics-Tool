//! FAT12/16/32 and exFAT: boot sector, FAT chains, directory entries (LFN assembly with checksum,
//! exFAT entry sets), deleted entries (0xE5 / cleared in-use bit) and file reading.
use crate::error::{FsError, Result};
use crate::io::{read_vec, read_vec_padded, Source};
use crate::util::{need, u16_at, u32_at, u8_at, utf16le};
use serde::Serialize;
use std::collections::BTreeSet;
use veritas_timeline::fat_datetime_to_ns;

/// Maximum directory depth walked.
pub const MAX_DIR_DEPTH: usize = 64;
/// Maximum entries returned by a full walk.
pub const MAX_WALK_ENTRIES: usize = 1 << 20;
/// Maximum FAT table size loaded into memory.
pub const MAX_FAT_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum file size read into memory.
pub const MAX_FILE_READ: u64 = 1 << 30;
/// Maximum directory size (bytes) read.
pub const MAX_DIR_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
    ExFat,
}

impl FatType {
    pub fn name(&self) -> &'static str {
        match self {
            FatType::Fat12 => "FAT12",
            FatType::Fat16 => "FAT16",
            FatType::Fat32 => "FAT32",
            FatType::ExFat => "exFAT",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FatEntry {
    pub path: String,
    pub name: String,
    pub short_name: String,
    pub is_dir: bool,
    pub deleted: bool,
    pub size: u64,
    pub first_cluster: u32,
    pub attributes: u16,
    pub crtime: Option<i64>,
    pub mtime: Option<i64>,
    pub atime: Option<i64>,
    /// Byte offset of the (short / primary) directory entry in the volume; stable identifier.
    pub dir_entry_offset: u64,
    /// exFAT: data is contiguous, no FAT chain.
    pub no_fat_chain: bool,
    /// LFN checksum did not match (name taken from short entry).
    pub lfn_mismatch: bool,
    /// exFAT stream data length (also set for directories, whose `size` is reported as 0).
    pub data_length: u64,
}

#[derive(Debug, Clone, Copy)]
enum DirLoc {
    FixedRoot,
    Chain { cluster: u32, contiguous: bool, size: u64 },
}

pub struct FatFs {
    src: Source,
    pub kind: FatType,
    pub bytes_per_sector: u64,
    pub cluster_size: u64,
    pub fat_offset: u64,
    pub fat_size: u64,
    pub root_dir_offset: u64,
    pub root_dir_size: u64,
    pub data_offset: u64,
    pub root_cluster: u32,
    pub cluster_count: u32,
    pub label: String,
    pub serial: u32,
    fat: Vec<u8>,
}

fn sfn_checksum(n: &[u8]) -> u8 {
    n.iter().fold(0u8, |s, &c| ((s & 1) << 7).wrapping_add(s >> 1).wrapping_add(c))
}

fn sfn_to_string(n: &[u8], nt_res: u8) -> String {
    let mut base: Vec<u8> = n[0..8].to_vec();
    if base[0] == 0xE5 {
        base[0] = b'_'; // deletion marker: the original first character is lost
    } else if base[0] == 0x05 {
        base[0] = 0xE5;
    }
    let trim = |v: &[u8]| -> String { v.iter().map(|&b| b as char).collect::<String>().trim_end().to_string() };
    let mut b = trim(&base);
    let mut e = trim(&n[8..11]);
    if nt_res & 0x08 != 0 {
        b = b.to_lowercase();
    }
    if nt_res & 0x10 != 0 {
        e = e.to_lowercase();
    }
    if e.is_empty() { b } else { format!("{b}.{e}") }
}

/// exFAT timestamp + 10 ms increment + UTC offset byte -> epoch ns (UTC).
fn exfat_time(ts: u32, ms10: u8, utc: u8) -> Option<i64> {
    if ts == 0 {
        return None;
    }
    let t = fat_datetime_to_ns((ts >> 16) as u16, (ts & 0xFFFF) as u16, ms10)?;
    if utc & 0x80 != 0 {
        let q = ((utc & 0x7F) as i8).wrapping_shl(1) >> 1; // sign-extend 7 bits
        Some(t - (q as i64) * 15 * 60 * 1_000_000_000)
    } else {
        Some(t)
    }
}

impl FatFs {
    pub fn open(src: Source) -> Result<Self> {
        let b = read_vec(src.as_ref(), 0, 512)?;
        if need(&b, 3, 8)? == b"EXFAT   " {
            return Self::open_exfat(src, &b);
        }
        if u16_at(&b, 510)? != 0xAA55 {
            return Err(FsError::sig(510, "55AA", &b[510..512]));
        }
        let bps = u16_at(&b, 11)? as u64;
        let spc = u8_at(&b, 13)? as u64;
        let reserved = u16_at(&b, 14)? as u64;
        let nfats = u8_at(&b, 16)? as u64;
        let root_entries = u16_at(&b, 17)? as u64;
        let tot16 = u16_at(&b, 19)? as u64;
        let fatsz16 = u16_at(&b, 22)? as u64;
        let tot32 = u32_at(&b, 32)? as u64;
        let fatsz32 = u32_at(&b, 36)? as u64;
        if !matches!(bps, 512 | 1024 | 2048 | 4096) || spc == 0 || !spc.is_power_of_two() || nfats == 0 || nfats > 4 || reserved == 0 {
            return Err(FsError::invalid(11, "not a FAT boot sector"));
        }
        let fat_sectors = if fatsz16 != 0 { fatsz16 } else { fatsz32 };
        let total = if tot16 != 0 { tot16 } else { tot32 };
        let root_sectors = (root_entries * 32).div_ceil(bps);
        let data_start = reserved + nfats * fat_sectors + root_sectors;
        if fat_sectors == 0 || total <= data_start {
            return Err(FsError::invalid(19, "FAT geometry"));
        }
        let clusters = (total - data_start) / spc;
        let kind = if clusters < 4085 {
            FatType::Fat12
        } else if clusters < 65525 {
            FatType::Fat16
        } else {
            FatType::Fat32
        };
        let (label_off, serial_off, root_cluster) = if kind == FatType::Fat32 { (71usize, 67usize, u32_at(&b, 44)?) } else { (43, 39, 0) };
        let fat_offset = reserved * bps;
        let fat_size = fat_sectors * bps;
        if fat_size > MAX_FAT_BYTES {
            return Err(FsError::Limit("FAT too large".into()));
        }
        let fat = read_vec_padded(src.as_ref(), fat_offset, fat_size)?;
        Ok(FatFs {
            kind,
            bytes_per_sector: bps,
            cluster_size: bps * spc,
            fat_offset,
            fat_size,
            root_dir_offset: (reserved + nfats * fat_sectors) * bps,
            root_dir_size: root_sectors * bps,
            data_offset: data_start * bps,
            root_cluster,
            cluster_count: clusters.min(u32::MAX as u64) as u32,
            label: crate::util::ascii(need(&b, label_off, 11)?, false).trim_end().to_string(),
            serial: u32_at(&b, serial_off)?,
            fat,
            src,
        })
    }

    fn open_exfat(src: Source, b: &[u8]) -> Result<Self> {
        let bps_shift = u8_at(b, 0x6C)? as u32;
        let spc_shift = u8_at(b, 0x6D)? as u32;
        if !(9..=12).contains(&bps_shift) || spc_shift > 25 - bps_shift.min(25) {
            return Err(FsError::invalid(0x6C, "exFAT geometry"));
        }
        let bps = 1u64 << bps_shift;
        let cs = bps << spc_shift;
        let fat_offset = u32_at(b, 0x50)? as u64 * bps;
        let fat_size = u32_at(b, 0x54)? as u64 * bps;
        if fat_size > MAX_FAT_BYTES {
            return Err(FsError::Limit("FAT too large".into()));
        }
        let fat = read_vec_padded(src.as_ref(), fat_offset, fat_size)?;
        let mut fs = FatFs {
            kind: FatType::ExFat,
            bytes_per_sector: bps,
            cluster_size: cs,
            fat_offset,
            fat_size,
            root_dir_offset: 0,
            root_dir_size: 0,
            data_offset: u32_at(b, 0x58)? as u64 * bps,
            root_cluster: u32_at(b, 0x60)?,
            cluster_count: u32_at(b, 0x5C)?,
            label: String::new(),
            serial: u32_at(b, 0x64)?,
            fat,
            src,
        };
        if let Ok(root) = fs.read_dir_bytes(DirLoc::Chain { cluster: fs.root_cluster, contiguous: false, size: 0 }) {
            for e in root.chunks_exact(32) {
                if e[0] == 0x83 {
                    let n = (e[1] as usize).min(11);
                    fs.label = utf16le(&e[2..2 + n * 2], false);
                }
                if e[0] == 0 {
                    break;
                }
            }
        }
        Ok(fs)
    }

    pub fn source(&self) -> &Source { &self.src }

    /// Next cluster in the chain, `None` at end-of-chain / bad / free / out of range.
    pub fn next_cluster(&self, c: u32) -> Option<u32> {
        let v = self.fat_entry(c)?;
        let (eoc, bad) = match self.kind {
            FatType::Fat12 => (0xFF8, 0xFF7),
            FatType::Fat16 => (0xFFF8, 0xFFF7),
            FatType::Fat32 => (0x0FFF_FFF8, 0x0FFF_FFF7),
            FatType::ExFat => (0xFFFF_FFF8, 0xFFFF_FFF7),
        };
        if v < 2 || v >= eoc || v == bad || v > self.cluster_count + 1 {
            None
        } else {
            Some(v)
        }
    }

    /// Raw FAT value for cluster `c` (0 = free).
    pub fn fat_entry(&self, c: u32) -> Option<u32> {
        let c = c as usize;
        match self.kind {
            FatType::Fat12 => {
                let o = c + c / 2;
                let v = u16_at(&self.fat, o).ok()? as u32;
                Some(if c & 1 == 1 { v >> 4 } else { v & 0xFFF })
            }
            FatType::Fat16 => u16_at(&self.fat, c * 2).ok().map(|v| v as u32),
            FatType::Fat32 => u32_at(&self.fat, c * 4).ok().map(|v| v & 0x0FFF_FFFF),
            FatType::ExFat => u32_at(&self.fat, c * 4).ok(),
        }
    }

    pub fn cluster_allocated(&self, c: u32) -> bool { self.fat_entry(c).is_some_and(|v| v != 0) }

    pub fn cluster_offset(&self, c: u32) -> Option<u64> {
        if c < 2 || c > self.cluster_count + 1 {
            return None;
        }
        Some(self.data_offset + (c as u64 - 2) * self.cluster_size)
    }

    /// Follow a FAT chain (loop- and length-checked).
    pub fn chain(&self, first: u32, max_clusters: u64) -> Result<Vec<u32>> {
        let mut v = Vec::new();
        if first < 2 {
            return Ok(v);
        }
        let limit = max_clusters.min(self.cluster_count as u64 + 1);
        let mut c = first;
        loop {
            if self.cluster_offset(c).is_none() {
                break;
            }
            v.push(c);
            if v.len() as u64 > limit {
                return Err(FsError::invalid(c as u64, "FAT chain loop or overrun"));
            }
            match self.next_cluster(c) {
                Some(n) => c = n,
                None => break,
            }
        }
        Ok(v)
    }

    fn read_clusters(&self, clusters: &[u32], size: u64) -> Result<Vec<u8>> {
        if size > MAX_FILE_READ {
            return Err(FsError::Limit("file too large".into()));
        }
        let mut out = Vec::with_capacity(size as usize);
        for &c in clusters {
            if out.len() as u64 >= size {
                break;
            }
            let off = self.cluster_offset(c).ok_or_else(|| FsError::invalid(c as u64, "cluster out of range"))?;
            let want = self.cluster_size.min(size - out.len() as u64);
            out.extend_from_slice(&read_vec_padded(self.src.as_ref(), off, want)?);
        }
        Ok(out)
    }

    /// Read `size` bytes from contiguous clusters starting at `first` (exFAT NoFatChain, deleted files).
    pub fn read_contiguous(&self, first: u32, size: u64) -> Result<Vec<u8>> {
        if size > MAX_FILE_READ {
            return Err(FsError::Limit("file too large".into()));
        }
        let off = self.cluster_offset(first).ok_or_else(|| FsError::invalid(first as u64, "cluster out of range"))?;
        read_vec_padded(self.src.as_ref(), off, size)
    }

    pub fn read(&self, e: &FatEntry) -> Result<Vec<u8>> {
        if e.is_dir {
            return Err(FsError::invalid(e.dir_entry_offset, "is a directory"));
        }
        if e.size == 0 {
            return Ok(Vec::new());
        }
        if e.no_fat_chain || e.deleted {
            return self.read_contiguous(e.first_cluster, e.size);
        }
        let n = e.size.div_ceil(self.cluster_size);
        let ch = self.chain(e.first_cluster, n)?;
        let mut d = self.read_clusters(&ch, e.size)?;
        d.resize(e.size as usize, 0);
        Ok(d)
    }

    fn read_dir_bytes(&self, loc: DirLoc) -> Result<Vec<u8>> {
        match loc {
            DirLoc::FixedRoot => read_vec_padded(self.src.as_ref(), self.root_dir_offset, self.root_dir_size),
            DirLoc::Chain { cluster, contiguous, size } => {
                if contiguous && size > 0 {
                    return self.read_contiguous(cluster, size.min(MAX_DIR_BYTES));
                }
                let ch = self.chain(cluster, MAX_DIR_BYTES / self.cluster_size.max(1))?;
                self.read_clusters(&ch, (ch.len() as u64 * self.cluster_size).min(MAX_DIR_BYTES))
            }
        }
    }

    /// Volume offset of byte `i` of a directory stream.
    fn dir_byte_offset(&self, loc: DirLoc, i: u64) -> u64 {
        match loc {
            DirLoc::FixedRoot => self.root_dir_offset + i,
            DirLoc::Chain { cluster, contiguous, .. } => {
                let idx = i / self.cluster_size;
                let c = if contiguous { cluster.checked_add(idx as u32) } else { self.chain(cluster, idx + 1).ok().and_then(|v| v.get(idx as usize).copied()) };
                c.and_then(|c| self.cluster_offset(c)).map(|o| o + i % self.cluster_size).unwrap_or(0)
            }
        }
    }

    fn parse_dir(&self, loc: DirLoc, parent: &str) -> Result<Vec<FatEntry>> {
        let data = self.read_dir_bytes(loc)?;
        if self.kind == FatType::ExFat {
            return Ok(self.parse_exfat_dir(&data, loc, parent));
        }
        let mut out = Vec::new();
        let mut lfn: Vec<(u8, u8, String)> = Vec::new(); // (ord, checksum, part)
        for (i, e) in data.chunks_exact(32).enumerate() {
            let first = e[0];
            if first == 0x00 {
                break;
            }
            let attr = e[11];
            if attr & 0x3F == 0x0F {
                let part = {
                    let mut b = Vec::with_capacity(26);
                    b.extend_from_slice(&e[1..11]);
                    b.extend_from_slice(&e[14..26]);
                    b.extend_from_slice(&e[28..32]);
                    let mut units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                    if let Some(p) = units.iter().position(|&u| u == 0 || u == 0xFFFF) {
                        units.truncate(p);
                    }
                    String::from_utf16_lossy(&units)
                };
                if first & 0x40 != 0 && first != 0xE5 {
                    lfn.clear();
                }
                lfn.push((first, e[13], part));
                continue;
            }
            let deleted = first == 0xE5;
            if attr & 0x08 != 0 && attr & 0x10 == 0 {
                lfn.clear();
                continue; // volume label
            }
            let short = sfn_to_string(&e[0..11], e[12]);
            let mut name_bytes = [0u8; 11];
            name_bytes.copy_from_slice(&e[0..11]);
            let ck = sfn_checksum(&name_bytes);
            let mut name = short.clone();
            let mut lfn_mismatch = false;
            if !lfn.is_empty() {
                if lfn.iter().all(|(_, c, _)| *c == ck) || deleted {
                    let mut parts = lfn.clone();
                    if !deleted {
                        parts.sort_by_key(|(o, _, _)| o & 0x1F);
                    } else {
                        parts.reverse();
                    }
                    let n: String = parts.into_iter().map(|(_, _, p)| p).collect();
                    if !n.is_empty() {
                        name = n;
                    }
                } else {
                    lfn_mismatch = true;
                }
            }
            lfn.clear();
            if short == "." || short == ".." {
                continue;
            }
            let fc = ((u16_at(e, 20)? as u32) << 16) | u16_at(e, 26)? as u32;
            let fc = if self.kind == FatType::Fat32 { fc } else { fc & 0xFFFF };
            let is_dir = attr & 0x10 != 0;
            let date = |o: usize| u16_at(e, o).unwrap_or(0);
            out.push(FatEntry {
                path: format!("{}/{}", parent.trim_end_matches('/'), name),
                name,
                short_name: short,
                is_dir,
                deleted,
                size: if is_dir { 0 } else { u32_at(e, 28)? as u64 },
                first_cluster: fc,
                attributes: attr as u16,
                crtime: if date(16) != 0 { fat_datetime_to_ns(date(16), date(14), e[13]) } else { None },
                mtime: if date(24) != 0 { fat_datetime_to_ns(date(24), date(22), 0) } else { None },
                atime: if date(18) != 0 { fat_datetime_to_ns(date(18), 0, 0) } else { None },
                dir_entry_offset: self.dir_byte_offset(loc, (i * 32) as u64),
                no_fat_chain: false,
                lfn_mismatch,
                data_length: 0,
            });
        }
        Ok(out)
    }

    fn parse_exfat_dir(&self, data: &[u8], loc: DirLoc, parent: &str) -> Vec<FatEntry> {
        let mut out = Vec::new();
        let n = data.len() / 32;
        let mut i = 0usize;
        while i < n {
            let e = &data[i * 32..i * 32 + 32];
            let t = e[0];
            if t == 0x00 {
                break;
            }
            if t & 0x7F != 0x05 {
                i += 1;
                continue;
            }
            let deleted = t & 0x80 == 0;
            let sec = e[1] as usize;
            if sec < 2 || i + sec >= n {
                i += 1;
                continue;
            }
            let attrs = u16::from_le_bytes([e[4], e[5]]);
            let ts = |o: usize| u32::from_le_bytes([e[o], e[o + 1], e[o + 2], e[o + 3]]);
            let s = &data[(i + 1) * 32..(i + 2) * 32];
            if s[0] & 0x7F != 0x40 {
                i += 1;
                continue;
            }
            let name_len = s[3] as usize;
            let mut units: Vec<u16> = Vec::new();
            for k in 2..=sec {
                let f = &data[(i + k) * 32..(i + k + 1) * 32];
                if f[0] & 0x7F != 0x41 {
                    break;
                }
                units.extend(f[2..32].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])));
            }
            units.truncate(name_len);
            let name = String::from_utf16_lossy(&units);
            let is_dir = attrs & 0x10 != 0;
            let size = u64::from_le_bytes(s[24..32].try_into().unwrap_or([0; 8]));
            out.push(FatEntry {
                path: format!("{}/{}", parent.trim_end_matches('/'), name),
                name: name.clone(),
                short_name: String::new(),
                is_dir,
                deleted,
                size: if is_dir { 0 } else { size },
                first_cluster: u32::from_le_bytes([s[20], s[21], s[22], s[23]]),
                attributes: attrs,
                crtime: exfat_time(ts(8), e[20], e[22]),
                mtime: exfat_time(ts(12), e[21], e[23]),
                atime: exfat_time(ts(16), 0, e[24]),
                dir_entry_offset: self.dir_byte_offset(loc, (i * 32) as u64),
                no_fat_chain: s[1] & 0x02 != 0,
                lfn_mismatch: false,
                data_length: size,
            });
            i += 1 + sec;
        }
        out
    }

    fn dir_loc_of(&self, e: &FatEntry) -> DirLoc {
        DirLoc::Chain { cluster: e.first_cluster, contiguous: e.no_fat_chain || e.deleted, size: if e.no_fat_chain || e.deleted { self.exfat_dir_size(e) } else { 0 } }
    }

    fn exfat_dir_size(&self, e: &FatEntry) -> u64 {
        // Contiguous directory: exFAT data length, else one cluster when the true size is unknown.
        if e.data_length > 0 { e.data_length } else { self.cluster_size }
    }

    fn root_loc(&self) -> DirLoc {
        match self.kind {
            FatType::Fat12 | FatType::Fat16 => DirLoc::FixedRoot,
            _ => DirLoc::Chain { cluster: self.root_cluster, contiguous: false, size: 0 },
        }
    }

    /// Entries of the root directory (including deleted ones).
    pub fn root(&self) -> Result<Vec<FatEntry>> { self.parse_dir(self.root_loc(), "/") }

    /// Entries of directory `e` (including deleted ones).
    pub fn list_dir(&self, e: &FatEntry) -> Result<Vec<FatEntry>> {
        if !e.is_dir {
            return Err(FsError::invalid(e.dir_entry_offset, "not a directory"));
        }
        self.parse_dir(self.dir_loc_of(e), &e.path)
    }

    /// Recursive walk; deleted directories are listed but not descended.
    pub fn walk(&self, include_deleted: bool) -> Result<Vec<FatEntry>> {
        let mut out = Vec::new();
        let mut stack: Vec<(Vec<FatEntry>, usize)> = vec![(self.root()?, 0)];
        let mut seen_dirs: BTreeSet<u32> = BTreeSet::new();
        while let Some((list, depth)) = stack.pop() {
            for e in list {
                if out.len() >= MAX_WALK_ENTRIES {
                    return Ok(out);
                }
                if e.deleted && !include_deleted {
                    continue;
                }
                if e.is_dir && !e.deleted && depth < MAX_DIR_DEPTH && e.first_cluster >= 2 && seen_dirs.insert(e.first_cluster) {
                    if let Ok(children) = self.list_dir(&e) {
                        stack.push((children, depth + 1));
                    }
                }
                out.push(e);
            }
        }
        out.sort_by(|a, b| (&a.path, a.dir_entry_offset).cmp(&(&b.path, b.dir_entry_offset)));
        Ok(out)
    }

    pub fn lookup(&self, path: &str) -> Result<FatEntry> {
        let mut list = self.root()?;
        let comps: Vec<&str> = path.split(['/', '\\']).filter(|c| !c.is_empty()).collect();
        for (k, comp) in comps.iter().enumerate() {
            let hit = list
                .iter()
                .find(|e| !e.deleted && (e.name == *comp || e.short_name == *comp))
                .or_else(|| list.iter().find(|e| !e.deleted && (e.name.eq_ignore_ascii_case(comp) || e.short_name.eq_ignore_ascii_case(comp))))
                .cloned()
                .ok_or_else(|| FsError::NotFound(path.to_string()))?;
            if k + 1 == comps.len() {
                return Ok(hit);
            }
            list = self.list_dir(&hit)?;
        }
        Err(FsError::NotFound(path.to_string()))
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let e = self.lookup(path)?;
        self.read(&e)
    }
}

/// True when `b` looks like a FAT or exFAT boot sector.
pub fn probe(b: &[u8]) -> bool {
    if b.len() < 512 {
        return false;
    }
    if &b[3..11] == b"EXFAT   " {
        return true;
    }
    if b[510] != 0x55 || b[511] != 0xAA || &b[3..11] == b"NTFS    " {
        return false;
    }
    let bps = u16::from_le_bytes([b[11], b[12]]);
    let spc = b[13];
    let nfats = b[16];
    matches!(bps, 512 | 1024 | 2048 | 4096) && spc != 0 && spc.is_power_of_two() && (1..=4).contains(&nfats) && (b[0] == 0xEB || b[0] == 0xE9)
}
