//! NTFS: boot sector, MFT records, attributes (resident / non-resident / sparse / compressed),
//! $ATTRIBUTE_LIST, $I30 indexes incl. slack, path reconstruction, $UsnJrnl:$J, $LogFile and
//! timestomp heuristics.
pub mod boot;
pub mod index;
pub mod logfile;
pub mod lznt1;
pub mod record;
pub mod timestomp;
pub mod usn;

use crate::error::{FsError, Result};
use crate::io::{read_vec, read_vec_padded, MemSource, ReadAt, Source};
use boot::BootSector;
use index::IndexEntry;
use record::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Largest stream materialised in memory by `read_stream`.
pub const MAX_FILE_READ: u64 = 1 << 30;
/// Maximum parent hops followed while reconstructing a path.
pub const MAX_PATH_DEPTH: usize = 256;
/// Maximum extension records loaded through one $ATTRIBUTE_LIST.
pub const MAX_EXTENSION_RECORDS: usize = 256;
/// Maximum MFT entries enumerated.
pub const MAX_MFT_ENTRIES: u64 = 1 << 26;
/// Root directory MFT entry.
pub const ROOT_ENTRY: u64 = 5;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DataStream {
    pub name: String,
    pub size: u64,
    pub alloc_size: u64,
    pub init_size: u64,
    pub resident: bool,
    #[serde(skip)]
    pub resident_data: Vec<u8>,
    pub runs: Vec<Run>,
    pub flags: u16,
    pub compression_unit: u16,
}

impl DataStream {
    /// Merge the attribute pieces (extents from base and extension records) of one stream.
    pub fn from_parts(mut parts: Vec<&Attribute>) -> Option<Self> {
        parts.sort_by_key(|a| (a.start_vcn, a.record, a.id));
        let first = *parts.first()?;
        if first.resident {
            return Some(DataStream { name: first.name.clone(), size: first.data_size, alloc_size: first.data_size, init_size: first.data_size, resident: true, resident_data: first.data.clone(), runs: vec![], flags: first.flags, compression_unit: 0 });
        }
        let head = parts.iter().find(|a| a.start_vcn == 0).copied().unwrap_or(first);
        let mut runs = Vec::new();
        for p in &parts {
            if !p.resident {
                runs.extend(p.runs.iter().cloned());
            }
        }
        Some(DataStream { name: head.name.clone(), size: head.data_size, alloc_size: head.alloc_size, init_size: head.init_size, resident: false, resident_data: vec![], runs, flags: head.flags, compression_unit: head.compression_unit })
    }
    pub fn is_compressed(&self) -> bool { self.flags & 0x0001 != 0 && self.compression_unit != 0 }
    pub fn is_encrypted(&self) -> bool { self.flags & 0x4000 != 0 }
    pub fn is_sparse(&self) -> bool { self.flags & 0x8000 != 0 }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttrSummary {
    pub type_code: u32,
    pub type_name: String,
    pub name: String,
    pub id: u16,
    pub resident: bool,
    pub data_size: u64,
    pub record: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FileEntry {
    pub entry: u64,
    pub sequence: u16,
    pub in_use: bool,
    pub is_dir: bool,
    /// Base record number for extension records, 0 for base records.
    pub base_entry: u64,
    pub link_count: u16,
    pub lsn: u64,
    pub fixup_ok: bool,
    pub si: Option<StdInfo>,
    pub file_names: Vec<FileName>,
    pub streams: Vec<DataStream>,
    pub object_id: Option<ObjectId>,
    pub reparse: Option<ReparsePoint>,
    pub attribute_list: Vec<AttrListEntry>,
    pub attributes: Vec<AttrSummary>,
    pub path: Option<String>,
    #[serde(skip)]
    pub index_root: Option<Vec<u8>>,
    #[serde(skip)]
    pub index_allocation: Option<DataStream>,
}

impl FileEntry {
    /// Preferred name: Win32 or Win32+DOS, then POSIX, then DOS (8.3).
    pub fn best_name(&self) -> Option<&FileName> {
        let rank = |ns: u8| match ns {
            1 | 3 => 0,
            0 => 1,
            _ => 2,
        };
        self.file_names.iter().min_by_key(|f| rank(f.namespace))
    }
    pub fn name(&self) -> Option<&str> { self.best_name().map(|f| f.name.as_str()) }
    pub fn data(&self) -> Option<&DataStream> { self.streams.iter().find(|s| s.name.is_empty()) }
    pub fn stream(&self, name: &str) -> Option<&DataStream> { self.streams.iter().find(|s| s.name == name) }
    pub fn size(&self) -> u64 { self.data().map(|d| d.size).unwrap_or(0) }
    pub fn ads_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.streams.iter().filter(|s| !s.name.is_empty()).map(|s| s.name.clone()).collect();
        v.sort();
        v
    }
    pub fn is_base(&self) -> bool { self.base_entry == 0 }
    pub fn file_reference(&self) -> String { format!("{}-{}", self.entry, self.sequence) }
}

/// Anything that can hand out raw MFT records: a mounted volume or a bare `$MFT` extract.
pub trait RecordProvider {
    fn record_size(&self) -> u32;
    fn record_count(&self) -> u64;
    fn record_bytes(&self, n: u64) -> Result<Vec<u8>>;
    /// Read a non-resident stream. Bare `$MFT` extracts have no cluster data and return `Unsupported`.
    fn read_nonresident(&self, _s: &DataStream) -> Result<Vec<u8>> {
        Err(FsError::Unsupported("non-resident data without a volume".into()))
    }
}

/// Build a file entry from MFT record `n`, following its $ATTRIBUTE_LIST into extension records.
pub fn build_entry(p: &dyn RecordProvider, n: u64) -> Result<FileEntry> {
    let rec = MftRecord::parse(&p.record_bytes(n)?, n)?;
    let mut attrs: Vec<Attribute> = rec.attributes.clone();
    let mut attribute_list = Vec::new();
    if let Some(al) = rec.attributes.iter().find(|a| a.type_code == AT_ATTRIBUTE_LIST) {
        let data = if al.resident {
            Some(al.data.clone())
        } else {
            DataStream::from_parts(vec![al]).and_then(|s| p.read_nonresident(&s).ok())
        };
        if let Some(d) = data {
            attribute_list = parse_attribute_list(&d).unwrap_or_default();
            let ext: BTreeSet<u64> = attribute_list.iter().map(|e| e.record).filter(|&r| r != n).take(MAX_EXTENSION_RECORDS).collect();
            for r in ext {
                if let Ok(b) = p.record_bytes(r) {
                    if let Ok(x) = MftRecord::parse(&b, r) {
                        if x.base_entry() == n {
                            attrs.extend(x.attributes.into_iter().filter(|a| a.type_code != AT_ATTRIBUTE_LIST));
                        }
                    }
                }
            }
        }
    }
    let mut e = FileEntry {
        entry: n,
        sequence: rec.sequence,
        in_use: rec.in_use(),
        is_dir: rec.is_dir(),
        base_entry: rec.base_entry(),
        link_count: rec.link_count,
        lsn: rec.lsn,
        fixup_ok: rec.fixup_ok,
        attribute_list,
        ..Default::default()
    };
    let mut data_groups: BTreeMap<String, Vec<&Attribute>> = BTreeMap::new();
    let mut ia_parts: Vec<&Attribute> = Vec::new();
    for a in &attrs {
        e.attributes.push(AttrSummary { type_code: a.type_code, type_name: attribute_type_name(a.type_code).into(), name: a.name.clone(), id: a.id, resident: a.resident, data_size: a.data_size, record: a.record });
        match a.type_code {
            AT_STANDARD_INFORMATION if e.si.is_none() && a.resident => e.si = StdInfo::parse(&a.data).ok(),
            AT_FILE_NAME if a.resident => {
                if let Ok(f) = FileName::parse(&a.data) {
                    e.file_names.push(f);
                }
            }
            AT_OBJECT_ID if a.resident => e.object_id = ObjectId::parse(&a.data).ok(),
            AT_REPARSE_POINT if a.resident => e.reparse = ReparsePoint::parse(&a.data).ok(),
            AT_DATA => data_groups.entry(a.name.clone()).or_default().push(a),
            AT_INDEX_ROOT if a.name == "$I30" && a.resident => e.index_root = Some(a.data.clone()),
            AT_INDEX_ALLOCATION if a.name == "$I30" => ia_parts.push(a),
            _ => {}
        }
    }
    for (_, parts) in data_groups {
        if let Some(s) = DataStream::from_parts(parts) {
            e.streams.push(s);
        }
    }
    e.index_allocation = DataStream::from_parts(ia_parts);
    Ok(e)
}

/// Fill `path` for every base entry from $FILE_NAME parent references.
pub fn compute_paths(entries: &mut [FileEntry]) {
    let mut names: BTreeMap<u64, (u64, String)> = BTreeMap::new();
    for e in entries.iter() {
        if e.is_base() {
            if let Some(f) = e.best_name() {
                names.insert(e.entry, (f.parent_entry, f.name.clone()));
            }
        }
    }
    let mut memo: BTreeMap<u64, String> = BTreeMap::new();
    for e in entries.iter_mut() {
        if !e.is_base() || !names.contains_key(&e.entry) {
            continue;
        }
        e.path = Some(path_for(e.entry, &names, &mut memo));
    }
}

fn path_for(n: u64, names: &BTreeMap<u64, (u64, String)>, memo: &mut BTreeMap<u64, String>) -> String {
    if n == ROOT_ENTRY {
        return "/".into();
    }
    if let Some(p) = memo.get(&n) {
        return p.clone();
    }
    let mut parts = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cur = n;
    let mut prefix = String::new();
    for _ in 0..MAX_PATH_DEPTH {
        if cur == ROOT_ENTRY {
            break;
        }
        if let Some(p) = memo.get(&cur) {
            prefix = p.trim_end_matches('/').to_string();
            break;
        }
        if !seen.insert(cur) {
            prefix = "/$OrphanFiles".into();
            break;
        }
        match names.get(&cur) {
            Some((parent, name)) => {
                parts.push(name.clone());
                cur = *parent;
            }
            None => {
                prefix = "/$OrphanFiles".into();
                break;
            }
        }
    }
    parts.reverse();
    let p = format!("{}/{}", prefix, parts.join("/"));
    memo.insert(n, p.clone());
    p
}

/// Read a non-resident (possibly sparse) stream range. Bytes past `init_size` read as zero.
fn read_runs_range(src: &dyn ReadAt, cs: u64, s: &DataStream, off: u64, len: u64) -> Result<Vec<u8>> {
    if len > MAX_FILE_READ {
        return Err(FsError::Limit("stream read too large".into()));
    }
    let mut out = vec![0u8; len as usize];
    let end = off.saturating_add(len);
    // Bytes past the initialised size read as zero: never copy them from disk.
    let init_end = end.min(s.init_size);
    for r in &s.runs {
        let rs = r.vcn.saturating_mul(cs);
        let re = rs.saturating_add(r.length.saturating_mul(cs));
        let a = rs.max(off);
        let b = re.min(init_end);
        if a >= b {
            continue;
        }
        if let Some(lcn) = r.lcn {
            let disk = lcn.saturating_mul(cs).saturating_add(a - rs);
            let chunk = read_vec_padded(src, disk, b - a)?;
            let o = (a - off) as usize;
            out[o..o + chunk.len()].copy_from_slice(&chunk);
        }
    }
    Ok(out)
}

fn read_compressed(src: &dyn ReadAt, cs: u64, s: &DataStream) -> Result<Vec<u8>> {
    let cu = 1u64 << s.compression_unit.min(16);
    let unit_bytes = cu * cs;
    let size = s.size;
    if size > MAX_FILE_READ {
        return Err(FsError::Limit("compressed stream too large".into()));
    }
    // vcn -> lcn map for the clusters actually covered by runs.
    let mut map: BTreeMap<u64, (u64, Option<u64>)> = BTreeMap::new();
    for r in &s.runs {
        map.insert(r.vcn, (r.length, r.lcn));
    }
    let lookup = |vcn: u64| -> Option<u64> {
        let (start, (len, lcn)) = map.range(..=vcn).next_back()?;
        if vcn < start + len {
            lcn.map(|l| l + (vcn - start))
        } else {
            None
        }
    };
    let mut out = Vec::with_capacity(size as usize);
    let units = size.div_ceil(unit_bytes);
    for u in 0..units {
        let base = u * cu;
        let lcns: Vec<Option<u64>> = (base..base + cu).map(lookup).collect();
        let present = lcns.iter().filter(|l| l.is_some()).count() as u64;
        if present == cu {
            for l in &lcns {
                out.extend_from_slice(&read_vec_padded(src, l.unwrap_or(0) * cs, cs)?);
            }
        } else if present == 0 {
            out.resize(out.len() + unit_bytes as usize, 0);
        } else {
            let mut comp = Vec::with_capacity((present * cs) as usize);
            for l in lcns.iter().flatten() {
                comp.extend_from_slice(&read_vec_padded(src, l * cs, cs)?);
            }
            let mut d = lznt1::decompress(&comp, unit_bytes as usize)?;
            d.resize(unit_bytes as usize, 0);
            out.extend_from_slice(&d);
        }
        if out.len() as u64 >= size {
            break;
        }
    }
    out.truncate(size as usize);
    Ok(out)
}

/// A mounted NTFS volume.
pub struct Ntfs {
    src: Source,
    pub boot: BootSector,
    mft: DataStream,
}

impl RecordProvider for Ntfs {
    fn record_size(&self) -> u32 { self.boot.mft_record_size }
    fn record_count(&self) -> u64 {
        // The $MFT cannot be larger than the volume holding it.
        let rs = self.boot.mft_record_size as u64;
        (self.mft.size.min(self.src.size()) / rs).min(MAX_MFT_ENTRIES)
    }
    fn record_bytes(&self, n: u64) -> Result<Vec<u8>> {
        let rs = self.boot.mft_record_size as u64;
        let off = n.checked_mul(rs).ok_or_else(|| FsError::invalid(n, "record number overflow"))?;
        if off + rs > self.mft.size {
            return Err(FsError::NotFound(format!("MFT entry {n}")));
        }
        read_runs_range(self.src.as_ref(), self.boot.cluster_size, &self.mft, off, rs)
    }
    fn read_nonresident(&self, s: &DataStream) -> Result<Vec<u8>> { self.read_stream(s) }
}

impl Ntfs {
    pub fn open(src: Source) -> Result<Self> {
        let b = read_vec(src.as_ref(), 0, 512)?;
        let boot = BootSector::parse(&b)?;
        let rs = boot.mft_record_size as u64;
        let mft_off = boot.mft_lcn.checked_mul(boot.cluster_size).ok_or_else(|| FsError::invalid(0x30, "MFT LCN overflow"))?;
        let r0 = read_vec(src.as_ref(), mft_off, rs)?;
        let rec0 = MftRecord::parse(&r0, 0)?;
        let parts: Vec<&Attribute> = rec0.attributes.iter().filter(|a| a.type_code == AT_DATA && a.name.is_empty()).collect();
        let mft = DataStream::from_parts(parts).ok_or_else(|| FsError::NotFound("$MFT $DATA".into()))?;
        if mft.resident {
            return Err(FsError::invalid(mft_off, "resident $MFT data"));
        }
        let mut fs = Ntfs { src, boot, mft };
        // A fragmented $MFT keeps further extents in extension records listed in $ATTRIBUTE_LIST.
        if rec0.attributes.iter().any(|a| a.type_code == AT_ATTRIBUTE_LIST) {
            if let Ok(e0) = build_entry(&fs, 0) {
                if let Some(d) = e0.data() {
                    if d.size >= fs.mft.size && !d.resident {
                        fs.mft = d.clone();
                    }
                }
            }
        }
        Ok(fs)
    }

    pub fn source(&self) -> &Source { &self.src }
    pub fn cluster_size(&self) -> u64 { self.boot.cluster_size }

    pub fn read_stream(&self, s: &DataStream) -> Result<Vec<u8>> {
        if s.resident {
            return Ok(s.resident_data.clone());
        }
        if s.is_encrypted() {
            return Err(FsError::Unsupported("EFS-encrypted stream".into()));
        }
        if s.is_compressed() {
            return read_compressed(self.src.as_ref(), self.boot.cluster_size, s);
        }
        read_runs_range(self.src.as_ref(), self.boot.cluster_size, s, 0, s.size)
    }

    /// Read `len` bytes at `off` of a stream without materialising the whole stream (compressed
    /// streams up to `MAX_FILE_READ` are decompressed in full and sliced).
    pub fn read_stream_at(&self, s: &DataStream, off: u64, len: u64) -> Result<Vec<u8>> {
        let end = off.saturating_add(len).min(s.size);
        if off >= end {
            return Ok(Vec::new());
        }
        if s.resident {
            return Ok(s.resident_data.get(off as usize..end as usize).unwrap_or(&[]).to_vec());
        }
        if s.is_encrypted() {
            return Err(FsError::Unsupported("EFS-encrypted stream".into()));
        }
        if s.is_compressed() {
            let all = read_compressed(self.src.as_ref(), self.boot.cluster_size, s)?;
            return Ok(all.get(off as usize..end as usize).unwrap_or(&[]).to_vec());
        }
        read_runs_range(self.src.as_ref(), self.boot.cluster_size, s, off, end - off)
    }

    /// Read only the allocated (non-sparse) runs of a stream as `(stream_offset, bytes)` chunks.
    pub fn read_allocated_chunks(&self, s: &DataStream, max_total: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        if s.resident {
            return Ok(vec![(0, s.resident_data.clone())]);
        }
        let cs = self.boot.cluster_size;
        let mut out = Vec::new();
        let mut total = 0u64;
        for r in &s.runs {
            let Some(lcn) = r.lcn else { continue };
            let start = r.vcn.saturating_mul(cs);
            if start >= s.size {
                continue;
            }
            let len = r.length.saturating_mul(cs).min(s.size - start);
            total = total.saturating_add(len);
            if total > max_total {
                return Err(FsError::Limit("allocated stream data too large".into()));
            }
            out.push((start, read_vec_padded(self.src.as_ref(), lcn.saturating_mul(cs), len)?));
        }
        Ok(out)
    }

    pub fn entry(&self, n: u64) -> Result<FileEntry> {
        let mut e = build_entry(self, n)?;
        if e.is_base() && e.best_name().is_some() {
            e.path = Some(self.path_of(n));
        }
        Ok(e)
    }

    /// Path of entry `n` from its $FILE_NAME chain.
    pub fn path_of(&self, n: u64) -> String {
        let mut names: BTreeMap<u64, (u64, String)> = BTreeMap::new();
        let mut cur = n;
        for _ in 0..MAX_PATH_DEPTH {
            if cur == ROOT_ENTRY || names.contains_key(&cur) {
                break;
            }
            match build_entry(self, cur) {
                Ok(e) => match e.best_name() {
                    Some(f) => {
                        names.insert(cur, (f.parent_entry, f.name.clone()));
                        cur = f.parent_entry;
                    }
                    None => break,
                },
                Err(_) => break,
            }
        }
        path_for(n, &names, &mut BTreeMap::new())
    }

    /// Every MFT entry that parses, with reconstructed paths.
    pub fn entries(&self) -> Result<Vec<FileEntry>> {
        let mut v = Vec::new();
        for n in 0..self.record_count() {
            if let Ok(e) = build_entry(self, n) {
                v.push(e);
            }
        }
        compute_paths(&mut v);
        Ok(v)
    }

    /// Directory listing from $I30 (live entries and slack-carved entries, `slack == true`).
    pub fn list_dir(&self, n: u64) -> Result<Vec<IndexEntry>> {
        let e = build_entry(self, n)?;
        let Some(root) = &e.index_root else {
            return Err(FsError::NotFound(format!("entry {n} has no $I30 index")));
        };
        let (mut out, rec_size) = index::parse_index_root(root)?;
        if let Some(ia) = &e.index_allocation {
            let data = self.read_stream(ia)?;
            let rs = if rec_size >= 512 { rec_size as usize } else { self.boot.index_record_size as usize };
            out.extend(index::parse_index_allocation(&data, rs, self.boot.bytes_per_sector as usize)?);
        }
        out.sort_by(|a, b| (a.slack, &a.file_name.name, a.entry, a.offset).cmp(&(b.slack, &b.file_name.name, b.entry, b.offset)));
        // Live entries are present in exactly one node; remove DOS-only duplicates of Win32 names.
        let mut seen = BTreeSet::new();
        out.retain(|ie| ie.slack || ie.file_name.namespace != 2 || seen.insert(ie.entry));
        Ok(out)
    }

    /// Resolve a `/`-separated path to an MFT entry number.
    pub fn lookup(&self, path: &str) -> Result<u64> {
        let mut cur = ROOT_ENTRY;
        for comp in path.split(['/', '\\']).filter(|c| !c.is_empty()) {
            let list = self.list_dir(cur)?;
            let live: Vec<&IndexEntry> = list.iter().filter(|e| !e.slack).collect();
            let hit = live.iter().find(|e| e.file_name.name == comp).or_else(|| live.iter().find(|e| e.file_name.name.eq_ignore_ascii_case(comp)));
            match hit {
                Some(e) => cur = e.entry,
                None => return Err(FsError::NotFound(path.to_string())),
            }
        }
        Ok(cur)
    }

    /// Read the unnamed (or a named) data stream of an entry.
    pub fn read_entry_data(&self, n: u64, stream: &str) -> Result<Vec<u8>> {
        let e = build_entry(self, n)?;
        let s = e.stream(stream).ok_or_else(|| FsError::NotFound(format!("stream '{stream}' of entry {n}")))?;
        self.read_stream(s)
    }

    /// Read a file by path; `path:stream` selects an alternate data stream.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let (p, s) = match path.rsplit_once(':') {
            Some((p, s)) if !s.contains('/') => (p, s),
            _ => (path, ""),
        };
        let n = self.lookup(p)?;
        self.read_entry_data(n, s)
    }

    /// Parse `$Extend/$UsnJrnl:$J` from the volume (only allocated runs are read).
    pub fn usn_records(&self) -> Result<Vec<usn::UsnRecord>> {
        let n = self.lookup("/$Extend/$UsnJrnl")?;
        let e = build_entry(self, n)?;
        let j = e.stream("$J").ok_or_else(|| FsError::NotFound("$UsnJrnl:$J".into()))?;
        let mut out = Vec::new();
        for (base, chunk) in self.read_allocated_chunks(j, MAX_FILE_READ)? {
            out.extend(usn::parse_usn_records(&chunk, base));
        }
        out.sort_by_key(|r| (r.usn, r.offset));
        Ok(out)
    }

    /// Parse `$LogFile` (entry 2).
    pub fn logfile(&self) -> Result<logfile::LogFile> {
        let data = self.read_entry_data(2, "")?;
        logfile::parse_logfile(&data, self.boot.cluster_size, self.boot.mft_record_size as u64)
    }
}

/// A bare `$MFT` extract (e.g. plaso `MFT`). Only resident data is readable.
pub struct MftFile {
    data: Source,
    record_size: u32,
}

impl MftFile {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let rs = (0..bytes.len().min(64 * 4096))
            .step_by(1024)
            .find_map(|o| {
                if bytes.get(o..o + 4) == Some(b"FILE") {
                    let a = crate::util::u32_at(&bytes, o + 0x1C).ok()?;
                    if (512..=65536).contains(&a) && a.is_power_of_two() {
                        return Some(a);
                    }
                }
                None
            })
            .ok_or_else(|| FsError::sig(0, "FILE", bytes.get(0..4).unwrap_or(&[])))?;
        Ok(Self { data: MemSource::source(bytes), record_size: rs })
    }
}

impl RecordProvider for MftFile {
    fn record_size(&self) -> u32 { self.record_size }
    fn record_count(&self) -> u64 { (self.data.size() / self.record_size as u64).min(MAX_MFT_ENTRIES) }
    fn record_bytes(&self, n: u64) -> Result<Vec<u8>> {
        let off = n.checked_mul(self.record_size as u64).ok_or_else(|| FsError::invalid(n, "record number overflow"))?;
        read_vec(self.data.as_ref(), off, self.record_size as u64)
    }
}

/// Parse a raw `$MFT` extract into file entries (with paths).
pub fn parse_mft_file(bytes: &[u8]) -> Result<Vec<FileEntry>> {
    let m = MftFile::new(bytes.to_vec())?;
    let mut v = Vec::new();
    for n in 0..m.record_count() {
        if let Ok(e) = build_entry(&m, n) {
            v.push(e);
        }
    }
    compute_paths(&mut v);
    Ok(v)
}
