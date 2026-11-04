//! MFT FILE records: update-sequence fixups, attribute headers, data runs and typed attribute values.
use crate::error::{FsError, Result};
use crate::util::{guid_le, i64_at, need, u16_at, u32_at, u64_at, u8_at, utf16le};
use serde::Serialize;

/// Maximum attributes parsed from one FILE record.
pub const MAX_ATTRIBUTES_PER_RECORD: usize = 256;
/// Maximum data runs decoded for one attribute.
pub const MAX_RUNS: usize = 1 << 16;

pub const AT_STANDARD_INFORMATION: u32 = 0x10;
pub const AT_ATTRIBUTE_LIST: u32 = 0x20;
pub const AT_FILE_NAME: u32 = 0x30;
pub const AT_OBJECT_ID: u32 = 0x40;
pub const AT_SECURITY_DESCRIPTOR: u32 = 0x50;
pub const AT_VOLUME_NAME: u32 = 0x60;
pub const AT_VOLUME_INFORMATION: u32 = 0x70;
pub const AT_DATA: u32 = 0x80;
pub const AT_INDEX_ROOT: u32 = 0x90;
pub const AT_INDEX_ALLOCATION: u32 = 0xA0;
pub const AT_BITMAP: u32 = 0xB0;
pub const AT_REPARSE_POINT: u32 = 0xC0;
pub const AT_EA_INFORMATION: u32 = 0xD0;
pub const AT_EA: u32 = 0xE0;
pub const AT_LOGGED_UTILITY_STREAM: u32 = 0x100;

pub fn attribute_type_name(t: u32) -> &'static str {
    match t {
        0x10 => "$STANDARD_INFORMATION",
        0x20 => "$ATTRIBUTE_LIST",
        0x30 => "$FILE_NAME",
        0x40 => "$OBJECT_ID",
        0x50 => "$SECURITY_DESCRIPTOR",
        0x60 => "$VOLUME_NAME",
        0x70 => "$VOLUME_INFORMATION",
        0x80 => "$DATA",
        0x90 => "$INDEX_ROOT",
        0xA0 => "$INDEX_ALLOCATION",
        0xB0 => "$BITMAP",
        0xC0 => "$REPARSE_POINT",
        0xD0 => "$EA_INFORMATION",
        0xE0 => "$EA",
        0x100 => "$LOGGED_UTILITY_STREAM",
        _ => "UNKNOWN",
    }
}

/// Split a 64-bit file reference into (entry, sequence).
pub fn split_ref(r: u64) -> (u64, u16) {
    (r & 0x0000_FFFF_FFFF_FFFF, (r >> 48) as u16)
}

/// Apply the update sequence array of a multi-sector protected record in place.
/// Returns `Ok(false)` when a sector's trailer did not match the update sequence number.
pub fn apply_fixups(buf: &mut [u8], sector: usize) -> Result<bool> {
    let usa_off = u16_at(buf, 4)? as usize;
    let usa_count = u16_at(buf, 6)? as usize;
    if usa_count == 0 {
        return Ok(true);
    }
    let usa = need(buf, usa_off, usa_count * 2)?.to_vec();
    let usn = [usa[0], usa[1]];
    let mut ok = true;
    for i in 1..usa_count {
        let pos = i * sector - 2;
        if pos + 2 > buf.len() {
            ok = false;
            break;
        }
        if buf[pos..pos + 2] != usn {
            ok = false;
        }
        buf[pos] = usa[i * 2];
        buf[pos + 1] = usa[i * 2 + 1];
    }
    Ok(ok)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Run {
    pub vcn: u64,
    pub length: u64,
    /// `None` for a sparse run.
    pub lcn: Option<u64>,
}

/// Decode a mapping-pairs (data run) list.
pub fn decode_runs(d: &[u8], start_vcn: u64) -> Result<Vec<Run>> {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    let mut vcn = start_vcn;
    let mut lcn: i64 = 0;
    while pos < d.len() {
        let h = d[pos];
        if h == 0 {
            break;
        }
        let len_size = (h & 0x0F) as usize;
        let off_size = (h >> 4) as usize;
        if len_size == 0 || len_size > 8 || off_size > 8 {
            return Err(FsError::invalid(pos as u64, "bad data run header"));
        }
        let lb = need(d, pos + 1, len_size)?;
        let mut length: u64 = 0;
        for (i, b) in lb.iter().enumerate() {
            length |= (*b as u64) << (8 * i);
        }
        let ob = need(d, pos + 1 + len_size, off_size)?;
        let run_lcn = if off_size == 0 {
            None
        } else {
            let mut off: i64 = 0;
            for (i, b) in ob.iter().enumerate() {
                off |= (*b as i64) << (8 * i);
            }
            let bits = 8 * off_size as u32;
            if bits < 64 && (off >> (bits - 1)) & 1 == 1 {
                off -= 1i64 << bits;
            }
            lcn = lcn.checked_add(off).ok_or_else(|| FsError::invalid(pos as u64, "LCN overflow"))?;
            if lcn < 0 {
                return Err(FsError::invalid(pos as u64, "negative LCN"));
            }
            Some(lcn as u64)
        };
        if length == 0 {
            return Err(FsError::invalid(pos as u64, "zero-length run"));
        }
        runs.push(Run { vcn, length, lcn: run_lcn });
        if runs.len() > MAX_RUNS {
            return Err(FsError::Limit("too many data runs".into()));
        }
        vcn = vcn.checked_add(length).ok_or_else(|| FsError::invalid(pos as u64, "VCN overflow"))?;
        pos += 1 + len_size + off_size;
    }
    Ok(runs)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Attribute {
    pub type_code: u32,
    pub name: String,
    pub id: u16,
    pub flags: u16,
    /// MFT entry the attribute was physically stored in (differs from the base for extension records).
    pub record: u64,
    pub resident: bool,
    #[serde(skip)]
    pub data: Vec<u8>,
    pub start_vcn: u64,
    pub last_vcn: u64,
    pub runs: Vec<Run>,
    pub alloc_size: u64,
    pub data_size: u64,
    pub init_size: u64,
    pub compression_unit: u16,
}

impl Attribute {
    pub fn is_compressed(&self) -> bool { self.flags & 0x0001 != 0 }
    pub fn is_encrypted(&self) -> bool { self.flags & 0x4000 != 0 }
    pub fn is_sparse(&self) -> bool { self.flags & 0x8000 != 0 }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MftRecord {
    pub entry: u64,
    pub sequence: u16,
    pub link_count: u16,
    pub flags: u16,
    pub lsn: u64,
    pub base_ref: u64,
    pub used_size: u32,
    pub alloc_size: u32,
    pub fixup_ok: bool,
    pub attributes: Vec<Attribute>,
    /// Attribute parsing stopped early because of a malformed attribute header.
    pub truncated: bool,
}

impl MftRecord {
    pub fn in_use(&self) -> bool { self.flags & 0x0001 != 0 }
    pub fn is_dir(&self) -> bool { self.flags & 0x0002 != 0 }
    pub fn base_entry(&self) -> u64 { split_ref(self.base_ref).0 }

    /// Parse a FILE record. `fallback_entry` is used when the header does not carry its own number.
    pub fn parse(raw: &[u8], fallback_entry: u64) -> Result<Self> {
        let sig = need(raw, 0, 4)?;
        if sig != b"FILE" {
            return Err(FsError::sig(0, "FILE", sig));
        }
        let mut buf = raw.to_vec();
        let fixup_ok = apply_fixups(&mut buf, 512)?;
        let usa_off = u16_at(&buf, 4)?;
        let attr_off = u16_at(&buf, 0x14)? as usize;
        let used = (u32_at(&buf, 0x18)? as usize).min(buf.len());
        let entry = if usa_off >= 0x30 { u32_at(&buf, 0x2C)? as u64 } else { fallback_entry };
        let mut rec = MftRecord {
            entry: if entry == 0 && fallback_entry != 0 { fallback_entry } else { entry },
            sequence: u16_at(&buf, 0x10)?,
            link_count: u16_at(&buf, 0x12)?,
            flags: u16_at(&buf, 0x16)?,
            lsn: u64_at(&buf, 0x08)?,
            base_ref: u64_at(&buf, 0x20)?,
            used_size: u32_at(&buf, 0x18)?,
            alloc_size: u32_at(&buf, 0x1C)?,
            fixup_ok,
            attributes: Vec::new(),
            truncated: false,
        };
        let mut pos = attr_off;
        for _ in 0..MAX_ATTRIBUTES_PER_RECORD {
            let Ok(t) = u32_at(&buf, pos) else {
                rec.truncated = true;
                break;
            };
            if t == 0xFFFF_FFFF {
                break;
            }
            let len = match u32_at(&buf, pos + 4) {
                Ok(l) => l as usize,
                Err(_) => {
                    rec.truncated = true;
                    break;
                }
            };
            if len < 0x18 || pos.checked_add(len).map_or(true, |e| e > used) || len % 8 != 0 {
                rec.truncated = true;
                break;
            }
            match parse_attribute(&buf[pos..pos + len], rec.entry) {
                Ok(a) => rec.attributes.push(a),
                Err(_) => rec.truncated = true,
            }
            pos += len;
        }
        Ok(rec)
    }
}

pub fn parse_attribute(a: &[u8], record: u64) -> Result<Attribute> {
    let type_code = u32_at(a, 0)?;
    let non_res = u8_at(a, 8)? != 0;
    let name_len = u8_at(a, 9)? as usize;
    let name_off = u16_at(a, 0x0A)? as usize;
    let name = if name_len > 0 { utf16le(need(a, name_off, name_len * 2)?, false) } else { String::new() };
    let flags = u16_at(a, 0x0C)?;
    let id = u16_at(a, 0x0E)?;
    if !non_res {
        let vlen = u32_at(a, 0x10)? as usize;
        let voff = u16_at(a, 0x14)? as usize;
        let data = need(a, voff, vlen)?.to_vec();
        Ok(Attribute { type_code, name, id, flags, record, resident: true, data_size: vlen as u64, alloc_size: vlen as u64, init_size: vlen as u64, data, start_vcn: 0, last_vcn: 0, runs: Vec::new(), compression_unit: 0 })
    } else {
        let start_vcn = u64_at(a, 0x10)?;
        let last_vcn = u64_at(a, 0x18)?;
        let run_off = u16_at(a, 0x20)? as usize;
        let cu = u16_at(a, 0x22)?;
        let runs = decode_runs(need(a, run_off, a.len().saturating_sub(run_off))?, start_vcn)?;
        Ok(Attribute {
            type_code,
            name,
            id,
            flags,
            record,
            resident: false,
            data: Vec::new(),
            start_vcn,
            last_vcn,
            runs,
            alloc_size: u64_at(a, 0x28)?,
            data_size: u64_at(a, 0x30)?,
            init_size: u64_at(a, 0x38)?,
            compression_unit: cu,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StdInfo {
    pub crtime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atime: u64,
    pub flags: u32,
    pub owner_id: Option<u32>,
    pub security_id: Option<u32>,
    pub usn: Option<u64>,
}

impl StdInfo {
    pub fn parse(d: &[u8]) -> Result<Self> {
        let mut s = StdInfo { crtime: u64_at(d, 0)?, mtime: u64_at(d, 8)?, ctime: u64_at(d, 0x10)?, atime: u64_at(d, 0x18)?, flags: u32_at(d, 0x20)?, ..Default::default() };
        if d.len() >= 0x48 {
            s.owner_id = Some(u32_at(d, 0x30)?);
            s.security_id = Some(u32_at(d, 0x34)?);
            s.usn = Some(u64_at(d, 0x40)?);
        }
        Ok(s)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FileName {
    pub parent_entry: u64,
    pub parent_sequence: u16,
    pub crtime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atime: u64,
    pub alloc_size: u64,
    pub real_size: u64,
    pub flags: u32,
    pub reparse: u32,
    /// 0 POSIX, 1 Win32, 2 DOS, 3 Win32+DOS.
    pub namespace: u8,
    pub name: String,
}

impl FileName {
    pub fn parse(d: &[u8]) -> Result<Self> {
        let (pe, ps) = split_ref(u64_at(d, 0)?);
        let nlen = u8_at(d, 0x40)? as usize;
        Ok(FileName {
            parent_entry: pe,
            parent_sequence: ps,
            crtime: u64_at(d, 0x08)?,
            mtime: u64_at(d, 0x10)?,
            ctime: u64_at(d, 0x18)?,
            atime: u64_at(d, 0x20)?,
            alloc_size: u64_at(d, 0x28)?,
            real_size: u64_at(d, 0x30)?,
            flags: u32_at(d, 0x38)?,
            reparse: u32_at(d, 0x3C)?,
            namespace: u8_at(d, 0x41)?,
            name: utf16le(need(d, 0x42, nlen * 2)?, false),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ObjectId {
    pub object_id: String,
    pub birth_volume_id: Option<String>,
    pub birth_object_id: Option<String>,
    pub domain_id: Option<String>,
}

impl ObjectId {
    pub fn parse(d: &[u8]) -> Result<Self> {
        let opt = |o: usize| if d.len() >= o + 16 { guid_le(&d[o..o + 16]).ok() } else { None };
        Ok(ObjectId { object_id: guid_le(need(d, 0, 16)?)?, birth_volume_id: opt(16), birth_object_id: opt(32), domain_id: opt(48) })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ReparsePoint {
    pub tag: u32,
    pub tag_name: String,
    pub substitute_name: Option<String>,
    pub print_name: Option<String>,
}

impl ReparsePoint {
    pub fn parse(d: &[u8]) -> Result<Self> {
        let tag = u32_at(d, 0)?;
        let dlen = u16_at(d, 4)? as usize;
        let body = need(d, 8, dlen.min(d.len().saturating_sub(8)))?;
        let tag_name = match tag {
            0xA000_000C => "symbolic_link",
            0xA000_0003 => "mount_point",
            0x8000_0017 => "wof",
            0x8000_0013 => "dedup",
            0x9000_001C => "onedrive",
            _ => "other",
        }
        .to_string();
        let (mut subst, mut print) = (None, None);
        let buf_off = match tag {
            0xA000_000C => Some(12usize),
            0xA000_0003 => Some(8usize),
            _ => None,
        };
        if let Some(bo) = buf_off {
            let so = u16_at(body, 0)? as usize;
            let sl = u16_at(body, 2)? as usize;
            let po = u16_at(body, 4)? as usize;
            let pl = u16_at(body, 6)? as usize;
            subst = need(body, bo + so, sl).ok().map(|b| utf16le(b, false));
            print = need(body, bo + po, pl).ok().map(|b| utf16le(b, false));
        }
        Ok(ReparsePoint { tag, tag_name, substitute_name: subst, print_name: print })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttrListEntry {
    pub type_code: u32,
    pub name: String,
    pub start_vcn: u64,
    pub record: u64,
    pub record_sequence: u16,
    pub id: u16,
}

/// Maximum entries decoded from one $ATTRIBUTE_LIST.
pub const MAX_ATTR_LIST_ENTRIES: usize = 4096;

pub fn parse_attribute_list(d: &[u8]) -> Result<Vec<AttrListEntry>> {
    let mut v = Vec::new();
    let mut pos = 0usize;
    while pos + 0x1A <= d.len() && v.len() < MAX_ATTR_LIST_ENTRIES {
        let t = u32_at(d, pos)?;
        let len = u16_at(d, pos + 4)? as usize;
        if t == 0 || len < 0x1A {
            break;
        }
        let nlen = u8_at(d, pos + 6)? as usize;
        let noff = u8_at(d, pos + 7)? as usize;
        let name = if nlen > 0 { utf16le(need(d, pos + noff, nlen * 2)?, false) } else { String::new() };
        let (rec, seq) = split_ref(u64_at(d, pos + 0x10)?);
        v.push(AttrListEntry { type_code: t, name, start_vcn: u64_at(d, pos + 8)?, record: rec, record_sequence: seq, id: u16_at(d, pos + 0x18)? });
        pos += len;
    }
    Ok(v)
}

/// FILETIME helper retained for callers that need signed arithmetic.
pub fn ft_i64(d: &[u8], o: usize) -> Result<i64> { i64_at(d, o) }
