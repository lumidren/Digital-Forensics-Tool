//! USN change journal (`$UsnJrnl:$J`) records, versions 2, 3 and 4.
use super::record::split_ref;
use crate::util::{need, u16_at, u32_at, u64_at, utf16le};
use serde::Serialize;

/// Maximum records returned from one buffer.
pub const MAX_USN_RECORDS: usize = 10_000_000;
/// Largest record length accepted.
pub const MAX_USN_RECORD_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsnRecord {
    /// Byte offset of the record in the `$J` stream.
    pub offset: u64,
    pub major_version: u16,
    pub minor_version: u16,
    pub file_entry: u64,
    pub file_sequence: u16,
    pub parent_entry: u64,
    pub parent_sequence: u16,
    /// Full 128-bit reference (hex) for v3/v4 records.
    pub file_reference_128: Option<String>,
    pub usn: u64,
    pub timestamp_raw: u64,
    pub timestamp: Option<i64>,
    pub reason: u32,
    pub reasons: Vec<String>,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: u32,
    pub name: String,
}

const REASONS: &[(u32, &str)] = &[
    (0x0000_0001, "DATA_OVERWRITE"),
    (0x0000_0002, "DATA_EXTEND"),
    (0x0000_0004, "DATA_TRUNCATION"),
    (0x0000_0010, "NAMED_DATA_OVERWRITE"),
    (0x0000_0020, "NAMED_DATA_EXTEND"),
    (0x0000_0040, "NAMED_DATA_TRUNCATION"),
    (0x0000_0100, "FILE_CREATE"),
    (0x0000_0200, "FILE_DELETE"),
    (0x0000_0400, "EA_CHANGE"),
    (0x0000_0800, "SECURITY_CHANGE"),
    (0x0000_1000, "RENAME_OLD_NAME"),
    (0x0000_2000, "RENAME_NEW_NAME"),
    (0x0000_4000, "INDEXABLE_CHANGE"),
    (0x0000_8000, "BASIC_INFO_CHANGE"),
    (0x0001_0000, "HARD_LINK_CHANGE"),
    (0x0002_0000, "COMPRESSION_CHANGE"),
    (0x0004_0000, "ENCRYPTION_CHANGE"),
    (0x0008_0000, "OBJECT_ID_CHANGE"),
    (0x0010_0000, "REPARSE_POINT_CHANGE"),
    (0x0020_0000, "STREAM_CHANGE"),
    (0x0040_0000, "TRANSACTED_CHANGE"),
    (0x0080_0000, "INTEGRITY_CHANGE"),
    (0x8000_0000, "CLOSE"),
];

/// Reasons that indicate the file content was modified.
pub const DATA_CHANGE_MASK: u32 = 0x0000_0077;

pub fn reason_names(r: u32) -> Vec<String> {
    REASONS
        .iter()
        .filter(|(b, _)| r & b != 0)
        .map(|(_, n)| n.to_string())
        .collect()
}

fn parse_one(d: &[u8], pos: usize, base: u64) -> Option<(UsnRecord, usize)> {
    let len = u32_at(d, pos).ok()? as usize;
    if !(0x38..=MAX_USN_RECORD_LEN).contains(&len) || len % 8 != 0 {
        return None;
    }
    let r = need(d, pos, len).ok()?;
    let major = u16_at(r, 4).ok()?;
    let minor = u16_at(r, 6).ok()?;
    let mut rec = UsnRecord {
        offset: base + pos as u64,
        major_version: major,
        minor_version: minor,
        file_entry: 0,
        file_sequence: 0,
        parent_entry: 0,
        parent_sequence: 0,
        file_reference_128: None,
        usn: 0,
        timestamp_raw: 0,
        timestamp: None,
        reason: 0,
        reasons: vec![],
        source_info: 0,
        security_id: 0,
        file_attributes: 0,
        name: String::new(),
    };
    match major {
        2 => {
            let (fe, fs) = split_ref(u64_at(r, 8).ok()?);
            let (pe, ps) = split_ref(u64_at(r, 16).ok()?);
            rec.file_entry = fe;
            rec.file_sequence = fs;
            rec.parent_entry = pe;
            rec.parent_sequence = ps;
            rec.usn = u64_at(r, 24).ok()?;
            rec.timestamp_raw = u64_at(r, 32).ok()?;
            rec.reason = u32_at(r, 40).ok()?;
            rec.source_info = u32_at(r, 44).ok()?;
            rec.security_id = u32_at(r, 48).ok()?;
            rec.file_attributes = u32_at(r, 52).ok()?;
            let nl = u16_at(r, 56).ok()? as usize;
            let no = u16_at(r, 58).ok()? as usize;
            rec.name = utf16le(need(r, no, nl).ok()?, false);
        }
        3 => {
            let f = need(r, 8, 16).ok()?;
            let p = need(r, 24, 16).ok()?;
            rec.file_reference_128 = Some(hex::encode(f));
            let (fe, fs) = split_ref(u64_at(f, 0).ok()?);
            let (pe, ps) = split_ref(u64_at(p, 0).ok()?);
            rec.file_entry = fe;
            rec.file_sequence = fs;
            rec.parent_entry = pe;
            rec.parent_sequence = ps;
            rec.usn = u64_at(r, 40).ok()?;
            rec.timestamp_raw = u64_at(r, 48).ok()?;
            rec.reason = u32_at(r, 56).ok()?;
            rec.source_info = u32_at(r, 60).ok()?;
            rec.security_id = u32_at(r, 64).ok()?;
            rec.file_attributes = u32_at(r, 68).ok()?;
            let nl = u16_at(r, 72).ok()? as usize;
            let no = u16_at(r, 74).ok()? as usize;
            rec.name = utf16le(need(r, no, nl).ok()?, false);
        }
        4 => {
            let f = need(r, 8, 16).ok()?;
            let p = need(r, 24, 16).ok()?;
            rec.file_reference_128 = Some(hex::encode(f));
            let (fe, fs) = split_ref(u64_at(f, 0).ok()?);
            let (pe, ps) = split_ref(u64_at(p, 0).ok()?);
            rec.file_entry = fe;
            rec.file_sequence = fs;
            rec.parent_entry = pe;
            rec.parent_sequence = ps;
            rec.usn = u64_at(r, 40).ok()?;
            rec.reason = u32_at(r, 48).ok()?;
            rec.source_info = u32_at(r, 52).ok()?;
        }
        _ => return None,
    }
    rec.timestamp = veritas_timeline::filetime_to_ns(rec.timestamp_raw);
    rec.reasons = reason_names(rec.reason);
    Some((rec, len))
}

/// Parse every USN record in `d` (a raw `$J` extract or one allocated chunk of it).
/// `base` is the stream offset of `d[0]`. Zero padding and garbage are skipped in 8-byte steps.
pub fn parse_usn_records(d: &[u8], base: u64) -> Vec<UsnRecord> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 8 <= d.len() && out.len() < MAX_USN_RECORDS {
        if d[pos..pos + 8].iter().all(|&b| b == 0) {
            pos += 8;
            continue;
        }
        match parse_one(d, pos, base) {
            Some((r, len)) => {
                out.push(r);
                pos += len;
            }
            None => pos += 8,
        }
    }
    out
}
