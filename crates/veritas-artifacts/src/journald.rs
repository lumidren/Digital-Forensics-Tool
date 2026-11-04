//! systemd journal file parser (journal-file format, regular and compact layouts).
//!
//! LZ4-compressed data objects are decompressed with a built-in LZ4 block decoder; XZ and
//! ZSTD payloads are reported as unsupported per field instead of failing the file.
use crate::error::{ParseError, Result};
use crate::util::{need, u32_at, u64_at, u8_at};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use veritas_timeline::{desc, Event};

pub const SIGNATURE: &[u8; 8] = b"LPKSHHRH";
const INCOMPAT_XZ: u32 = 1;
const INCOMPAT_LZ4: u32 = 2;
const INCOMPAT_KEYED_HASH: u32 = 4;
const INCOMPAT_ZSTD: u32 = 8;
const INCOMPAT_COMPACT: u32 = 16;
const OBJ_DATA: u8 = 1;
const OBJ_ENTRY: u8 = 3;
const OBJ_ENTRY_ARRAY: u8 = 6;
/// Cap on a single decompressed field.
pub const MAX_FIELD_SIZE: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000_000;

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub compatible_flags: u32,
    pub incompatible_flags: u32,
    pub state: u8,
    pub file_id: String,
    pub machine_id: String,
    pub header_size: u64,
    pub arena_size: u64,
    pub n_objects: u64,
    pub n_entries: u64,
    pub entry_array_offset: u64,
    pub head_entry_realtime: u64,
    pub tail_entry_realtime: u64,
    pub compact: bool,
    pub keyed_hash: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub offset: u64,
    pub seqnum: u64,
    pub realtime_us: u64,
    pub monotonic_us: u64,
    pub boot_id: String,
    /// Field name -> values (a field can repeat). Values are lossily UTF-8 decoded.
    pub fields: BTreeMap<String, Vec<String>>,
    /// Fields whose payload could not be decoded (e.g. XZ/ZSTD compression).
    pub unsupported: Vec<String>,
}

impl Entry {
    pub fn get(&self, k: &str) -> Option<&str> {
        self.fields.get(k).and_then(|v| v.first()).map(|s| s.as_str())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Journal {
    pub header: Header,
    pub entries: Vec<Entry>,
    pub errors: Vec<String>,
}

fn id_hex(b: &[u8]) -> String {
    hex::encode(b)
}

/// LZ4 block-format decompression (no frame), output capped at `max_out`.
pub fn lz4_block_decompress(src: &[u8], expected: usize, max_out: usize) -> Result<Vec<u8>> {
    if expected > max_out {
        return Err(ParseError::Limit(format!("LZ4 output {expected} exceeds {max_out}")));
    }
    let mut out: Vec<u8> = Vec::with_capacity(expected);
    let mut i = 0usize;
    let rd_len = |i: &mut usize, base: usize| -> Result<usize> {
        let mut l = base;
        if base == 15 {
            loop {
                let b = *src.get(*i).ok_or(ParseError::Truncated { offset: *i, needed: 1, available: 0 })?;
                *i += 1;
                l = l.checked_add(b as usize).ok_or_else(|| ParseError::Limit("LZ4 length overflow".into()))?;
                if b != 255 {
                    break;
                }
            }
        }
        Ok(l)
    };
    while i < src.len() {
        let token = src[i];
        i += 1;
        let lit = rd_len(&mut i, (token >> 4) as usize)?;
        let lits = need(src, i, lit)?;
        if out.len() + lit > max_out {
            return Err(ParseError::Limit("LZ4 output cap".into()));
        }
        out.extend_from_slice(lits);
        i += lit;
        if i >= src.len() {
            break; // last sequence has literals only
        }
        let off = u16::from_le_bytes([src[i], *src.get(i + 1).ok_or(ParseError::Truncated { offset: i, needed: 2, available: 1 })?]) as usize;
        i += 2;
        if off == 0 || off > out.len() {
            return Err(ParseError::Invalid { offset: i, reason: format!("LZ4 match offset {off}") });
        }
        let mlen = rd_len(&mut i, (token & 15) as usize)? + 4;
        if out.len() + mlen > max_out {
            return Err(ParseError::Limit("LZ4 output cap".into()));
        }
        let start = out.len() - off;
        for k in 0..mlen {
            let b = out[start + k];
            out.push(b);
        }
    }
    if expected != 0 && out.len() != expected {
        return Err(ParseError::Invalid { offset: 0, reason: format!("LZ4 produced {} bytes, expected {expected}", out.len()) });
    }
    Ok(out)
}

pub fn parse(d: &[u8]) -> Result<Journal> {
    let sig = need(d, 0, 8)?;
    if sig != SIGNATURE {
        return Err(ParseError::BadSignature { offset: 0, expected: "LPKSHHRH".into(), found: hex::encode(sig) });
    }
    let incompat = u32_at(d, 12)?;
    let header = Header {
        compatible_flags: u32_at(d, 8)?,
        incompatible_flags: incompat,
        state: u8_at(d, 16)?,
        file_id: id_hex(need(d, 24, 16)?),
        machine_id: id_hex(need(d, 40, 16)?),
        header_size: u64_at(d, 88)?,
        arena_size: u64_at(d, 96)?,
        n_objects: u64_at(d, 144)?,
        n_entries: u64_at(d, 152)?,
        entry_array_offset: u64_at(d, 176)?,
        head_entry_realtime: u64_at(d, 184)?,
        tail_entry_realtime: u64_at(d, 192)?,
        compact: incompat & INCOMPAT_COMPACT != 0,
        keyed_hash: incompat & INCOMPAT_KEYED_HASH != 0,
    };
    let _ = (INCOMPAT_XZ, INCOMPAT_LZ4, INCOMPAT_ZSTD);
    let mut errors = Vec::new();
    // Walk the entry array chain.
    let mut offsets = Vec::new();
    let mut seen = BTreeSet::new();
    let mut arr = header.entry_array_offset;
    let want = (header.n_entries as usize).min(MAX_ENTRIES);
    while arr != 0 && offsets.len() < want {
        if !seen.insert(arr) {
            errors.push(format!("entry array cycle at {arr}"));
            break;
        }
        let o = arr as usize;
        let (typ, size) = match (u8_at(d, o), u64_at(d, o + 8)) {
            (Ok(t), Ok(s)) => (t, s as usize),
            _ => {
                errors.push(format!("truncated entry array at {o}"));
                break;
            }
        };
        if typ != OBJ_ENTRY_ARRAY || size < 24 || o.checked_add(size).map(|e| e > d.len()).unwrap_or(true) {
            errors.push(format!("bad entry array object at {o}"));
            break;
        }
        let next = u64_at(d, o + 16)?;
        let isz = if header.compact { 4 } else { 8 };
        let n = (size - 24) / isz;
        for k in 0..n {
            let v = if header.compact { u32_at(d, o + 24 + k * 4)? as u64 } else { u64_at(d, o + 24 + k * 8)? };
            if v == 0 {
                break;
            }
            offsets.push(v);
            if offsets.len() >= want {
                break;
            }
        }
        arr = next;
    }
    let mut entries = Vec::with_capacity(offsets.len());
    for off in offsets {
        match parse_entry(d, off as usize, header.compact) {
            Ok(e) => entries.push(e),
            Err(e) => errors.push(format!("entry at {off}: {e}")),
        }
    }
    Ok(Journal { header, entries, errors })
}

fn parse_entry(d: &[u8], o: usize, compact: bool) -> Result<Entry> {
    let typ = u8_at(d, o)?;
    let size = u64_at(d, o + 8)? as usize;
    if typ != OBJ_ENTRY || size < 64 {
        return Err(ParseError::Invalid { offset: o, reason: format!("not an entry object (type {typ}, size {size})") });
    }
    let obj = need(d, o, size)?;
    let mut e = Entry {
        offset: o as u64,
        seqnum: u64_at(obj, 16)?,
        realtime_us: u64_at(obj, 24)?,
        monotonic_us: u64_at(obj, 32)?,
        boot_id: id_hex(need(obj, 40, 16)?),
        fields: BTreeMap::new(),
        unsupported: Vec::new(),
    };
    let isz = if compact { 4 } else { 16 };
    let n = (size - 64) / isz;
    for k in 0..n {
        let doff = if compact { u32_at(obj, 64 + k * 4)? as usize } else { u64_at(obj, 64 + k * 16)? as usize };
        match read_data(d, doff, compact) {
            Ok(DataPayload::Bytes(p)) => {
                if let Some(eq) = p.iter().position(|&b| b == b'=') {
                    let k = String::from_utf8_lossy(&p[..eq]).into_owned();
                    let v = String::from_utf8_lossy(&p[eq + 1..]).into_owned();
                    e.fields.entry(k).or_default().push(v);
                }
            }
            Ok(DataPayload::Unsupported(what)) => e.unsupported.push(what),
            Err(err) => e.unsupported.push(format!("data at {doff}: {err}")),
        }
    }
    Ok(e)
}

enum DataPayload {
    Bytes(Vec<u8>),
    Unsupported(String),
}

fn read_data(d: &[u8], o: usize, compact: bool) -> Result<DataPayload> {
    let typ = u8_at(d, o)?;
    let flags = u8_at(d, o + 1)?;
    let size = u64_at(d, o + 8)? as usize;
    let hdr = if compact { 72 } else { 64 };
    if typ != OBJ_DATA || size < hdr {
        return Err(ParseError::Invalid { offset: o, reason: format!("not a data object (type {typ})") });
    }
    let payload = need(d, o + hdr, size - hdr)?;
    if flags & 2 != 0 {
        let usize_ = u64_at(payload, 0)? as usize;
        if usize_ > MAX_FIELD_SIZE {
            return Err(ParseError::Limit(format!("LZ4 field of {usize_} bytes")));
        }
        return Ok(DataPayload::Bytes(lz4_block_decompress(&payload[8..], usize_, MAX_FIELD_SIZE)?));
    }
    if flags & 1 != 0 {
        return Ok(DataPayload::Unsupported(format!("xz-compressed data object at {o}")));
    }
    if flags & 4 != 0 {
        return Ok(DataPayload::Unsupported(format!("zstd-compressed data object at {o}")));
    }
    Ok(DataPayload::Bytes(payload.to_vec()))
}

pub fn events(j: &Journal, sha: &str, path: &str) -> Vec<Event> {
    let mut out = Vec::new();
    for e in &j.entries {
        let body = e.get("MESSAGE").unwrap_or("").to_string();
        let host = e.get("_HOSTNAME").unwrap_or("").to_string();
        let reporter = e.get("SYSLOG_IDENTIFIER").or(e.get("_COMM")).unwrap_or("").to_string();
        let pid = e.get("_PID").or(e.get("SYSLOG_PID")).unwrap_or("").to_string();
        let msg = if pid.is_empty() { format!("{host} [{reporter}] {body}") } else { format!("{host} [{reporter}, pid: {pid}] {body}") };
        let ts = (e.realtime_us as i64).checked_mul(1000);
        let mut ev = Event::new("systemd:journal", desc::WRITTEN, msg)
            .with_time(ts)
            .attr("body", body)
            .attr("hostname", host.clone())
            .attr("reporter", reporter)
            .attr("pid", json!(e.get("_PID")))
            .attr("uid", json!(e.get("_UID")))
            .attr("comm", json!(e.get("_COMM")))
            .attr("exe", json!(e.get("_EXE")))
            .attr("cmdline", json!(e.get("_CMDLINE")))
            .attr("unit", json!(e.get("_SYSTEMD_UNIT")))
            .attr("priority", json!(e.get("PRIORITY")))
            .attr("source_realtime_timestamp", json!(e.get("_SOURCE_REALTIME_TIMESTAMP")))
            .attr("seqnum", e.seqnum)
            .attr("boot_id", e.boot_id.clone());
        if !e.unsupported.is_empty() {
            ev = ev.attr("unsupported_fields", json!(e.unsupported));
        }
        ev.host = if host.is_empty() { None } else { Some(host) };
        ev.source_short = "LOG".into();
        ev.source_long = "systemd journal".into();
        out.push(ev.provenance(sha, path, e.offset as i64, "journald", crate::PARSER_VERSION));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lz4_literal_and_match() {
        // "abcabcabcabc": literals "abc", then match offset 3 length 9
        let src = [0x35, b'a', b'b', b'c', 3, 0, 0x00];
        // token 0x35: 3 literals, match len 5+4=9 ; then final token 0x00 with 0 literals
        let out = lz4_block_decompress(&src, 12, 1024).unwrap();
        assert_eq!(out, b"abcabcabcabc");
        assert!(lz4_block_decompress(&[0x10, b'a', 9, 0], 0, 1024).is_err());
    }
}
