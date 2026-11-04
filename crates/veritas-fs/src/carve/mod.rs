//! Header/footer carving with structural validation: JPEG, PNG, PDF, ZIP/OOXML, GIF, PE, SQLite, EVTX.
//! The source is scanned in fixed-size chunks with an overlap so headers straddling a chunk boundary
//! are found exactly once; each candidate is validated by reading forward from the source.
use crate::error::Result;
use crate::io::{read_vec_padded, ReadAt};
use serde::Serialize;

/// Scan chunk size.
pub const CHUNK_SIZE: u64 = 8 * 1024 * 1024;
/// Overlap between consecutive chunks (longer than any signature).
pub const CHUNK_OVERLAP: u64 = 64;
/// Maximum hits reported.
pub const MAX_HITS: usize = 1_000_000;
/// Per-type maximum carved size.
pub const MAX_JPEG: u64 = 64 << 20;
pub const MAX_PNG: u64 = 64 << 20;
pub const MAX_PDF: u64 = 256 << 20;
pub const MAX_ZIP: u64 = 512 << 20;
pub const MAX_GIF: u64 = 32 << 20;
pub const MAX_PE: u64 = 512 << 20;
pub const MAX_SQLITE: u64 = 4 << 30;
pub const MAX_EVTX: u64 = 1 << 30;
/// Validator read window.
const WINDOW: u64 = 1 << 20;
/// Maximum PNG chunks / JPEG segments / GIF blocks / ZIP entries walked.
const MAX_STRUCT_ITEMS: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct CarveHit {
    pub offset: u64,
    pub size: u64,
    pub file_type: String,
    pub extension: String,
    pub validated: bool,
    pub detail: String,
}

const SIGS: &[(&[u8], &str)] = &[
    (b"\xFF\xD8\xFF", "jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"MZ", "pe"),
    (b"SQLite format 3\0", "sqlite"),
    (b"ElfFile\0", "evtx"),
];

/// Streaming reader over a source with a moving window.
struct Cursor<'a> {
    src: &'a dyn ReadAt,
    base: u64,
    buf: Vec<u8>,
}

impl<'a> Cursor<'a> {
    fn new(src: &'a dyn ReadAt) -> Self { Self { src, base: 0, buf: Vec::new() } }
    /// Byte at absolute offset, `None` past the end of the source.
    fn byte(&mut self, off: u64) -> Option<u8> {
        if off < self.base || off >= self.base + self.buf.len() as u64 {
            if off >= self.src.size() {
                return None;
            }
            self.base = off;
            self.buf = read_vec_padded(self.src, off, WINDOW.min(self.src.size() - off)).ok()?;
        }
        self.buf.get((off - self.base) as usize).copied()
    }
    fn bytes(&mut self, off: u64, n: usize) -> Option<Vec<u8>> {
        let mut v = Vec::with_capacity(n);
        for i in 0..n as u64 {
            v.push(self.byte(off + i)?);
        }
        Some(v)
    }
    fn u16be(&mut self, off: u64) -> Option<u16> { let b = self.bytes(off, 2)?; Some(u16::from_be_bytes([b[0], b[1]])) }
    fn u32be(&mut self, off: u64) -> Option<u32> { let b = self.bytes(off, 4)?; Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]])) }
    fn u16le(&mut self, off: u64) -> Option<u16> { let b = self.bytes(off, 2)?; Some(u16::from_le_bytes([b[0], b[1]])) }
    fn u32le(&mut self, off: u64) -> Option<u32> { let b = self.bytes(off, 4)?; Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]])) }
    /// Find `pat` in `[from, from+limit)`.
    fn find(&mut self, pat: &[u8], from: u64, limit: u64) -> Option<u64> {
        let end = from.saturating_add(limit).min(self.src.size());
        let mut pos = from;
        while pos + pat.len() as u64 <= end {
            let chunk_len = (4 * WINDOW).min(end - pos);
            let d = read_vec_padded(self.src, pos, chunk_len).ok()?;
            if let Some(i) = d.windows(pat.len()).position(|w| w == pat) {
                return Some(pos + i as u64);
            }
            if chunk_len <= pat.len() as u64 {
                break;
            }
            pos += chunk_len - pat.len() as u64 + 1;
        }
        None
    }
}

type V = Option<(u64, bool, String)>;

fn v_jpeg(c: &mut Cursor, o: u64) -> V {
    let mut p = o + 2;
    let mut sos = false;
    for _ in 0..MAX_STRUCT_ITEMS {
        if p - o > MAX_JPEG {
            return None;
        }
        if c.byte(p)? != 0xFF {
            return None;
        }
        let m = c.byte(p + 1)?;
        match m {
            // A bare SOI/EOI pair without scan data is not an image.
            0xD9 if !sos => return None,
            0xD9 => return Some((p + 2 - o, true, "EOI".into())),
            0xFF => p += 1,
            0x01 | 0xD0..=0xD7 => p += 2,
            0xDA => {
                let len = c.u16be(p + 2)? as u64;
                p += 2 + len;
                sos = true;
                // Entropy-coded data until a marker other than stuffing / RST.
                loop {
                    if p - o > MAX_JPEG {
                        return None;
                    }
                    if c.byte(p)? == 0xFF {
                        let n = c.byte(p + 1)?;
                        if n != 0x00 && !(0xD0..=0xD7).contains(&n) {
                            break;
                        }
                        p += 2;
                    } else {
                        p += 1;
                    }
                }
            }
            _ => {
                let len = c.u16be(p + 2)? as u64;
                if len < 2 {
                    return None;
                }
                p += 2 + len;
            }
        }
    }
    None
}

fn v_png(c: &mut Cursor, o: u64) -> V {
    let mut p = o + 8;
    let mut first = true;
    for _ in 0..MAX_STRUCT_ITEMS {
        let len = c.u32be(p)? as u64;
        if len > MAX_PNG {
            return None;
        }
        let typ = c.bytes(p + 4, 4)?;
        if first && typ != b"IHDR" {
            return None;
        }
        first = false;
        let data = if len <= 64 << 20 { read_vec_padded(c.src, p + 4, 4 + len).ok()? } else { return None };
        let crc = c.u32be(p + 8 + len)?;
        if crate::volume::gpt::crc32(&data) != crc {
            return Some((p + 12 + len - o, false, format!("CRC mismatch in {} chunk", String::from_utf8_lossy(&typ))));
        }
        p += 12 + len;
        if typ == b"IEND" {
            return Some((p - o, true, "IEND".into()));
        }
        if p - o > MAX_PNG {
            return None;
        }
    }
    None
}

fn v_pdf(c: &mut Cursor, o: u64) -> V {
    let mut last = None;
    let mut from = o + 5;
    for _ in 0..1024 {
        let Some(e) = c.find(b"%%EOF", from, MAX_PDF.saturating_sub(from - o)) else { break };
        let next_hdr = c.find(b"%PDF-", from, e - from);
        if next_hdr.is_some() {
            break;
        }
        last = Some(e);
        from = e + 5;
        // Incremental updates append another body; stop when no further %%EOF follows closely.
        if c.find(b"%%EOF", from, 1 << 20).is_none() {
            break;
        }
    }
    let e = last?;
    let mut end = e + 5;
    for _ in 0..2 {
        if matches!(c.byte(end), Some(b'\r') | Some(b'\n')) {
            end += 1;
        }
    }
    Some((end - o, true, "%%EOF".into()))
}

fn v_zip(c: &mut Cursor, o: u64) -> V {
    let eocd = c.find(b"PK\x05\x06", o + 4, MAX_ZIP)?;
    let cd_size = c.u32le(eocd + 12)? as u64;
    let cd_off = c.u32le(eocd + 16)? as u64;
    let comment = c.u16le(eocd + 20)? as u64;
    let size = eocd + 22 + comment - o;
    let ok = cd_off + cd_size == eocd - o && c.bytes(o + cd_off, 4)? == b"PK\x01\x02";
    // Classify OOXML by central-directory names.
    let mut kind = "zip".to_string();
    if ok {
        let cd = read_vec_padded(c.src, o + cd_off, cd_size.min(16 << 20)).ok()?;
        let s = String::from_utf8_lossy(&cd);
        if s.contains("[Content_Types].xml") {
            kind = if s.contains("word/") { "docx" } else if s.contains("xl/") { "xlsx" } else if s.contains("ppt/") { "pptx" } else { "ooxml" }.into();
        }
    }
    Some((size, ok, kind))
}

fn v_gif(c: &mut Cursor, o: u64) -> V {
    let flags = c.byte(o + 10)?;
    let mut p = o + 13;
    if flags & 0x80 != 0 {
        p += 3 * (1u64 << ((flags & 7) + 1));
    }
    let skip_sub = |c: &mut Cursor, mut p: u64| -> Option<u64> {
        for _ in 0..MAX_STRUCT_ITEMS {
            let n = c.byte(p)? as u64;
            p += 1 + n;
            if n == 0 {
                return Some(p);
            }
        }
        None
    };
    for _ in 0..MAX_STRUCT_ITEMS {
        if p - o > MAX_GIF {
            return None;
        }
        match c.byte(p)? {
            0x3B => return Some((p + 1 - o, true, "trailer".into())),
            0x21 => p = skip_sub(c, p + 2)?,
            0x2C => {
                let f = c.byte(p + 9)?;
                p += 10;
                if f & 0x80 != 0 {
                    p += 3 * (1u64 << ((f & 7) + 1));
                }
                p = skip_sub(c, p + 1)?;
            }
            _ => return None,
        }
    }
    None
}

fn v_pe(c: &mut Cursor, o: u64) -> V {
    let lfanew = c.u32le(o + 0x3C)? as u64;
    if !(0x40..=0x1000).contains(&lfanew) || c.bytes(o + lfanew, 4)? != b"PE\0\0" {
        return None;
    }
    let coff = o + lfanew + 4;
    let nsec = c.u16le(coff + 2)? as u64;
    let opt = c.u16le(coff + 16)? as u64;
    if nsec == 0 || nsec > 96 {
        return None;
    }
    let size_of_headers = c.u32le(coff + 20 + 60).unwrap_or(0) as u64;
    let mut end = size_of_headers;
    let st = coff + 20 + opt;
    for i in 0..nsec {
        let s = st + i * 40;
        let raw_size = c.u32le(s + 16)? as u64;
        let raw_ptr = c.u32le(s + 20)? as u64;
        end = end.max(raw_ptr.saturating_add(raw_size));
    }
    if end == 0 || end > MAX_PE {
        return None;
    }
    Some((end, true, format!("{nsec} sections")))
}

fn v_sqlite(c: &mut Cursor, o: u64) -> V {
    let ps = c.u16be(o + 16)? as u64;
    let ps = if ps == 1 { 65536 } else { ps };
    if !(512..=65536).contains(&ps) || !ps.is_power_of_two() {
        return None;
    }
    let change = c.u32be(o + 24)?;
    let count = c.u32be(o + 28)? as u64;
    let valid_for = c.u32be(o + 92)?;
    if count != 0 && change == valid_for {
        let size = ps.checked_mul(count)?;
        if size > MAX_SQLITE {
            return None;
        }
        return Some((size, true, format!("page_size {ps} pages {count}")));
    }
    // Legacy (pre-3.7.0) header without a valid in-header page count: estimate the size from
    // consecutive pages whose first byte is a b-tree page type or a page-number high byte.
    let mut pages = 1u64;
    while ps * (pages + 1) <= MAX_SQLITE {
        match c.byte(o + ps * pages) {
            Some(0x00 | 0x02 | 0x05 | 0x0A | 0x0D) => pages += 1,
            _ => break,
        }
    }
    Some((ps * pages, false, format!("legacy header; size estimated from {pages} pages of {ps}")))
}

fn v_evtx(c: &mut Cursor, o: u64) -> V {
    let hdr = c.bytes(o, 128)?;
    let header_chunks = u16::from_le_bytes([hdr[42], hdr[43]]) as u64;
    let crc = u32::from_le_bytes([hdr[124], hdr[125], hdr[126], hdr[127]]);
    // The header chunk count can lag behind the chunks present; count ElfChnk signatures instead.
    let mut chunks = 0u64;
    while 4096 + (chunks + 1) * 65536 <= MAX_EVTX && c.bytes(o + 4096 + chunks * 65536, 8).as_deref() == Some(&b"ElfChnk\0"[..]) {
        chunks += 1;
    }
    let size = 4096 + chunks * 65536;
    let ok = crate::volume::gpt::crc32(&hdr[..120]) == crc && chunks >= header_chunks;
    Some((size, ok, format!("{chunks} chunks (header: {header_chunks})")))
}

fn validate(c: &mut Cursor, kind: &str, o: u64) -> V {
    match kind {
        "jpeg" => v_jpeg(c, o),
        "png" => v_png(c, o),
        "pdf" => v_pdf(c, o),
        "zip" => v_zip(c, o),
        "gif" => v_gif(c, o),
        "pe" => v_pe(c, o),
        "sqlite" => v_sqlite(c, o),
        "evtx" => v_evtx(c, o),
        _ => None,
    }
}

fn extension(kind: &str, detail: &str) -> String {
    match kind {
        "jpeg" => "jpg".into(),
        "zip" if detail != "zip" => detail.into(),
        "pe" => "exe".into(),
        "sqlite" => "sqlite".into(),
        k => k.into(),
    }
}

/// Carve the whole source. Validated hits advance the scan past their end; unvalidated hits do not.
pub fn carve(src: &dyn ReadAt) -> Result<Vec<CarveHit>> {
    let mut hits = Vec::new();
    let mut c = Cursor::new(src);
    let size = src.size();
    let mut skip_until = 0u64;
    let mut start = 0u64;
    while start < size && hits.len() < MAX_HITS {
        let len = (CHUNK_SIZE + CHUNK_OVERLAP).min(size - start);
        let buf = read_vec_padded(src, start, len)?;
        let limit = CHUNK_SIZE.min(len) as usize; // only report headers that start before the overlap
        let mut i = 0usize;
        while i < limit {
            let abs = start + i as u64;
            if abs < skip_until {
                i = (skip_until - start).min(limit as u64) as usize;
                continue;
            }
            if !matches!(buf[i], 0xFF | 0x89 | b'%' | b'P' | b'G' | b'M' | b'S' | b'E') {
                i += 1;
                continue;
            }
            for (sig, kind) in SIGS {
                if buf[i..].starts_with(sig) {
                    if let Some((sz, ok, detail)) = validate(&mut c, kind, abs) {
                        let file_type = if *kind == "zip" { detail.clone() } else { kind.to_string() };
                        hits.push(CarveHit { offset: abs, size: sz, extension: extension(kind, &detail), file_type, validated: ok, detail });
                        if ok {
                            skip_until = abs + sz.max(1);
                        }
                    }
                    break;
                }
            }
            i += 1;
        }
        start += CHUNK_SIZE;
    }
    hits.sort();
    Ok(hits)
}

/// Read the bytes of a hit (capped by the per-type maximum used during validation).
pub fn extract(src: &dyn ReadAt, hit: &CarveHit) -> Result<Vec<u8>> {
    read_vec_padded(src, hit.offset, hit.size.min(src.size().saturating_sub(hit.offset)))
}
