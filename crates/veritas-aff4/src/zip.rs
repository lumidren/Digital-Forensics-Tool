//! Minimal, bounds-checked ZIP64 support for AFF4 volumes.
//!
//! Reading: the end of central directory record is located from the end of the file, ZIP64
//! records are followed when the classic fields are saturated, and a "global offset" is derived
//! (as pyaff4 does) so archives that were appended to another file still resolve. Central
//! directory size and entry count are capped. Member data is read as stored (method 0) slices or
//! inflated (method 8) into a size-capped buffer.
//!
//! Writing: every local header carries a ZIP64 extra field (so streamed bevies can exceed 4 GiB
//! and be patched in place once their size and CRC are known); the central directory carries a
//! ZIP64 extra only where a value does not fit 32 bits; the archive always ends with a ZIP64 end
//! of central directory record, its locator and a classic record whose comment is the volume URN.

use crate::{Aff4Error, Result};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};

/// Anything the reader can pull bytes from.
pub trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

/// Largest central directory accepted (bytes).
pub const MAX_CENTRAL_DIRECTORY: u64 = 256 * 1024 * 1024;
/// Largest number of archive members accepted.
pub const MAX_ENTRIES: u64 = 1 << 20;

const SIG_LOCAL: &[u8; 4] = b"PK\x03\x04";
const SIG_CENTRAL: &[u8; 4] = b"PK\x01\x02";
const SIG_EOCD: &[u8; 4] = b"PK\x05\x06";
const SIG_EOCD64: &[u8; 4] = b"PK\x06\x06";
const SIG_LOCATOR: &[u8; 4] = b"PK\x06\x07";
const EOCD_SIZE: usize = 22;
const EOCD64_SIZE: u64 = 56;
const LOCATOR_SIZE: u64 = 20;
const CENTRAL_SIZE: usize = 46;
const LOCAL_SIZE: usize = 30;
const FLAG_UTF8: u16 = 1 << 11;
const VERSION_ZIP64: u16 = 45;

pub const METHOD_STORED: u16 = 0;
pub const METHOD_DEFLATE: u16 = 8;

/// One central directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    pub name: String,
    pub method: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub size: u64,
    /// Offset of the local header in archive coordinates (before the global offset).
    pub local_header_offset: u64,
}

fn u16_at(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(Aff4Error::Truncated("zip record"))
}
fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(Aff4Error::Truncated("zip record"))
}
fn u64_at(b: &[u8], o: usize) -> Result<u64> {
    b.get(o..o + 8)
        .map(|s| {
            let mut a = [0u8; 8];
            a.copy_from_slice(s);
            u64::from_le_bytes(a)
        })
        .ok_or(Aff4Error::Truncated("zip record"))
}

fn read_exact_at(src: &mut dyn ReadSeek, len_total: u64, off: u64, len: u64) -> Result<Vec<u8>> {
    let end = off
        .checked_add(len)
        .ok_or_else(|| Aff4Error::Zip("offset overflow".into()))?;
    if end > len_total {
        return Err(Aff4Error::Truncated("zip data"));
    }
    let len = usize::try_from(len).map_err(|_| Aff4Error::Limit("read too large".into()))?;
    let mut buf = vec![0u8; len];
    src.seek(SeekFrom::Start(off))?;
    src.read_exact(&mut buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Aff4Error::Truncated("zip data")
        } else {
            Aff4Error::Io(e)
        }
    })?;
    Ok(buf)
}

/// A ZIP archive opened for reading.
pub struct ZipArchive {
    src: Box<dyn ReadSeek>,
    len: u64,
    global_offset: i128,
    entries: Vec<ZipEntry>,
    data_starts: Vec<Option<u64>>,
    by_name: HashMap<String, usize>,
    comment: Vec<u8>,
}

impl std::fmt::Debug for ZipArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZipArchive")
            .field("len", &self.len)
            .field("global_offset", &self.global_offset)
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl ZipArchive {
    pub fn new(mut src: Box<dyn ReadSeek>) -> Result<Self> {
        let len = src.seek(SeekFrom::End(0))?;
        if len < EOCD_SIZE as u64 {
            return Err(Aff4Error::NotAff4(
                "file too small for a ZIP archive".into(),
            ));
        }
        let tail_len = len.min(EOCD_SIZE as u64 + 65535);
        let tail_start = len - tail_len;
        let tail = read_exact_at(src.as_mut(), len, tail_start, tail_len)?;
        // Last EOCD signature whose comment fits inside the file.
        let mut eocd_at = None;
        let mut i = tail.len().saturating_sub(EOCD_SIZE);
        loop {
            if &tail[i..i + 4] == SIG_EOCD {
                let clen = u16_at(&tail, i + 20)? as usize;
                if i + EOCD_SIZE + clen <= tail.len() {
                    eocd_at = Some(i);
                    break;
                }
            }
            if i == 0 {
                break;
            }
            i -= 1;
        }
        let i = eocd_at
            .ok_or_else(|| Aff4Error::NotAff4("no ZIP end of central directory record".into()))?;
        let eocd = &tail[i..];
        let eocd_pos = tail_start + i as u64;
        let disk = u16_at(eocd, 4)?;
        let cd_disk = u16_at(eocd, 6)?;
        let mut entries_total = u16_at(eocd, 10)? as u64;
        let mut cd_size = u32_at(eocd, 12)? as u64;
        let mut cd_offset = u32_at(eocd, 16)? as u64;
        let clen = u16_at(eocd, 20)? as usize;
        let comment = eocd[EOCD_SIZE..EOCD_SIZE + clen].to_vec();
        let mut directory_end = eocd_pos;
        let zip64 = entries_total == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF;
        if zip64 {
            if eocd_pos < LOCATOR_SIZE {
                return Err(Aff4Error::Zip("ZIP64 locator missing".into()));
            }
            let loc_pos = eocd_pos - LOCATOR_SIZE;
            let loc = read_exact_at(src.as_mut(), len, loc_pos, LOCATOR_SIZE)?;
            if &loc[..4] != SIG_LOCATOR {
                return Err(Aff4Error::Zip("ZIP64 locator signature invalid".into()));
            }
            if u32_at(&loc, 4)? != 0 || u32_at(&loc, 16)? > 1 {
                return Err(Aff4Error::Unsupported("multi-disk ZIP archives".into()));
            }
            let claimed = u64_at(&loc, 8)?;
            // The record normally sits right before the locator; fall back to the claimed offset.
            let mut rec = None;
            for cand in [loc_pos.checked_sub(EOCD64_SIZE), Some(claimed)]
                .into_iter()
                .flatten()
            {
                if cand.checked_add(EOCD64_SIZE).map(|e| e <= len) != Some(true) {
                    continue;
                }
                let r = read_exact_at(src.as_mut(), len, cand, EOCD64_SIZE)?;
                if &r[..4] == SIG_EOCD64 {
                    rec = Some((cand, r));
                    break;
                }
            }
            let (pos64, r) =
                rec.ok_or_else(|| Aff4Error::Zip("ZIP64 end of central directory missing".into()))?;
            if u32_at(&r, 16)? != 0 || u32_at(&r, 20)? != 0 {
                return Err(Aff4Error::Unsupported("multi-disk ZIP archives".into()));
            }
            entries_total = u64_at(&r, 32)?;
            cd_size = u64_at(&r, 40)?;
            cd_offset = u64_at(&r, 48)?;
            directory_end = pos64;
        } else if disk != 0 || cd_disk != 0 {
            return Err(Aff4Error::Unsupported("multi-disk ZIP archives".into()));
        }
        if entries_total > MAX_ENTRIES {
            return Err(Aff4Error::Limit(format!(
                "{} archive members (limit {})",
                entries_total, MAX_ENTRIES
            )));
        }
        if cd_size > MAX_CENTRAL_DIRECTORY {
            return Err(Aff4Error::Limit(format!(
                "central directory of {} bytes",
                cd_size
            )));
        }
        let cd_real = directory_end
            .checked_sub(cd_size)
            .ok_or_else(|| Aff4Error::Zip("central directory larger than the archive".into()))?;
        let global_offset = cd_real as i128 - cd_offset as i128;
        let cd = read_exact_at(src.as_mut(), len, cd_real, cd_size)?;
        let mut entries = Vec::with_capacity(entries_total.min(65536) as usize);
        let mut off = 0usize;
        for _ in 0..entries_total {
            let rec = cd
                .get(off..off + CENTRAL_SIZE)
                .ok_or(Aff4Error::Truncated("central directory entry"))?;
            if &rec[..4] != SIG_CENTRAL {
                return Err(Aff4Error::Zip(format!(
                    "central directory entry signature invalid at {}",
                    off
                )));
            }
            let flags = u16_at(rec, 8)?;
            let method = u16_at(rec, 10)?;
            let crc32 = u32_at(rec, 16)?;
            let mut csize = u32_at(rec, 20)? as u64;
            let mut usize_ = u32_at(rec, 24)? as u64;
            let nlen = u16_at(rec, 28)? as usize;
            let xlen = u16_at(rec, 30)? as usize;
            let clen = u16_at(rec, 32)? as usize;
            let disk_start = u16_at(rec, 34)?;
            let mut lho = u32_at(rec, 42)? as u64;
            let name_start = off + CENTRAL_SIZE;
            let name = cd
                .get(name_start..name_start + nlen)
                .ok_or(Aff4Error::Truncated("central directory name"))?;
            let extra = cd
                .get(name_start + nlen..name_start + nlen + xlen)
                .ok_or(Aff4Error::Truncated("central directory extra field"))?;
            let name = if flags & FLAG_UTF8 != 0 {
                String::from_utf8_lossy(name).into_owned()
            } else {
                // CP437 names are only ever ASCII in AFF4 volumes.
                String::from_utf8_lossy(name).into_owned()
            };
            // ZIP64 extended information. pyaff4 records a data size 4 bytes too large, so the
            // fields are taken from whatever follows the header, up to the end of the extra area.
            let mut x = 0usize;
            while x + 4 <= extra.len() {
                let id = u16_at(extra, x)?;
                let dsize = u16_at(extra, x + 2)? as usize;
                if id == 1 {
                    let mut p = x + 4;
                    let mut take = |v: &mut u64| -> Result<()> {
                        *v = u64_at(extra, p)
                            .map_err(|_| Aff4Error::Zip("ZIP64 extra field too short".into()))?;
                        p += 8;
                        Ok(())
                    };
                    if usize_ == 0xFFFF_FFFF {
                        take(&mut usize_)?;
                    }
                    if csize == 0xFFFF_FFFF {
                        take(&mut csize)?;
                    }
                    if lho == 0xFFFF_FFFF {
                        take(&mut lho)?;
                    }
                    let _ = disk_start;
                    break;
                }
                x = x.saturating_add(4 + dsize);
            }
            entries.push(ZipEntry {
                name,
                method,
                crc32,
                compressed_size: csize,
                size: usize_,
                local_header_offset: lho,
            });
            off = name_start + nlen + xlen + clen;
        }
        let mut by_name = HashMap::with_capacity(entries.len());
        for (i, e) in entries.iter().enumerate() {
            // A later duplicate replaces an earlier one (append semantics).
            by_name.insert(e.name.clone(), i);
        }
        let data_starts = vec![None; entries.len()];
        Ok(Self {
            src,
            len,
            global_offset,
            entries,
            data_starts,
            by_name,
            comment,
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }
    pub fn comment(&self) -> &[u8] {
        &self.comment
    }
    pub fn find(&self, name: &str) -> Option<usize> {
        self.by_name.get(name).copied()
    }
    pub fn entry(&self, idx: usize) -> Result<&ZipEntry> {
        self.entries
            .get(idx)
            .ok_or_else(|| Aff4Error::InvalidInput(format!("zip member {} out of range", idx)))
    }

    fn real(&self, archive_offset: u64) -> Result<u64> {
        let r = archive_offset as i128 + self.global_offset;
        if r < 0 || r > self.len as i128 {
            return Err(Aff4Error::Zip(format!(
                "offset {} lies outside the archive",
                archive_offset
            )));
        }
        Ok(r as u64)
    }

    /// File offset of member `idx`'s data, validated against its local header.
    pub fn data_start(&mut self, idx: usize) -> Result<u64> {
        if let Some(Some(s)) = self.data_starts.get(idx) {
            return Ok(*s);
        }
        let e = self.entry(idx)?.clone();
        let lh = self.real(e.local_header_offset)?;
        let hdr = read_exact_at(self.src.as_mut(), self.len, lh, LOCAL_SIZE as u64)?;
        if &hdr[..4] != SIG_LOCAL {
            return Err(Aff4Error::Zip(format!(
                "local header of {} has a bad signature",
                e.name
            )));
        }
        let nlen = u16_at(&hdr, 26)? as u64;
        let xlen = u16_at(&hdr, 28)? as u64;
        let name = read_exact_at(self.src.as_mut(), self.len, lh + LOCAL_SIZE as u64, nlen)?;
        if String::from_utf8_lossy(&name) != e.name {
            return Err(Aff4Error::Zip(format!(
                "local header name differs from central directory for {}",
                e.name
            )));
        }
        let start = lh + LOCAL_SIZE as u64 + nlen + xlen;
        let end = start
            .checked_add(e.compressed_size)
            .ok_or_else(|| Aff4Error::Zip("member size overflow".into()))?;
        if end > self.len {
            return Err(Aff4Error::Truncated("zip member data"));
        }
        if let Some(slot) = self.data_starts.get_mut(idx) {
            *slot = Some(start);
        }
        Ok(start)
    }

    /// Whole member, decompressed, at most `cap` bytes. The CRC-32 is checked (a stored CRC of 0
    /// is accepted without a check, as some writers leave it unset).
    pub fn read_member(&mut self, idx: usize, cap: u64) -> Result<Vec<u8>> {
        let e = self.entry(idx)?.clone();
        if e.size > cap {
            return Err(Aff4Error::Limit(format!(
                "member {} is {} bytes (limit {})",
                e.name, e.size, cap
            )));
        }
        let start = self.data_start(idx)?;
        let data = match e.method {
            METHOD_STORED => {
                if e.compressed_size != e.size {
                    return Err(Aff4Error::Zip(format!(
                        "stored member {} has differing sizes",
                        e.name
                    )));
                }
                read_exact_at(self.src.as_mut(), self.len, start, e.size)?
            }
            METHOD_DEFLATE => {
                if e.compressed_size > cap.saturating_mul(2).saturating_add(1024) {
                    return Err(Aff4Error::Limit(format!(
                        "compressed member {} is too large",
                        e.name
                    )));
                }
                let raw = read_exact_at(self.src.as_mut(), self.len, start, e.compressed_size)?;
                let out = crate::compress::inflate_raw(&raw, e.size as usize)?;
                if out.len() as u64 != e.size {
                    return Err(Aff4Error::Corrupt(format!(
                        "member {} inflates to {} bytes, expected {}",
                        e.name,
                        out.len(),
                        e.size
                    )));
                }
                out
            }
            m => {
                return Err(Aff4Error::Unsupported(format!(
                    "ZIP compression method {} for {}",
                    m, e.name
                )))
            }
        };
        if e.crc32 != 0 && crc32fast::hash(&data) != e.crc32 {
            return Err(Aff4Error::Corrupt(format!("CRC-32 mismatch in {}", e.name)));
        }
        Ok(data)
    }

    /// Read `buf.len()` bytes at `offset` inside stored member `idx`.
    pub fn read_stored_at(&mut self, idx: usize, offset: u64, buf: &mut [u8]) -> Result<()> {
        let e = self.entry(idx)?.clone();
        if e.method != METHOD_STORED {
            return Err(Aff4Error::Unsupported(format!(
                "random access into compressed member {}",
                e.name
            )));
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| Aff4Error::Corrupt("member offset overflow".into()))?;
        if end > e.size || e.size != e.compressed_size {
            return Err(Aff4Error::Corrupt(format!(
                "read [{}, {}) outside member {} of {} bytes",
                offset, end, e.name, e.size
            )));
        }
        let start = self.data_start(idx)?;
        self.src.seek(SeekFrom::Start(start + offset))?;
        self.src.read_exact(buf).map_err(|err| {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                Aff4Error::Truncated("zip member data")
            } else {
                Aff4Error::Io(err)
            }
        })?;
        Ok(())
    }

    /// Check member `idx`'s CRC-32 (stored members are streamed in 1 MiB pieces).
    pub fn crc_ok(&mut self, idx: usize) -> Result<bool> {
        let e = self.entry(idx)?.clone();
        if e.crc32 == 0 {
            return Ok(true);
        }
        if e.method != METHOD_STORED {
            return Ok(crc32fast::hash(&self.read_member(idx, 1 << 30)?) == e.crc32);
        }
        let mut h = crc32fast::Hasher::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut done = 0u64;
        while done < e.size {
            let n = (e.size - done).min(buf.len() as u64) as usize;
            self.read_stored_at(idx, done, &mut buf[..n])?;
            h.update(&buf[..n]);
            done += n as u64;
        }
        Ok(h.finalize() == e.crc32)
    }
}

/// MS-DOS date and time for ZIP headers.
pub fn dos_datetime(t: &chrono::DateTime<chrono::Utc>) -> (u16, u16) {
    use chrono::{Datelike, Timelike};
    let year = t.year().clamp(1980, 2107) as u16;
    let date = ((year - 1980) << 9) | ((t.month() as u16) << 5) | t.day() as u16;
    let time = ((t.hour() as u16) << 11) | ((t.minute() as u16) << 5) | (t.second() as u16 / 2);
    (time, date)
}

struct OpenEntry {
    name: String,
    lho: u64,
    crc: crc32fast::Hasher,
    size: u64,
}

/// Streaming ZIP64 writer (stored members only; AFF4 compresses inside the image stream).
pub struct ZipWriter<W: Write + Seek> {
    w: W,
    pos: u64,
    time: u16,
    date: u16,
    entries: Vec<ZipEntry>,
    open: Option<OpenEntry>,
}

impl<W: Write + Seek> ZipWriter<W> {
    pub fn new(w: W, dos: (u16, u16)) -> Self {
        Self {
            w,
            pos: 0,
            time: dos.0,
            date: dos.1,
            entries: Vec::new(),
            open: None,
        }
    }

    pub fn position(&self) -> u64 {
        self.pos
    }

    fn local_header(&self, name: &str, crc: u32, size: u64) -> Vec<u8> {
        let n = name.as_bytes();
        let mut h = Vec::with_capacity(LOCAL_SIZE + n.len() + 20);
        h.extend_from_slice(SIG_LOCAL);
        h.extend_from_slice(&VERSION_ZIP64.to_le_bytes());
        h.extend_from_slice(&FLAG_UTF8.to_le_bytes());
        h.extend_from_slice(&METHOD_STORED.to_le_bytes());
        h.extend_from_slice(&self.time.to_le_bytes());
        h.extend_from_slice(&self.date.to_le_bytes());
        h.extend_from_slice(&crc.to_le_bytes());
        h.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        h.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        h.extend_from_slice(&(n.len() as u16).to_le_bytes());
        h.extend_from_slice(&20u16.to_le_bytes());
        h.extend_from_slice(n);
        h.extend_from_slice(&1u16.to_le_bytes());
        h.extend_from_slice(&16u16.to_le_bytes());
        h.extend_from_slice(&size.to_le_bytes());
        h.extend_from_slice(&size.to_le_bytes());
        h
    }

    fn check_name(name: &str) -> Result<()> {
        if name.is_empty() || name.len() > 0xFFFF {
            return Err(Aff4Error::InvalidInput(format!(
                "bad member name {:?}",
                name
            )));
        }
        Ok(())
    }

    /// Add a complete stored member.
    pub fn add_stored(&mut self, name: &str, data: &[u8]) -> Result<()> {
        if self.open.is_some() {
            return Err(Aff4Error::InvalidInput("a streamed member is open".into()));
        }
        Self::check_name(name)?;
        let crc = crc32fast::hash(data);
        let h = self.local_header(name, crc, data.len() as u64);
        let lho = self.pos;
        self.w.write_all(&h)?;
        self.w.write_all(data)?;
        self.pos += h.len() as u64 + data.len() as u64;
        self.entries.push(ZipEntry {
            name: name.to_string(),
            method: METHOD_STORED,
            crc32: crc,
            compressed_size: data.len() as u64,
            size: data.len() as u64,
            local_header_offset: lho,
        });
        Ok(())
    }

    /// Start a stored member whose size is not yet known.
    pub fn begin(&mut self, name: &str) -> Result<()> {
        if self.open.is_some() {
            return Err(Aff4Error::InvalidInput("a streamed member is open".into()));
        }
        Self::check_name(name)?;
        let h = self.local_header(name, 0, 0);
        let lho = self.pos;
        self.w.write_all(&h)?;
        self.pos += h.len() as u64;
        self.open = Some(OpenEntry {
            name: name.to_string(),
            lho,
            crc: crc32fast::Hasher::new(),
            size: 0,
        });
        Ok(())
    }

    pub fn is_open(&self) -> bool {
        self.open.is_some()
    }

    /// Size of the open member so far.
    pub fn open_size(&self) -> u64 {
        self.open.as_ref().map(|o| o.size).unwrap_or(0)
    }

    pub fn write_open(&mut self, data: &[u8]) -> Result<()> {
        let o = self
            .open
            .as_mut()
            .ok_or_else(|| Aff4Error::InvalidInput("no streamed member is open".into()))?;
        self.w.write_all(data)?;
        o.crc.update(data);
        o.size += data.len() as u64;
        self.pos += data.len() as u64;
        Ok(())
    }

    /// Close the open member, rewriting its local header with the final CRC and size.
    pub fn end(&mut self) -> Result<()> {
        let o = self
            .open
            .take()
            .ok_or_else(|| Aff4Error::InvalidInput("no streamed member is open".into()))?;
        let crc = o.crc.finalize();
        let h = self.local_header(&o.name, crc, o.size);
        self.w.seek(SeekFrom::Start(o.lho))?;
        self.w.write_all(&h)?;
        self.w.seek(SeekFrom::Start(self.pos))?;
        self.entries.push(ZipEntry {
            name: o.name,
            method: METHOD_STORED,
            crc32: crc,
            compressed_size: o.size,
            size: o.size,
            local_header_offset: o.lho,
        });
        Ok(())
    }

    /// Write the central directory and end records; returns the inner writer.
    pub fn finish(mut self, comment: &[u8]) -> Result<W> {
        if self.open.is_some() {
            self.end()?;
        }
        if comment.len() > 0xFFFF {
            return Err(Aff4Error::InvalidInput("archive comment too long".into()));
        }
        let cd_offset = self.pos;
        let mut cd = Vec::new();
        for e in &self.entries {
            let n = e.name.as_bytes();
            let mut extra = Vec::new();
            let fits = |v: u64| v < 0xFFFF_FFFF;
            let usize_f = if fits(e.size) {
                e.size as u32
            } else {
                extra.extend_from_slice(&e.size.to_le_bytes());
                0xFFFF_FFFF
            };
            let csize_f = if fits(e.compressed_size) {
                e.compressed_size as u32
            } else {
                extra.extend_from_slice(&e.compressed_size.to_le_bytes());
                0xFFFF_FFFF
            };
            let lho_f = if fits(e.local_header_offset) {
                e.local_header_offset as u32
            } else {
                extra.extend_from_slice(&e.local_header_offset.to_le_bytes());
                0xFFFF_FFFF
            };
            let mut x = Vec::new();
            if !extra.is_empty() {
                x.extend_from_slice(&1u16.to_le_bytes());
                x.extend_from_slice(&(extra.len() as u16).to_le_bytes());
                x.extend_from_slice(&extra);
            }
            cd.extend_from_slice(SIG_CENTRAL);
            cd.extend_from_slice(&VERSION_ZIP64.to_le_bytes()); // made by: MS-DOS, 4.5
            cd.extend_from_slice(&VERSION_ZIP64.to_le_bytes());
            cd.extend_from_slice(&FLAG_UTF8.to_le_bytes());
            cd.extend_from_slice(&e.method.to_le_bytes());
            cd.extend_from_slice(&self.time.to_le_bytes());
            cd.extend_from_slice(&self.date.to_le_bytes());
            cd.extend_from_slice(&e.crc32.to_le_bytes());
            cd.extend_from_slice(&csize_f.to_le_bytes());
            cd.extend_from_slice(&usize_f.to_le_bytes());
            cd.extend_from_slice(&(n.len() as u16).to_le_bytes());
            cd.extend_from_slice(&(x.len() as u16).to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes()); // comment
            cd.extend_from_slice(&0u16.to_le_bytes()); // disk
            cd.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
            cd.extend_from_slice(&0u32.to_le_bytes()); // external attributes
            cd.extend_from_slice(&lho_f.to_le_bytes());
            cd.extend_from_slice(n);
            cd.extend_from_slice(&x);
        }
        let n = self.entries.len() as u64;
        let eocd64_pos = cd_offset + cd.len() as u64;
        let mut tail = Vec::with_capacity(160 + comment.len());
        tail.extend_from_slice(SIG_EOCD64);
        tail.extend_from_slice(&(EOCD64_SIZE - 12).to_le_bytes());
        tail.extend_from_slice(&VERSION_ZIP64.to_le_bytes());
        tail.extend_from_slice(&VERSION_ZIP64.to_le_bytes());
        tail.extend_from_slice(&0u32.to_le_bytes());
        tail.extend_from_slice(&0u32.to_le_bytes());
        tail.extend_from_slice(&n.to_le_bytes());
        tail.extend_from_slice(&n.to_le_bytes());
        tail.extend_from_slice(&(cd.len() as u64).to_le_bytes());
        tail.extend_from_slice(&cd_offset.to_le_bytes());
        tail.extend_from_slice(SIG_LOCATOR);
        tail.extend_from_slice(&0u32.to_le_bytes());
        tail.extend_from_slice(&eocd64_pos.to_le_bytes());
        tail.extend_from_slice(&1u32.to_le_bytes());
        tail.extend_from_slice(SIG_EOCD);
        tail.extend_from_slice(&0u16.to_le_bytes());
        tail.extend_from_slice(&0u16.to_le_bytes());
        let n16 = n.min(0xFFFF) as u16;
        tail.extend_from_slice(&n16.to_le_bytes());
        tail.extend_from_slice(&n16.to_le_bytes());
        tail.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        tail.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        tail.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        tail.extend_from_slice(comment);
        self.w.write_all(&cd)?;
        self.w.write_all(&tail)?;
        self.pos += cd.len() as u64 + tail.len() as u64;
        self.w.flush()?;
        Ok(self.w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn write_then_read() {
        let mut zw = ZipWriter::new(Cursor::new(Vec::new()), (0, 0x21));
        zw.add_stored("a.txt", b"hello").unwrap();
        zw.begin("big").unwrap();
        zw.write_open(&[7u8; 1000]).unwrap();
        zw.write_open(&[8u8; 24]).unwrap();
        zw.end().unwrap();
        let bytes = zw.finish(b"aff4://x").unwrap().into_inner();
        let mut z = ZipArchive::new(Box::new(Cursor::new(bytes.clone()))).unwrap();
        assert_eq!(z.comment(), b"aff4://x");
        let i = z.find("a.txt").unwrap();
        assert_eq!(z.read_member(i, 100).unwrap(), b"hello");
        let j = z.find("big").unwrap();
        let mut b = [0u8; 4];
        z.read_stored_at(j, 998, &mut b).unwrap();
        assert_eq!(b, [7, 7, 8, 8]);
        assert!(z.crc_ok(j).unwrap());
        // Appended to another file: the global offset still resolves members.
        let mut shifted = vec![0xAAu8; 333];
        shifted.extend_from_slice(&bytes);
        let mut z = ZipArchive::new(Box::new(Cursor::new(shifted))).unwrap();
        let i = z.find("a.txt").unwrap();
        assert_eq!(z.read_member(i, 100).unwrap(), b"hello");
    }
}
