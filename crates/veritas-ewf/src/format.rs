//! On-disk structures of the EWF-E01 ("EnCase 6" variant) container.
//!
//! Every decoder in this module takes a byte slice, checks its length before touching any field
//! and returns [`EwfError`] rather than panicking. Encoders produce the layout written by libewf's
//! `ewfacquire` for the EnCase 6 format so that libewf, EnCase and FTK accept the output.

use crate::{EwfError, Result};
use chrono::{DateTime, Datelike, Local, TimeZone, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;

/// File header signature of every EWF-E01 segment: `EVF\x09\x0d\x0a\xff\x00`.
pub const SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
/// Size of the segment file header: signature (8), fields start (1), segment number (2), fields end (2).
pub const FILE_HEADER_SIZE: u64 = 13;
/// Size of a section descriptor.
pub const SECTION_DESCRIPTOR_SIZE: u64 = 76;
/// Payload size of the `volume` and `data` sections (EnCase 2 and later).
pub const VOLUME_SIZE: usize = 1052;
/// Payload size of the `hash` section.
pub const HASH_SIZE: usize = 36;
/// Payload size of the `digest` section.
pub const DIGEST_SIZE: usize = 80;
/// Size of the table section header that precedes the entries.
pub const TABLE_HEADER_SIZE: usize = 24;
/// Size of the `error2` section header.
pub const ERROR2_HEADER_SIZE: usize = 520;
/// Maximum table entries per `table` section (the EnCase 6 limit).
pub const MAX_TABLE_ENTRIES: usize = 16375;
/// High bit of a table entry: the chunk is zlib compressed.
pub const COMPRESSED_FLAG: u32 = 0x8000_0000;
/// Table entries hold 31-bit offsets relative to the table base offset.
pub const MAX_TABLE_OFFSET: u64 = 0x7fff_ffff;
pub const DEFAULT_SECTORS_PER_CHUNK: u32 = 64;
pub const DEFAULT_BYTES_PER_SECTOR: u32 = 512;
/// Largest chunk this implementation will allocate when reading (cap against hostile files).
pub const MAX_CHUNK_SIZE: u64 = 64 * 1024 * 1024;
/// Largest decompressed header section accepted.
pub const MAX_HEADER_SIZE: usize = 4 * 1024 * 1024;
/// Largest error2 entry count accepted.
pub const MAX_ERROR2_ENTRIES: u32 = 1_000_000;

/// Adler-32 as used by zlib and by EWF for descriptor, table and chunk checksums.
pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    // 5552 is the largest block length for which the u32 accumulators cannot overflow.
    for block in data.chunks(5552) {
        for &byte in block {
            a += byte as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

pub(crate) fn u16_le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
pub(crate) fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
pub(crate) fn u64_le(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Encode the 13-byte segment file header.
pub fn encode_file_header(segment_number: u16) -> [u8; 13] {
    let mut out = [0u8; 13];
    out[..8].copy_from_slice(&SIGNATURE);
    out[8] = 1;
    out[9..11].copy_from_slice(&segment_number.to_le_bytes());
    out
}

/// Parse the segment file header and return the segment number.
pub fn parse_file_header(buf: &[u8]) -> Result<u16> {
    if buf.len() < FILE_HEADER_SIZE as usize {
        return Err(EwfError::Truncated("segment file header"));
    }
    if buf[..8] != SIGNATURE {
        return Err(EwfError::InvalidSignature);
    }
    if buf[8] != 1 {
        return Err(EwfError::Corrupt(format!(
            "unexpected fields-start byte {:#x}",
            buf[8]
        )));
    }
    let segment = u16_le(&buf[9..11]);
    if segment == 0 {
        return Err(EwfError::Corrupt("segment number 0".into()));
    }
    Ok(segment)
}

/// A section descriptor: type string, offset of the next descriptor and the size of this section
/// (descriptor included).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionDescriptor {
    pub kind: String,
    pub next_offset: u64,
    pub size: u64,
}

impl SectionDescriptor {
    pub fn encode(&self) -> [u8; 76] {
        let mut out = [0u8; 76];
        let name = self.kind.as_bytes();
        let n = name.len().min(16);
        out[..n].copy_from_slice(&name[..n]);
        out[16..24].copy_from_slice(&self.next_offset.to_le_bytes());
        out[24..32].copy_from_slice(&self.size.to_le_bytes());
        let chk = adler32(&out[..72]);
        out[72..76].copy_from_slice(&chk.to_le_bytes());
        out
    }

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 76 {
            return Err(EwfError::Truncated("section descriptor"));
        }
        let stored = u32_le(&buf[72..76]);
        let calc = adler32(&buf[..72]);
        if stored != calc {
            return Err(EwfError::Checksum {
                what: "section descriptor".into(),
                stored,
                calculated: calc,
            });
        }
        let end = buf[..16].iter().position(|&b| b == 0).unwrap_or(16);
        let kind = String::from_utf8_lossy(&buf[..end]).into_owned();
        Ok(Self {
            kind,
            next_offset: u64_le(&buf[16..24]),
            size: u64_le(&buf[24..32]),
        })
    }
}

/// Media type byte of the volume section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaType {
    Removable,
    Fixed,
    Optical,
    LogicalEvidence,
    Memory,
    Unknown(u8),
}

impl MediaType {
    pub fn to_byte(self) -> u8 {
        match self {
            MediaType::Removable => 0x00,
            MediaType::Fixed => 0x01,
            MediaType::Optical => 0x03,
            MediaType::LogicalEvidence => 0x0e,
            MediaType::Memory => 0x10,
            MediaType::Unknown(b) => b,
        }
    }
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => MediaType::Removable,
            0x01 => MediaType::Fixed,
            0x03 => MediaType::Optical,
            0x0e => MediaType::LogicalEvidence,
            0x10 => MediaType::Memory,
            other => MediaType::Unknown(other),
        }
    }
}

/// Media flag: the file is an image file (always set by acquisition tools).
pub const MEDIA_FLAG_IMAGE: u8 = 0x01;
/// Media flag: the source was a physical device.
pub const MEDIA_FLAG_PHYSICAL: u8 = 0x02;

/// Contents of the `volume` / `data` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub media_type: MediaType,
    pub chunk_count: u32,
    pub sectors_per_chunk: u32,
    pub bytes_per_sector: u32,
    pub sector_count: u64,
    pub media_flags: u8,
    /// 0 none, 1 fast, 2 best.
    pub compression_level: u8,
    pub error_granularity: u32,
    /// Segment file set identifier (GUID bytes as stored).
    pub set_identifier: [u8; 16],
}

impl VolumeInfo {
    pub fn chunk_size(&self) -> u64 {
        self.sectors_per_chunk as u64 * self.bytes_per_sector as u64
    }

    pub fn media_size(&self) -> u64 {
        self.sector_count
            .saturating_mul(self.bytes_per_sector as u64)
    }

    /// Reject geometries that cannot describe a real image before any allocation is sized from them.
    pub fn validate(&self) -> Result<()> {
        if self.bytes_per_sector == 0 || self.bytes_per_sector > 1 << 20 {
            return Err(EwfError::Corrupt(format!(
                "bytes per sector {} out of range",
                self.bytes_per_sector
            )));
        }
        if self.sectors_per_chunk == 0 || self.chunk_size() > MAX_CHUNK_SIZE {
            return Err(EwfError::Corrupt(format!(
                "sectors per chunk {} out of range",
                self.sectors_per_chunk
            )));
        }
        if self
            .sector_count
            .checked_mul(self.bytes_per_sector as u64)
            .is_none()
        {
            return Err(EwfError::Corrupt(
                "sector count overflows media size".into(),
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; VOLUME_SIZE];
        out[0] = self.media_type.to_byte();
        out[4..8].copy_from_slice(&self.chunk_count.to_le_bytes());
        out[8..12].copy_from_slice(&self.sectors_per_chunk.to_le_bytes());
        out[12..16].copy_from_slice(&self.bytes_per_sector.to_le_bytes());
        out[16..24].copy_from_slice(&self.sector_count.to_le_bytes());
        out[36] = self.media_flags;
        out[52] = self.compression_level;
        out[56..60].copy_from_slice(&self.error_granularity.to_le_bytes());
        out[64..80].copy_from_slice(&self.set_identifier);
        let chk = adler32(&out[..VOLUME_SIZE - 4]);
        out[VOLUME_SIZE - 4..].copy_from_slice(&chk.to_le_bytes());
        out
    }

    /// Parse a `volume` / `data` section payload, or the 94-byte EnCase 1 / FTK `disk` payload.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() >= VOLUME_SIZE {
            let stored = u32_le(&buf[VOLUME_SIZE - 4..VOLUME_SIZE]);
            let calc = adler32(&buf[..VOLUME_SIZE - 4]);
            if stored != calc {
                return Err(EwfError::Checksum {
                    what: "volume section".into(),
                    stored,
                    calculated: calc,
                });
            }
            let mut id = [0u8; 16];
            id.copy_from_slice(&buf[64..80]);
            let v = Self {
                media_type: MediaType::from_byte(buf[0]),
                chunk_count: u32_le(&buf[4..8]),
                sectors_per_chunk: u32_le(&buf[8..12]),
                bytes_per_sector: u32_le(&buf[12..16]),
                sector_count: u64_le(&buf[16..24]),
                media_flags: buf[36],
                compression_level: buf[52],
                error_granularity: u32_le(&buf[56..60]),
                set_identifier: id,
            };
            v.validate()?;
            return Ok(v);
        }
        if buf.len() >= 94 {
            let stored = u32_le(&buf[90..94]);
            let calc = adler32(&buf[..90]);
            if stored != calc {
                return Err(EwfError::Checksum {
                    what: "disk section".into(),
                    stored,
                    calculated: calc,
                });
            }
            let v = Self {
                media_type: MediaType::Fixed,
                chunk_count: u32_le(&buf[4..8]),
                sectors_per_chunk: u32_le(&buf[8..12]),
                bytes_per_sector: u32_le(&buf[12..16]),
                sector_count: u32_le(&buf[16..20]) as u64,
                media_flags: MEDIA_FLAG_IMAGE,
                compression_level: 0,
                error_granularity: 0,
                set_identifier: [0u8; 16],
            };
            v.validate()?;
            return Ok(v);
        }
        Err(EwfError::Truncated("volume section"))
    }
}

/// Parsed `table` section: base offset plus raw entries (compressed flag still in the high bit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSection {
    pub base_offset: u64,
    pub entries: Vec<u32>,
}

impl TableSection {
    /// Encode a table payload: header, entries, entries checksum.
    pub fn encode(&self) -> Vec<u8> {
        let n = self.entries.len() as u32;
        let mut out = Vec::with_capacity(TABLE_HEADER_SIZE + self.entries.len() * 4 + 4);
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&self.base_offset.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]);
        let hchk = adler32(&out[..20]);
        out.extend_from_slice(&hchk.to_le_bytes());
        let start = out.len();
        for e in &self.entries {
            out.extend_from_slice(&e.to_le_bytes());
        }
        let echk = adler32(&out[start..]);
        out.extend_from_slice(&echk.to_le_bytes());
        out
    }

    /// Parse a table payload (descriptor excluded).
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < TABLE_HEADER_SIZE {
            return Err(EwfError::Truncated("table header"));
        }
        let stored = u32_le(&buf[20..24]);
        let calc = adler32(&buf[..20]);
        if stored != calc {
            return Err(EwfError::Checksum {
                what: "table header".into(),
                stored,
                calculated: calc,
            });
        }
        let n = u32_le(&buf[0..4]) as usize;
        if n > 65535 {
            return Err(EwfError::Corrupt(format!("table claims {} entries", n)));
        }
        let base_offset = u64_le(&buf[8..16]);
        let end = TABLE_HEADER_SIZE + n * 4;
        if buf.len() < end {
            return Err(EwfError::Truncated("table entries"));
        }
        let entries: Vec<u32> = buf[TABLE_HEADER_SIZE..end]
            .chunks_exact(4)
            .map(u32_le)
            .collect();
        if buf.len() >= end + 4 {
            let stored = u32_le(&buf[end..end + 4]);
            let calc = adler32(&buf[TABLE_HEADER_SIZE..end]);
            if stored != calc {
                return Err(EwfError::Checksum {
                    what: "table entries".into(),
                    stored,
                    calculated: calc,
                });
            }
        }
        Ok(Self {
            base_offset,
            entries,
        })
    }
}

/// Encode the `hash` section payload (MD5 only).
pub fn encode_hash_section(md5: &[u8; 16]) -> [u8; HASH_SIZE] {
    let mut out = [0u8; HASH_SIZE];
    out[..16].copy_from_slice(md5);
    let chk = adler32(&out[..32]);
    out[32..].copy_from_slice(&chk.to_le_bytes());
    out
}

pub fn parse_hash_section(buf: &[u8]) -> Result<[u8; 16]> {
    if buf.len() < HASH_SIZE {
        return Err(EwfError::Truncated("hash section"));
    }
    let stored = u32_le(&buf[32..36]);
    let calc = adler32(&buf[..32]);
    if stored != calc {
        return Err(EwfError::Checksum {
            what: "hash section".into(),
            stored,
            calculated: calc,
        });
    }
    let mut md5 = [0u8; 16];
    md5.copy_from_slice(&buf[..16]);
    Ok(md5)
}

/// Encode the `digest` section payload (MD5 + SHA-1).
pub fn encode_digest_section(md5: &[u8; 16], sha1: &[u8; 20]) -> [u8; DIGEST_SIZE] {
    let mut out = [0u8; DIGEST_SIZE];
    out[..16].copy_from_slice(md5);
    out[16..36].copy_from_slice(sha1);
    let chk = adler32(&out[..76]);
    out[76..].copy_from_slice(&chk.to_le_bytes());
    out
}

pub fn parse_digest_section(buf: &[u8]) -> Result<([u8; 16], [u8; 20])> {
    if buf.len() < DIGEST_SIZE {
        return Err(EwfError::Truncated("digest section"));
    }
    let stored = u32_le(&buf[76..80]);
    let calc = adler32(&buf[..76]);
    if stored != calc {
        return Err(EwfError::Checksum {
            what: "digest section".into(),
            stored,
            calculated: calc,
        });
    }
    let mut md5 = [0u8; 16];
    md5.copy_from_slice(&buf[..16]);
    let mut sha1 = [0u8; 20];
    sha1.copy_from_slice(&buf[16..36]);
    Ok((md5, sha1))
}

/// A run of unreadable sectors, as recorded in the `error2` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BadSectorRange {
    pub first_sector: u64,
    pub sector_count: u64,
}

/// Encode the `error2` payload: 520-byte header, 8-byte entries, entries checksum.
pub fn encode_error2_section(ranges: &[BadSectorRange]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; ERROR2_HEADER_SIZE];
    out[..4].copy_from_slice(&(ranges.len() as u32).to_le_bytes());
    let chk = adler32(&out[..ERROR2_HEADER_SIZE - 4]);
    out[ERROR2_HEADER_SIZE - 4..].copy_from_slice(&chk.to_le_bytes());
    let start = out.len();
    for r in ranges {
        let first = u32::try_from(r.first_sector)
            .map_err(|_| EwfError::InvalidInput("bad sector beyond 32-bit range".into()))?;
        let count = u32::try_from(r.sector_count)
            .map_err(|_| EwfError::InvalidInput("bad sector run beyond 32-bit range".into()))?;
        out.extend_from_slice(&first.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
    }
    let echk = adler32(&out[start..]);
    out.extend_from_slice(&echk.to_le_bytes());
    Ok(out)
}

pub fn parse_error2_section(buf: &[u8]) -> Result<Vec<BadSectorRange>> {
    if buf.len() < ERROR2_HEADER_SIZE {
        return Err(EwfError::Truncated("error2 header"));
    }
    let stored = u32_le(&buf[ERROR2_HEADER_SIZE - 4..ERROR2_HEADER_SIZE]);
    let calc = adler32(&buf[..ERROR2_HEADER_SIZE - 4]);
    if stored != calc {
        return Err(EwfError::Checksum {
            what: "error2 header".into(),
            stored,
            calculated: calc,
        });
    }
    let n = u32_le(&buf[..4]);
    if n > MAX_ERROR2_ENTRIES {
        return Err(EwfError::Corrupt(format!("error2 claims {} entries", n)));
    }
    let end = ERROR2_HEADER_SIZE + n as usize * 8;
    if buf.len() < end {
        return Err(EwfError::Truncated("error2 entries"));
    }
    Ok(buf[ERROR2_HEADER_SIZE..end]
        .chunks_exact(8)
        .map(|e| BadSectorRange {
            first_sector: u32_le(&e[..4]) as u64,
            sector_count: u32_le(&e[4..8]) as u64,
        })
        .collect())
}

/// Compression level as stored in the volume section and used for chunk data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    /// Store every chunk verbatim with an Adler-32 trailer.
    None,
    /// zlib level 1.
    #[default]
    Fast,
    /// zlib level 9.
    Best,
}

impl Compression {
    pub fn to_level_byte(self) -> u8 {
        match self {
            Compression::None => 0,
            Compression::Fast => 1,
            Compression::Best => 2,
        }
    }
    /// zlib level used for header sections and (unless `None`) for chunks.
    pub fn zlib_level(self) -> u32 {
        match self {
            Compression::Best => 9,
            _ => 1,
        }
    }
    /// Header identifier `r` value: n(one), f(ast), b(est).
    pub fn header_letter(self) -> &'static str {
        match self {
            Compression::None => "n",
            Compression::Fast => "f",
            Compression::Best => "b",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "none" | "n" | "0" => Some(Compression::None),
            "fast" | "f" | "1" => Some(Compression::Fast),
            "best" | "b" | "2" => Some(Compression::Best),
            _ => None,
        }
    }
}

/// Acquisition metadata stored in the `header` / `header2` sections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EwfHeader {
    pub case_number: String,
    pub evidence_number: String,
    pub description: String,
    pub examiner_name: String,
    pub notes: String,
    /// Tool name and version that produced the image (`av`).
    pub acquiry_software_version: String,
    /// Operating system the image was produced on (`ov`).
    pub acquiry_operating_system: String,
    pub model: String,
    pub serial_number: String,
    pub acquiry_date: Option<DateTime<Utc>>,
    pub system_date: Option<DateTime<Utc>>,
    /// Compression letter from the `r` field when present (n, f, b).
    pub compression: Option<String>,
    /// Identifier/value pairs not mapped to a field above.
    #[serde(default)]
    pub raw: BTreeMap<String, String>,
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\t' || c == '\n' || c == '\r' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// The EnCase `header` section stores local wall-clock time (libewf interprets it that way);
/// `header2` stores POSIX seconds and is authoritative.
fn header_date(d: &DateTime<Utc>) -> String {
    let d = d.with_timezone(&Local);
    format!(
        "{} {} {} {} {} {}",
        d.year(),
        d.month(),
        d.day(),
        d.hour(),
        d.minute(),
        d.second()
    )
}

impl EwfHeader {
    /// EnCase 4-6 style `header` string (ASCII, CRLF line ends).
    pub fn to_header_string(&self, compression: Compression) -> String {
        let epoch = DateTime::<Utc>::UNIX_EPOCH;
        let m = header_date(self.acquiry_date.as_ref().unwrap_or(&epoch));
        let u = header_date(
            self.system_date
                .as_ref()
                .or(self.acquiry_date.as_ref())
                .unwrap_or(&epoch),
        );
        format!(
            "1\r\nmain\r\nc\tn\ta\te\tt\tav\tov\tm\tu\tp\tr\r\n{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t0\t{}\r\n\r\n",
            sanitize(&self.case_number),
            sanitize(&self.evidence_number),
            sanitize(&self.description),
            sanitize(&self.examiner_name),
            sanitize(&self.notes),
            sanitize(&self.acquiry_software_version),
            sanitize(&self.acquiry_operating_system),
            m,
            u,
            compression.header_letter(),
        )
    }

    /// EnCase 6 style `header2` string (encoded as UTF-16LE with BOM, LF line ends).
    pub fn to_header2_string(&self) -> String {
        let m = self.acquiry_date.map(|d| d.timestamp()).unwrap_or(0);
        let u = self
            .system_date
            .or(self.acquiry_date)
            .map(|d| d.timestamp())
            .unwrap_or(0);
        format!(
            "3\nmain\na\tc\tn\te\tt\tmd\tsn\tav\tov\tm\tu\tp\tdc\n{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t0\t\n\n\
             srce\n0\t1\np\tn\tid\tev\ttb\tlo\tpo\tah\tgu\taq\n0\t0\n\t\t\t\t\t-1\t-1\t\t\t\n\n\
             sub\n0\t1\np\tn\tid\tnu\tco\tgu\n0\t0\n\t\t\t\t1\t\n\n",
            sanitize(&self.description),
            sanitize(&self.case_number),
            sanitize(&self.evidence_number),
            sanitize(&self.examiner_name),
            sanitize(&self.notes),
            sanitize(&self.model),
            sanitize(&self.serial_number),
            sanitize(&self.acquiry_software_version),
            sanitize(&self.acquiry_operating_system),
            m,
            u,
        )
    }

    /// Merge one identifier/value pair; values already set win, so `header2` (parsed first)
    /// takes precedence over `header`.
    fn absorb(&mut self, id: &str, value: &str, is_header2: bool) {
        let set = |slot: &mut String| {
            if slot.is_empty() {
                *slot = value.to_string();
            }
        };
        match id {
            "c" => set(&mut self.case_number),
            "n" => set(&mut self.evidence_number),
            "a" => set(&mut self.description),
            "e" => set(&mut self.examiner_name),
            "t" => set(&mut self.notes),
            "av" => set(&mut self.acquiry_software_version),
            "ov" => set(&mut self.acquiry_operating_system),
            "md" => set(&mut self.model),
            "sn" => set(&mut self.serial_number),
            "m" => {
                if self.acquiry_date.is_none() {
                    self.acquiry_date = parse_date(value, is_header2);
                }
            }
            "u" => {
                if self.system_date.is_none() {
                    self.system_date = parse_date(value, is_header2);
                }
            }
            "r" => {
                if self.compression.is_none() && !value.is_empty() {
                    self.compression = Some(value.to_string());
                }
            }
            "p" => {}
            other => {
                self.raw
                    .entry(other.to_string())
                    .or_insert_with(|| value.to_string());
            }
        }
    }

    /// Parse a decoded header string (either flavour) into `self`.
    pub fn parse_into(&mut self, text: &str, is_header2: bool) -> Result<()> {
        let lines: Vec<&str> = text.split('\n').map(|l| l.trim_end_matches('\r')).collect();
        let main = lines
            .iter()
            .position(|l| *l == "main")
            .ok_or_else(|| EwfError::Corrupt("header has no main table".into()))?;
        let ids = lines
            .get(main + 1)
            .ok_or_else(|| EwfError::Corrupt("header has no identifiers".into()))?;
        let values = lines
            .get(main + 2)
            .ok_or_else(|| EwfError::Corrupt("header has no values".into()))?;
        let values: Vec<&str> = values.split('\t').collect();
        for (i, id) in ids.split('\t').enumerate() {
            self.absorb(id, values.get(i).copied().unwrap_or(""), is_header2);
        }
        Ok(())
    }
}

/// Parse "yyyy m d h m s" (local time), a POSIX timestamp (header2), or ctime style
/// "Tue Dec 10 13:28:38 2013" (local time).
pub fn parse_date(value: &str, is_header2: bool) -> Option<DateTime<Utc>> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if is_header2 {
        if let Ok(ts) = value.parse::<i64>() {
            return Utc.timestamp_opt(ts, 0).single();
        }
    }
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() == 6 {
        let nums: Option<Vec<u32>> = parts.iter().map(|p| p.parse::<u32>().ok()).collect();
        if let Some(n) = nums {
            return Local
                .with_ymd_and_hms(n[0] as i32, n[1], n[2], n[3], n[4], n[5])
                .earliest()
                .map(|d| d.with_timezone(&Utc));
        }
    }
    if parts.len() == 5 {
        let months = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let month = months
            .iter()
            .position(|m| m.eq_ignore_ascii_case(parts[1]))? as u32
            + 1;
        let day = parts[2].parse::<u32>().ok()?;
        let hms: Vec<u32> = parts[3].split(':').filter_map(|x| x.parse().ok()).collect();
        let year = parts[4].parse::<i32>().ok()?;
        if hms.len() == 3 {
            return Local
                .with_ymd_and_hms(year, month, day, hms[0], hms[1], hms[2])
                .earliest()
                .map(|d| d.with_timezone(&Utc));
        }
    }
    value
        .parse::<i64>()
        .ok()
        .and_then(|ts| Utc.timestamp_opt(ts, 0).single())
}

/// zlib-compress a buffer at the given level.
pub fn zlib_compress(data: &[u8], level: u32) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(
        Vec::with_capacity(data.len() / 2 + 64),
        flate2::Compression::new(level),
    );
    // Writing into a Vec cannot fail; an error here would only come from the allocator.
    if enc.write_all(data).is_err() {
        return Vec::new();
    }
    enc.finish().unwrap_or_default()
}

/// zlib-decompress with a hard output cap so a hostile chunk cannot exhaust memory.
pub fn zlib_decompress(data: &[u8], max_out: usize) -> Result<Vec<u8>> {
    let mut dec = flate2::read::ZlibDecoder::new(data);
    let mut out = Vec::with_capacity(max_out.min(1 << 20));
    (&mut dec)
        .take(max_out as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| EwfError::Corrupt(format!("zlib: {}", e)))?;
    if out.len() > max_out {
        return Err(EwfError::Corrupt(format!(
            "decompressed data exceeds {} bytes",
            max_out
        )));
    }
    Ok(out)
}

/// `header` section payload: zlib over ASCII.
pub fn encode_header_section(text: &str, level: u32) -> Vec<u8> {
    zlib_compress(text.as_bytes(), level)
}

/// `header2` section payload: zlib over UTF-16LE with BOM.
pub fn encode_header2_section(text: &str, level: u32) -> Vec<u8> {
    let mut raw = Vec::with_capacity(text.len() * 2 + 2);
    raw.extend_from_slice(&[0xff, 0xfe]);
    for unit in text.encode_utf16() {
        raw.extend_from_slice(&unit.to_le_bytes());
    }
    zlib_compress(&raw, level)
}

/// Decode a `header` or `header2` payload into text.
pub fn decode_header_section(payload: &[u8]) -> Result<String> {
    let raw = zlib_decompress(payload, MAX_HEADER_SIZE)?;
    if raw.len() >= 2 && raw[0] == 0xff && raw[1] == 0xfe {
        let units: Vec<u16> = raw[2..].chunks_exact(2).map(u16_le).collect();
        return Ok(String::from_utf16_lossy(&units));
    }
    if raw.len() >= 2 && raw[0] == 0xfe && raw[1] == 0xff {
        let units: Vec<u16> = raw[2..]
            .chunks_exact(2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .collect();
        return Ok(String::from_utf16_lossy(&units));
    }
    Ok(raw.iter().map(|&b| b as char).collect())
}

/// Extension of segment `n` (1-based): E01..E99, EAA..EZZ, FAA.. as libewf names them; lower case
/// when the first segment used a lower-case extension.
pub fn segment_extension(first_ext: &str, n: u32) -> Option<String> {
    if n == 0 {
        return None;
    }
    let lower = first_ext
        .chars()
        .next()
        .map(|c| c.is_ascii_lowercase())
        .unwrap_or(false);
    let first = first_ext.chars().next().unwrap_or('E').to_ascii_uppercase();
    let ext = if n <= 99 {
        format!("{}{:02}", first, n)
    } else {
        let idx = n - 100;
        let c2 = (b'A' + (idx % 26) as u8) as char;
        let c1 = (b'A' + ((idx / 26) % 26) as u8) as char;
        let c0 = first as u32 + idx / 676;
        if c0 > 'Z' as u32 {
            return None;
        }
        format!("{}{}{}", char::from_u32(c0)?, c1, c2)
    };
    Some(if lower { ext.to_ascii_lowercase() } else { ext })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_known_vectors() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        let big = vec![0xabu8; 100_000];
        let z = zlib_compress(&big, 1);
        let trailer = u32::from_be_bytes([
            z[z.len() - 4],
            z[z.len() - 3],
            z[z.len() - 2],
            z[z.len() - 1],
        ]);
        assert_eq!(adler32(&big), trailer);
    }

    #[test]
    fn descriptor_roundtrip_and_checksum() {
        let d = SectionDescriptor {
            kind: "sectors".into(),
            next_offset: 1234,
            size: 999,
        };
        let enc = d.encode();
        assert_eq!(SectionDescriptor::parse(&enc).unwrap(), d);
        let mut bad = enc;
        bad[20] ^= 1;
        assert!(matches!(
            SectionDescriptor::parse(&bad),
            Err(EwfError::Checksum { .. })
        ));
        assert!(matches!(
            SectionDescriptor::parse(&bad[..10]),
            Err(EwfError::Truncated(_))
        ));
    }

    #[test]
    fn volume_roundtrip() {
        let v = VolumeInfo {
            media_type: MediaType::Fixed,
            chunk_count: 7,
            sectors_per_chunk: 64,
            bytes_per_sector: 512,
            sector_count: 448,
            media_flags: MEDIA_FLAG_IMAGE | MEDIA_FLAG_PHYSICAL,
            compression_level: 2,
            error_granularity: 64,
            set_identifier: [9u8; 16],
        };
        assert_eq!(VolumeInfo::parse(&v.encode()).unwrap(), v);
    }

    #[test]
    fn table_and_error2_roundtrip() {
        let t = TableSection {
            base_offset: 1871,
            entries: vec![0x8000_004c, 0x4c, 0x8000_1234],
        };
        assert_eq!(TableSection::parse(&t.encode()).unwrap(), t);
        let r = vec![
            BadSectorRange {
                first_sector: 10,
                sector_count: 2,
            },
            BadSectorRange {
                first_sector: 99,
                sector_count: 1,
            },
        ];
        assert_eq!(
            parse_error2_section(&encode_error2_section(&r).unwrap()).unwrap(),
            r
        );
    }

    #[test]
    fn header_strings_parse_back() {
        let h = EwfHeader {
            case_number: "C-1".into(),
            evidence_number: "E\t1".into(),
            description: "desc".into(),
            examiner_name: "alice".into(),
            notes: "n".into(),
            acquiry_software_version: "veritas".into(),
            acquiry_operating_system: "Windows".into(),
            acquiry_date: Utc.with_ymd_and_hms(2021, 7, 22, 17, 33, 18).single(),
            system_date: Utc.with_ymd_and_hms(2021, 7, 22, 17, 33, 20).single(),
            ..Default::default()
        };
        let mut back = EwfHeader::default();
        back.parse_into(
            &decode_header_section(&encode_header2_section(&h.to_header2_string(), 9)).unwrap(),
            true,
        )
        .unwrap();
        back.parse_into(
            &decode_header_section(&encode_header_section(
                &h.to_header_string(Compression::Best),
                9,
            ))
            .unwrap(),
            false,
        )
        .unwrap();
        assert_eq!(back.case_number, "C-1");
        assert_eq!(back.evidence_number, "E 1");
        assert_eq!(back.examiner_name, "alice");
        assert_eq!(back.acquiry_date, h.acquiry_date);
        assert_eq!(back.system_date, h.system_date);
        assert_eq!(back.compression.as_deref(), Some("b"));
    }

    #[test]
    fn extensions_follow_libewf_sequence() {
        assert_eq!(segment_extension("E01", 1).unwrap(), "E01");
        assert_eq!(segment_extension("E01", 99).unwrap(), "E99");
        assert_eq!(segment_extension("E01", 100).unwrap(), "EAA");
        assert_eq!(segment_extension("E01", 101).unwrap(), "EAB");
        assert_eq!(segment_extension("E01", 126).unwrap(), "EBA");
        assert_eq!(segment_extension("E01", 100 + 676).unwrap(), "FAA");
        assert_eq!(segment_extension("e01", 100).unwrap(), "eaa");
        assert!(segment_extension("E01", 0).is_none());
    }

    #[test]
    fn date_formats() {
        let want = Utc.with_ymd_and_hms(2013, 12, 10, 11, 28, 38).single();
        assert_eq!(parse_date("1386674918", true), want);
        let local = Local
            .with_ymd_and_hms(2013, 12, 10, 12, 28, 38)
            .earliest()
            .map(|d| d.with_timezone(&Utc));
        assert_eq!(parse_date("2013 12 10 12 28 38", false), local);
        assert_eq!(parse_date("Tue Dec 10 12:28:38 2013", false), local);
        assert_eq!(parse_date("", false), None);
        assert_eq!(parse_date("garbage", false), None);
    }

    #[test]
    fn decompress_cap_is_enforced() {
        let z = zlib_compress(&vec![0u8; 100_000], 9);
        assert!(zlib_decompress(&z, 1000).is_err());
        assert_eq!(zlib_decompress(&z, 100_000).unwrap().len(), 100_000);
    }
}
