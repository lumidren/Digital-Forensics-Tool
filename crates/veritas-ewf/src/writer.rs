//! Streaming EWF-E01 writer.
//!
//! Layout written (identical in shape to libewf `ewfacquire -f encase6`):
//!
//! ```text
//! E01: header | header2 | header2 | header | volume | (sectors table table2)+ | next
//! E0n: header | data | (sectors table table2)+ | next
//! last: ... | [data, when it is also the first segment] | [error2] | digest | hash | done
//! ```
//!
//! The total chunk and sector counts are not known while streaming, so the `volume` and `data`
//! sections are written with provisional values and rewritten in place by [`EwfWriter::finish`].
//! Media whose length is not a multiple of the sector size is zero-padded to the next sector;
//! the padding is hashed (it is part of the media as any EWF reader presents it) and reported in
//! [`EwfSummary::padding_bytes`].

use crate::format::{self, BadSectorRange, Compression, EwfHeader, MediaType, SectionDescriptor, TableSection, VolumeInfo};
use crate::{EwfError, Result};
use digest::Digest;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use veritas_hash::{Hashes, MultiHasher};

/// Smallest accepted segment size.
pub const MIN_SEGMENT_SIZE: u64 = 64 * 1024;
/// Default segment size (1.4 GiB, the libewf default; fits FAT32 and EnCase limits).
pub const DEFAULT_SEGMENT_SIZE: u64 = 1_503_238_553;

/// Writer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EwfOptions {
    /// Maximum size of one segment file in bytes.
    pub segment_size: u64,
    pub sectors_per_chunk: u32,
    pub bytes_per_sector: u32,
    pub compression: Compression,
    pub media_type: MediaType,
    /// Source was a physical device (sets the physical media flag).
    pub physical: bool,
    /// Case metadata. `acquiry_date` / `system_date` default to the creation time when unset;
    /// `acquiry_software_version` defaults to `veritas-ewf <version>`.
    pub header: EwfHeader,
}

impl Default for EwfOptions {
    fn default() -> Self {
        Self {
            segment_size: DEFAULT_SEGMENT_SIZE,
            sectors_per_chunk: format::DEFAULT_SECTORS_PER_CHUNK,
            bytes_per_sector: format::DEFAULT_BYTES_PER_SECTOR,
            compression: Compression::Fast,
            media_type: MediaType::Fixed,
            physical: false,
            header: EwfHeader::default(),
        }
    }
}

/// Result of a finished acquisition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EwfSummary {
    pub segments: Vec<PathBuf>,
    pub chunk_count: u64,
    pub sector_count: u64,
    pub bytes_per_sector: u32,
    pub chunk_size: u64,
    /// Media size as stored (input plus sector padding).
    pub media_size: u64,
    /// Bytes passed to [`EwfWriter::write`].
    pub input_bytes: u64,
    /// Zero bytes appended to complete the last sector.
    pub padding_bytes: u64,
    /// MD5 / SHA-256 / SHA3-256 of the stored media.
    pub hashes: Hashes,
    /// SHA-1 of the stored media (written to the `digest` section).
    pub sha1: String,
    pub bad_sectors: Vec<BadSectorRange>,
}

struct Group {
    sectors_offset: u64,
    entries: Vec<u32>,
}

struct Segment {
    file: BufWriter<File>,
    number: u16,
    pos: u64,
    chunks: u64,
    group: Option<Group>,
}

/// Streaming EWF-E01 writer. Call [`write`](Self::write) any number of times with any buffer
/// sizes, then [`finish`](Self::finish).
pub struct EwfWriter {
    base: String,
    first_ext: String,
    opts: EwfOptions,
    chunk_size: usize,
    buf: Vec<u8>,
    hasher: MultiHasher,
    sha1: sha1::Sha1,
    segments: Vec<PathBuf>,
    cur: Option<Segment>,
    /// (segment path, payload offset) of every volume/data section to rewrite at finish.
    volume_patches: Vec<(PathBuf, u64)>,
    chunk_count: u64,
    input_bytes: u64,
    bad_sectors: Vec<BadSectorRange>,
    set_identifier: [u8; 16],
    padding: u64,
}

fn table_section_bytes(entries: usize) -> u64 {
    format::SECTION_DESCRIPTOR_SIZE + (format::TABLE_HEADER_SIZE + entries * 4 + 4) as u64
}

impl EwfWriter {
    /// Create the first segment. `path_base` is the output path without extension (an `.E01`
    /// extension, if given, is accepted and its letter case kept). Existing files are never
    /// overwritten.
    pub fn create(path_base: impl AsRef<Path>, mut opts: EwfOptions) -> Result<Self> {
        let raw = path_base.as_ref().to_string_lossy().into_owned();
        let (base, first_ext) = match raw.rsplit_once('.') {
            Some((b, e)) if e.eq_ignore_ascii_case("e01") && !b.is_empty() => (b.to_string(), e.to_string()),
            _ => (raw.clone(), "E01".to_string()),
        };
        if opts.segment_size < MIN_SEGMENT_SIZE {
            return Err(EwfError::InvalidInput(format!("segment size must be at least {} bytes", MIN_SEGMENT_SIZE)));
        }
        if opts.bytes_per_sector == 0 || !opts.bytes_per_sector.is_power_of_two() || opts.bytes_per_sector > 65536 {
            return Err(EwfError::InvalidInput("bytes per sector must be a power of two up to 65536".into()));
        }
        let chunk_size = opts.sectors_per_chunk as u64 * opts.bytes_per_sector as u64;
        if opts.sectors_per_chunk == 0 || chunk_size > format::MAX_CHUNK_SIZE || chunk_size > opts.segment_size / 2 {
            return Err(EwfError::InvalidInput("chunk size out of range for the segment size".into()));
        }
        let now = chrono::Utc::now();
        if opts.header.acquiry_date.is_none() {
            opts.header.acquiry_date = Some(now);
        }
        if opts.header.system_date.is_none() {
            opts.header.system_date = Some(now);
        }
        if opts.header.acquiry_software_version.is_empty() {
            opts.header.acquiry_software_version = format!("veritas-ewf {}", env!("CARGO_PKG_VERSION"));
        }
        if opts.header.acquiry_operating_system.is_empty() {
            opts.header.acquiry_operating_system = std::env::consts::OS.to_string();
        }
        let mut set_identifier = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut set_identifier);
        let mut w = Self {
            base,
            first_ext,
            chunk_size: chunk_size as usize,
            buf: Vec::with_capacity(chunk_size as usize),
            opts,
            hasher: MultiHasher::new(),
            sha1: sha1::Sha1::new(),
            segments: Vec::new(),
            cur: None,
            volume_patches: Vec::new(),
            chunk_count: 0,
            input_bytes: 0,
            padding: 0,
            bad_sectors: Vec::new(),
            set_identifier,
        };
        w.open_segment()?;
        Ok(w)
    }

    /// Path of segment `n` (1-based).
    pub fn segment_path(&self, n: u32) -> Result<PathBuf> {
        let ext = format::segment_extension(&self.first_ext, n)
            .ok_or_else(|| EwfError::InvalidInput(format!("segment number {} exceeds the EWF naming scheme", n)))?;
        Ok(PathBuf::from(format!("{}.{}", self.base, ext)))
    }

    /// Bytes accepted so far.
    pub fn bytes_written(&self) -> u64 {
        self.input_bytes
    }

    /// Segment files created so far (the last one may still be open).
    pub fn segments(&self) -> &[PathBuf] {
        &self.segments
    }

    /// Record a run of unreadable sectors (already zero-filled by the caller). Adjacent and
    /// overlapping runs are merged. Written to the `error2` section.
    pub fn record_bad_sectors(&mut self, first_sector: u64, sector_count: u64) {
        if sector_count == 0 {
            return;
        }
        if let Some(last) = self.bad_sectors.last_mut() {
            let end = last.first_sector + last.sector_count;
            if first_sector >= last.first_sector && first_sector <= end {
                let new_end = (first_sector + sector_count).max(end);
                last.sector_count = new_end - last.first_sector;
                return;
            }
        }
        self.bad_sectors.push(BadSectorRange { first_sector, sector_count });
    }

    /// Append media bytes.
    pub fn write(&mut self, mut data: &[u8]) -> Result<()> {
        self.hasher.update(data);
        self.sha1.update(data);
        self.input_bytes += data.len() as u64;
        while !data.is_empty() {
            let take = (self.chunk_size - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == self.chunk_size {
                let chunk = std::mem::replace(&mut self.buf, Vec::with_capacity(self.chunk_size));
                self.emit_chunk(&chunk)?;
            }
        }
        Ok(())
    }

    fn encode_chunk(&self, data: &[u8]) -> (Vec<u8>, bool) {
        if self.opts.compression != Compression::None {
            let z = format::zlib_compress(data, self.opts.compression.zlib_level());
            if !z.is_empty() && z.len() < data.len() {
                return (z, true);
            }
        }
        let mut out = Vec::with_capacity(data.len() + 4);
        out.extend_from_slice(data);
        out.extend_from_slice(&format::adler32(data).to_le_bytes());
        (out, false)
    }

    /// Bytes that must remain available in a segment to close it as the last segment.
    fn tail_reserve(&self, entries: usize) -> u64 {
        let tables = 2 * table_section_bytes(entries);
        let errors = format::SECTION_DESCRIPTOR_SIZE + (format::ERROR2_HEADER_SIZE + 8 * (self.bad_sectors.len() + 1) + 4) as u64;
        let last = (format::SECTION_DESCRIPTOR_SIZE + format::VOLUME_SIZE as u64)
            + errors
            + (format::SECTION_DESCRIPTOR_SIZE + format::DIGEST_SIZE as u64)
            + (format::SECTION_DESCRIPTOR_SIZE + format::HASH_SIZE as u64)
            + format::SECTION_DESCRIPTOR_SIZE;
        tables + last
    }

    fn emit_chunk(&mut self, data: &[u8]) -> Result<()> {
        let (stored, compressed) = self.encode_chunk(data);
        // Close the current chunk group if its table is full or offsets would overflow 31 bits.
        let must_close_group = match self.cur.as_ref().and_then(|s| s.group.as_ref().map(|g| (s.pos, g))) {
            Some((pos, g)) => {
                g.entries.len() >= format::MAX_TABLE_ENTRIES || pos + stored.len() as u64 - g.sectors_offset > format::MAX_TABLE_OFFSET
            }
            None => false,
        };
        if must_close_group {
            self.close_group()?;
        }
        // Start a new segment if this chunk would not fit.
        let (pos, chunks, entries, group_open) = {
            let s = self.cur.as_ref().ok_or_else(|| EwfError::InvalidInput("writer is closed".into()))?;
            let entries = s.group.as_ref().map(|g| g.entries.len()).unwrap_or(0);
            (s.pos, s.chunks, entries, s.group.is_some())
        };
        let projected = pos + if group_open { 0 } else { format::SECTION_DESCRIPTOR_SIZE } + stored.len() as u64 + self.tail_reserve(entries + 1);
        if projected > self.opts.segment_size && chunks > 0 {
            self.close_segment(None)?;
            self.open_segment()?;
        }
        let seg = self.cur.as_mut().ok_or_else(|| EwfError::InvalidInput("writer is closed".into()))?;
        if seg.group.is_none() {
            seg.file.write_all(&[0u8; 76])?;
            seg.group = Some(Group { sectors_offset: seg.pos, entries: Vec::new() });
            seg.pos += format::SECTION_DESCRIPTOR_SIZE;
        }
        let group = seg.group.as_mut().ok_or_else(|| EwfError::InvalidInput("no chunk group".into()))?;
        let rel = seg.pos - group.sectors_offset;
        if rel > format::MAX_TABLE_OFFSET {
            return Err(EwfError::InvalidInput("chunk offset exceeds 31-bit table range".into()));
        }
        group.entries.push(rel as u32 | if compressed { format::COMPRESSED_FLAG } else { 0 });
        seg.file.write_all(&stored)?;
        seg.pos += stored.len() as u64;
        seg.chunks += 1;
        self.chunk_count += 1;
        Ok(())
    }

    fn write_section(seg: &mut Segment, kind: &str, payload: &[u8]) -> Result<u64> {
        let size = format::SECTION_DESCRIPTOR_SIZE + payload.len() as u64;
        let d = SectionDescriptor { kind: kind.to_string(), next_offset: seg.pos + size, size };
        seg.file.write_all(&d.encode())?;
        seg.file.write_all(payload)?;
        let payload_offset = seg.pos + format::SECTION_DESCRIPTOR_SIZE;
        seg.pos += size;
        Ok(payload_offset)
    }

    fn write_terminator(seg: &mut Segment, kind: &str) -> Result<()> {
        let d = SectionDescriptor { kind: kind.to_string(), next_offset: seg.pos, size: 0 };
        seg.file.write_all(&d.encode())?;
        seg.pos += format::SECTION_DESCRIPTOR_SIZE;
        Ok(())
    }

    fn provisional_volume(&self) -> VolumeInfo {
        VolumeInfo {
            media_type: self.opts.media_type,
            chunk_count: self.chunk_count.min(u32::MAX as u64) as u32,
            sectors_per_chunk: self.opts.sectors_per_chunk,
            bytes_per_sector: self.opts.bytes_per_sector,
            sector_count: (self.input_bytes + self.padding) / self.opts.bytes_per_sector as u64,
            media_flags: format::MEDIA_FLAG_IMAGE | if self.opts.physical { format::MEDIA_FLAG_PHYSICAL } else { 0 },
            compression_level: self.opts.compression.to_level_byte(),
            error_granularity: self.opts.sectors_per_chunk,
            set_identifier: self.set_identifier,
        }
    }

    fn open_segment(&mut self) -> Result<()> {
        let number = self.segments.len() as u32 + 1;
        let number16 = u16::try_from(number).map_err(|_| EwfError::InvalidInput("too many segments".into()))?;
        let path = self.segment_path(number)?;
        let file = OpenOptions::new().write(true).create_new(true).open(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                EwfError::Exists(path.display().to_string())
            } else {
                EwfError::Io(e)
            }
        })?;
        let mut seg = Segment { file: BufWriter::with_capacity(1 << 20, file), number: number16, pos: 0, chunks: 0, group: None };
        seg.file.write_all(&format::encode_file_header(number16))?;
        seg.pos = format::FILE_HEADER_SIZE;
        let vol = self.provisional_volume().encode();
        if number == 1 {
            let level = self.opts.compression.zlib_level();
            let h2 = format::encode_header2_section(&self.opts.header.to_header2_string(), level);
            let h1 = format::encode_header_section(&self.opts.header.to_header_string(self.opts.compression), level);
            Self::write_section(&mut seg, "header2", &h2)?;
            Self::write_section(&mut seg, "header2", &h2)?;
            Self::write_section(&mut seg, "header", &h1)?;
            let off = Self::write_section(&mut seg, "volume", &vol)?;
            self.volume_patches.push((path.clone(), off));
        } else {
            let off = Self::write_section(&mut seg, "data", &vol)?;
            self.volume_patches.push((path.clone(), off));
        }
        self.segments.push(path);
        self.cur = Some(seg);
        Ok(())
    }

    fn close_group(&mut self) -> Result<()> {
        let seg = match self.cur.as_mut() {
            Some(s) => s,
            None => return Ok(()),
        };
        let group = match seg.group.take() {
            Some(g) => g,
            None => return Ok(()),
        };
        let sectors = SectionDescriptor { kind: "sectors".into(), next_offset: seg.pos, size: seg.pos - group.sectors_offset };
        seg.file.seek(SeekFrom::Start(group.sectors_offset))?;
        seg.file.write_all(&sectors.encode())?;
        seg.file.seek(SeekFrom::Start(seg.pos))?;
        let table = TableSection { base_offset: group.sectors_offset, entries: group.entries }.encode();
        Self::write_section(seg, "table", &table)?;
        Self::write_section(seg, "table2", &table)?;
        Ok(())
    }

    fn close_segment(&mut self, digests: Option<([u8; 16], [u8; 20])>) -> Result<()> {
        self.close_group()?;
        let vol = self.provisional_volume().encode();
        let errors = if digests.is_some() && !self.bad_sectors.is_empty() { Some(format::encode_error2_section(&self.bad_sectors)?) } else { None };
        let mut seg = self.cur.take().ok_or_else(|| EwfError::InvalidInput("writer is closed".into()))?;
        if let Some((md5, sha1)) = digests {
            if seg.number == 1 {
                let off = Self::write_section(&mut seg, "data", &vol)?;
                let path = self.segments.last().cloned().unwrap_or_default();
                self.volume_patches.push((path, off));
            }
            if let Some(e) = errors {
                Self::write_section(&mut seg, "error2", &e)?;
            }
            Self::write_section(&mut seg, "digest", &format::encode_digest_section(&md5, &sha1))?;
            Self::write_section(&mut seg, "hash", &format::encode_hash_section(&md5))?;
            Self::write_terminator(&mut seg, "done")?;
        } else {
            Self::write_terminator(&mut seg, "next")?;
        }
        seg.file.flush()?;
        seg.file.get_ref().sync_all()?;
        Ok(())
    }

    /// Flush the last chunk, write hash sections, close every segment and rewrite the volume and
    /// data sections with the final counts.
    pub fn finish(mut self) -> Result<EwfSummary> {
        let bps = self.opts.bytes_per_sector as u64;
        let rem = self.input_bytes % bps;
        let padding = if rem == 0 { 0 } else { bps - rem };
        if padding > 0 {
            let zeros = vec![0u8; padding as usize];
            self.hasher.update(&zeros);
            self.sha1.update(&zeros);
            self.buf.extend_from_slice(&zeros);
        }
        self.padding = padding;
        if !self.buf.is_empty() {
            let chunk = std::mem::take(&mut self.buf);
            self.emit_chunk(&chunk)?;
        }
        let hashes = std::mem::take(&mut self.hasher).finalize();
        let sha1: [u8; 20] = std::mem::replace(&mut self.sha1, sha1::Sha1::new()).finalize().into();
        let md5_vec = hex::decode(&hashes.md5).map_err(|e| EwfError::InvalidInput(e.to_string()))?;
        let md5: [u8; 16] = md5_vec.as_slice().try_into().map_err(|_| EwfError::InvalidInput("md5 length".into()))?;
        self.close_segment(Some((md5, sha1)))?;

        let media_size = self.input_bytes + padding;
        let mut volume = self.provisional_volume();
        volume.chunk_count = u32::try_from(self.chunk_count).map_err(|_| EwfError::InvalidInput("more than 2^32 chunks".into()))?;
        volume.sector_count = media_size / bps;
        let encoded = volume.encode();
        for (path, off) in &self.volume_patches {
            let mut f = OpenOptions::new().write(true).open(path)?;
            f.seek(SeekFrom::Start(*off))?;
            f.write_all(&encoded)?;
            f.sync_all()?;
        }
        Ok(EwfSummary {
            segments: self.segments.clone(),
            chunk_count: self.chunk_count,
            sector_count: volume.sector_count,
            bytes_per_sector: self.opts.bytes_per_sector,
            chunk_size: self.chunk_size as u64,
            media_size,
            input_bytes: self.input_bytes,
            padding_bytes: padding,
            hashes,
            sha1: hex::encode(sha1),
            bad_sectors: self.bad_sectors.clone(),
        })
    }
}
