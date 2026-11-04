//! EWF-E01 reader: segment-chain resolution, chunk mapping, random access and verification.

use crate::format::{self, BadSectorRange, EwfHeader, SectionDescriptor, TableSection, VolumeInfo};
use crate::{EwfError, Result};
use digest::Digest;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use veritas_hash::{Hashes, MultiHasher};

/// Upper bound for metadata section payloads read into memory (headers, volume, tables, error2).
const MAX_METADATA_SECTION: u64 = 16 * 1024 * 1024;
/// Upper bound on the number of sections walked per segment (loop guard).
const MAX_SECTIONS_PER_SEGMENT: usize = 1_000_000;

#[derive(Debug, Clone, Copy)]
struct ChunkLoc {
    segment: usize,
    offset: u64,
    size: u64,
    compressed: bool,
}

struct SegmentFile {
    path: PathBuf,
    file: File,
    len: u64,
}

/// Result of [`EwfReader::verify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    pub media_size: u64,
    pub computed: Hashes,
    pub computed_sha1: String,
    pub stored_md5: Option<String>,
    pub stored_sha1: Option<String>,
    pub md5_match: Option<bool>,
    pub sha1_match: Option<bool>,
    /// True when a stored MD5 exists and matches, and a stored SHA-1 (if any) matches.
    pub verified: bool,
}

/// Summary for display (`ewf-tool info`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EwfInfo {
    pub segments: Vec<PathBuf>,
    pub media_size: u64,
    pub volume: VolumeInfo,
    pub header: EwfHeader,
    pub chunk_count: usize,
    pub stored_md5: Option<String>,
    pub stored_sha1: Option<String>,
    pub acquisition_errors: Vec<BadSectorRange>,
}

/// Random-access reader over an EWF-E01 segment set. Implements [`Read`] and [`Seek`].
pub struct EwfReader {
    segments: Vec<SegmentFile>,
    volume: VolumeInfo,
    header: EwfHeader,
    chunks: Vec<ChunkLoc>,
    md5: Option<[u8; 16]>,
    sha1: Option<[u8; 20]>,
    errors: Vec<BadSectorRange>,
    position: u64,
    cache: Option<(usize, Vec<u8>)>,
}

/// Resolve the segment chain that starts at `first`: `x.E01, x.E02 .. x.E99, x.EAA ..`.
/// A file whose extension is not of the `?01` form is treated as a single segment.
pub fn resolve_segments(first: &Path) -> Result<Vec<PathBuf>> {
    if !first.is_file() {
        return Err(EwfError::MissingSegment(first.display().to_string()));
    }
    let ext = first.extension().and_then(|e| e.to_str()).unwrap_or("");
    let chained = ext.len() == 3 && ext.as_bytes()[0].is_ascii_alphabetic() && &ext[1..] == "01";
    if !chained {
        return Ok(vec![first.to_path_buf()]);
    }
    let mut out = vec![first.to_path_buf()];
    for n in 2u32.. {
        let Some(e) = format::segment_extension(ext, n) else { break };
        let p = first.with_extension(e);
        if p.is_file() {
            out.push(p);
        } else {
            break;
        }
    }
    Ok(out)
}

fn read_exact_at(file: &mut File, offset: u64, len: u64) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len as usize];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            EwfError::Truncated("section data")
        } else {
            EwfError::Io(e)
        }
    })?;
    Ok(buf)
}

impl EwfReader {
    /// Open the segment set whose first segment is `first_segment`.
    pub fn open(first_segment: impl AsRef<Path>) -> Result<Self> {
        let paths = resolve_segments(first_segment.as_ref())?;
        Self::open_segments(&paths)
    }

    /// Open an explicit, ordered list of segment files.
    pub fn open_segments(paths: &[PathBuf]) -> Result<Self> {
        if paths.is_empty() {
            return Err(EwfError::InvalidInput("no segment files".into()));
        }
        let mut segments = Vec::with_capacity(paths.len());
        for p in paths {
            let file = File::open(p)?;
            let len = file.metadata()?.len();
            segments.push(SegmentFile { path: p.clone(), file, len });
        }
        let mut header = EwfHeader::default();
        let mut have_header2 = false;
        let mut have_header = false;
        let mut volume: Option<VolumeInfo> = None;
        let mut chunks: Vec<ChunkLoc> = Vec::new();
        let mut md5 = None;
        let mut sha1 = None;
        let mut errors = Vec::new();
        let mut done = false;

        for idx in 0..segments.len() {
            if done {
                // Extra files after a `done` section are not part of this set.
                segments.truncate(idx);
                break;
            }
            let seg_len = segments[idx].len;
            let fh = read_exact_at(&mut segments[idx].file, 0, format::FILE_HEADER_SIZE).map_err(|_| EwfError::Truncated("segment file header"))?;
            let number = format::parse_file_header(&fh)?;
            if number as usize != idx + 1 {
                return Err(EwfError::Corrupt(format!("{} has segment number {}, expected {}", segments[idx].path.display(), number, idx + 1)));
            }
            let mut off = format::FILE_HEADER_SIZE;
            let mut last_sectors: Option<(u64, u64)> = None;
            let mut table_ok_in_group = false;
            let mut ended = false;
            for _ in 0..MAX_SECTIONS_PER_SEGMENT {
                if off.checked_add(format::SECTION_DESCRIPTOR_SIZE).map(|e| e > seg_len).unwrap_or(true) {
                    return Err(EwfError::Truncated("section descriptor"));
                }
                let raw = read_exact_at(&mut segments[idx].file, off, format::SECTION_DESCRIPTOR_SIZE)?;
                let desc = SectionDescriptor::parse(&raw)?;
                let terminal = desc.kind == "done" || desc.kind == "next";
                let section_end = if terminal {
                    off + format::SECTION_DESCRIPTOR_SIZE
                } else {
                    if desc.size < format::SECTION_DESCRIPTOR_SIZE {
                        return Err(EwfError::Corrupt(format!("section {} at {} has size {}", desc.kind, off, desc.size)));
                    }
                    off.checked_add(desc.size).ok_or_else(|| EwfError::Corrupt("section size overflow".into()))?
                };
                if section_end > seg_len {
                    return Err(EwfError::Truncated("section"));
                }
                let payload_off = off + format::SECTION_DESCRIPTOR_SIZE;
                let payload_len = section_end - payload_off;
                let payload = |segs: &mut Vec<SegmentFile>| -> Result<Vec<u8>> {
                    if payload_len > MAX_METADATA_SECTION {
                        return Err(EwfError::Corrupt(format!("{} section of {} bytes is too large", desc.kind, payload_len)));
                    }
                    read_exact_at(&mut segs[idx].file, payload_off, payload_len)
                };
                match desc.kind.as_str() {
                    "header2" if !have_header2 => {
                        let text = format::decode_header_section(&payload(&mut segments)?)?;
                        header.parse_into(&text, true)?;
                        have_header2 = true;
                    }
                    "header" if !have_header => {
                        let text = format::decode_header_section(&payload(&mut segments)?)?;
                        header.parse_into(&text, false)?;
                        have_header = true;
                    }
                    "volume" | "disk" | "data" if volume.is_none() => {
                        volume = Some(VolumeInfo::parse(&payload(&mut segments)?)?);
                    }
                    "sectors" => {
                        last_sectors = Some((payload_off, section_end));
                        table_ok_in_group = false;
                    }
                    "table" | "table2" => {
                        if desc.kind == "table" || !table_ok_in_group {
                            let parsed = TableSection::parse(&payload(&mut segments)?);
                            match parsed {
                                Ok(t) => {
                                    let end = match last_sectors {
                                        Some((_, e)) => e,
                                        None => off,
                                    };
                                    add_table_chunks(&mut chunks, idx, &t, end, seg_len)?;
                                    table_ok_in_group = true;
                                }
                                // A damaged `table` is recoverable from its `table2` copy.
                                Err(e) if desc.kind == "table" => {
                                    let _ = e;
                                    table_ok_in_group = false;
                                }
                                Err(e) => return Err(e),
                            }
                        }
                        if desc.kind == "table2" {
                            if !table_ok_in_group {
                                return Err(EwfError::Corrupt("table and table2 both unusable".into()));
                            }
                            // The next group starts fresh.
                            table_ok_in_group = true;
                        }
                    }
                    "hash" => md5 = Some(format::parse_hash_section(&payload(&mut segments)?)?),
                    "digest" => {
                        let (m, s) = format::parse_digest_section(&payload(&mut segments)?)?;
                        md5 = Some(m);
                        if s.iter().any(|&b| b != 0) {
                            sha1 = Some(s);
                        }
                    }
                    "error2" => errors = format::parse_error2_section(&payload(&mut segments)?)?,
                    "done" => {
                        done = true;
                        ended = true;
                    }
                    "next" => ended = true,
                    _ => {}
                }
                if ended {
                    break;
                }
                if desc.next_offset <= off {
                    return Err(EwfError::Corrupt(format!("section chain does not advance at offset {}", off)));
                }
                off = desc.next_offset;
            }
            if !ended {
                return Err(EwfError::Corrupt("too many sections".into()));
            }
        }
        if !done {
            return Err(EwfError::MissingSegment("segment set ends without a done section".into()));
        }
        let volume = volume.ok_or_else(|| EwfError::Corrupt("no volume section".into()))?;
        let chunk_size = volume.chunk_size();
        let media_size = volume.media_size();
        let needed = media_size.div_ceil(chunk_size);
        if (chunks.len() as u64) < needed {
            return Err(EwfError::Corrupt(format!("image has {} chunks, media size needs {}", chunks.len(), needed)));
        }
        chunks.truncate(needed as usize);
        Ok(Self { segments, volume, header, chunks, md5, sha1, errors, position: 0, cache: None })
    }

    pub fn media_size(&self) -> u64 {
        self.volume.media_size()
    }
    pub fn volume(&self) -> &VolumeInfo {
        &self.volume
    }
    pub fn header(&self) -> &EwfHeader {
        &self.header
    }
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
    pub fn segment_paths(&self) -> Vec<PathBuf> {
        self.segments.iter().map(|s| s.path.clone()).collect()
    }
    /// MD5 recorded in the `hash` / `digest` section, lower-case hex.
    pub fn stored_md5(&self) -> Option<String> {
        self.md5.map(hex::encode)
    }
    /// SHA-1 recorded in the `digest` section, lower-case hex.
    pub fn stored_sha1(&self) -> Option<String> {
        self.sha1.map(hex::encode)
    }
    /// Bad-sector runs recorded in the `error2` section.
    pub fn acquisition_errors(&self) -> &[BadSectorRange] {
        &self.errors
    }

    pub fn info(&self) -> EwfInfo {
        EwfInfo {
            segments: self.segment_paths(),
            media_size: self.media_size(),
            volume: self.volume.clone(),
            header: self.header.clone(),
            chunk_count: self.chunks.len(),
            stored_md5: self.stored_md5(),
            stored_sha1: self.stored_sha1(),
            acquisition_errors: self.errors.clone(),
        }
    }

    fn expected_len(&self, idx: usize) -> u64 {
        let cs = self.volume.chunk_size();
        cs.min(self.media_size() - idx as u64 * cs)
    }

    /// Decode chunk `idx` into exactly its media length.
    pub fn read_chunk(&mut self, idx: usize) -> Result<Vec<u8>> {
        let loc = *self.chunks.get(idx).ok_or_else(|| EwfError::InvalidInput(format!("chunk {} out of range", idx)))?;
        let expected = self.expected_len(idx) as usize;
        let chunk_size = self.volume.chunk_size() as usize;
        let stored = read_exact_at(&mut self.segments[loc.segment].file, loc.offset, loc.size)?;
        let mut data = if loc.compressed {
            format::zlib_decompress(&stored, chunk_size)?
        } else if stored.len() >= expected + 4 {
            let (d, chk) = stored.split_at(stored.len() - 4);
            let stored_chk = format::u32_le(chk);
            let calc = format::adler32(d);
            if stored_chk != calc {
                return Err(EwfError::Checksum { what: format!("chunk {}", idx), stored: stored_chk, calculated: calc });
            }
            d.to_vec()
        } else {
            stored
        };
        if data.len() < expected {
            return Err(EwfError::Corrupt(format!("chunk {} holds {} bytes, expected {}", idx, data.len(), expected)));
        }
        data.truncate(expected);
        Ok(data)
    }

    /// Read media bytes at `offset` into `buf`; returns the number of bytes read (0 at the end).
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let size = self.media_size();
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let cs = self.volume.chunk_size();
        let mut done = 0usize;
        let mut pos = offset;
        while done < buf.len() && pos < size {
            let idx = (pos / cs) as usize;
            let within = (pos % cs) as usize;
            if self.cache.as_ref().map(|(i, _)| *i != idx).unwrap_or(true) {
                let data = self.read_chunk(idx)?;
                self.cache = Some((idx, data));
            }
            let data = match &self.cache {
                Some((_, d)) => d,
                None => return Err(EwfError::Corrupt("chunk cache empty".into())),
            };
            if within >= data.len() {
                return Err(EwfError::Corrupt(format!("offset {} outside chunk {}", pos, idx)));
            }
            let n = (data.len() - within).min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&data[within..within + n]);
            done += n;
            pos += n as u64;
        }
        Ok(done)
    }

    /// Re-hash the whole media and compare with the stored MD5 (and SHA-1 when present).
    pub fn verify(&mut self) -> Result<VerifyReport> {
        let mut h = MultiHasher::new();
        let mut s1 = sha1::Sha1::new();
        for idx in 0..self.chunks.len() {
            let data = self.read_chunk(idx)?;
            h.update(&data);
            s1.update(&data);
        }
        let computed = h.finalize();
        let computed_sha1 = hex::encode(s1.finalize());
        let stored_md5 = self.stored_md5();
        let stored_sha1 = self.stored_sha1();
        let md5_match = stored_md5.as_ref().map(|m| *m == computed.md5);
        let sha1_match = stored_sha1.as_ref().map(|s| *s == computed_sha1);
        let verified = md5_match == Some(true) && sha1_match != Some(false);
        Ok(VerifyReport { media_size: self.media_size(), computed, computed_sha1, stored_md5, stored_sha1, md5_match, sha1_match, verified })
    }
}

fn add_table_chunks(chunks: &mut Vec<ChunkLoc>, segment: usize, t: &TableSection, sectors_end: u64, seg_len: u64) -> Result<()> {
    let offsets: Vec<(u64, bool)> = t
        .entries
        .iter()
        .map(|e| {
            let rel = (*e & !format::COMPRESSED_FLAG) as u64;
            (t.base_offset.saturating_add(rel), *e & format::COMPRESSED_FLAG != 0)
        })
        .collect();
    for (i, &(start, compressed)) in offsets.iter().enumerate() {
        let end = match offsets.get(i + 1) {
            Some(&(next, _)) => next,
            None => sectors_end,
        };
        if end <= start || end > seg_len {
            return Err(EwfError::Corrupt(format!("chunk at offset {} has invalid extent ending at {}", start, end)));
        }
        let size = end - start;
        if size > format::MAX_CHUNK_SIZE * 2 {
            return Err(EwfError::Corrupt(format!("chunk at offset {} is {} bytes", start, size)));
        }
        chunks.push(ChunkLoc { segment, offset: start, size, compressed });
    }
    Ok(())
}

impl Read for EwfReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(self.position, buf)?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for EwfReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let size = self.media_size() as i128;
        let target = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => size + d as i128,
            SeekFrom::Current(d) => self.position as i128 + d as i128,
        };
        if target < 0 || target > u64::MAX as i128 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek out of range"));
        }
        self.position = target as u64;
        Ok(self.position)
    }
}
