//! Streaming AFF4 writer: one `aff4:ImageStream` behind a linear `aff4:Map`, described by an
//! `aff4:Image` / `aff4:DiskImage`, in a single ZIP64 volume.
//!
//! Chunks are compressed as they fill and appended to the open bevy member; the bevy's local
//! header is rewritten with its CRC-32 and size when the bevy closes, and its `.index` member
//! (12 bytes per chunk) follows it. The last chunk is zero-padded to the chunk size before
//! compression, as pyaff4 and Evimetry do; `aff4:size` records the true media length, so the
//! media is never padded. Hashes (MD5, SHA-1, SHA-256 as `aff4:hash` literals; SHA3-256 in the
//! summary) cover exactly the bytes passed to [`Aff4Writer::write`].
//!
//! Determinism: with [`Aff4Options::creation_time`] set, all timestamps come from it and every
//! URN is derived from it (and the case details) instead of random UUIDs, so identical input
//! produces an identical container byte for byte.

use crate::compress::Compression;
use crate::turtle::escape_literal;
use crate::zip::{dos_datetime, ZipWriter};
use crate::{
    Aff4Error, Result, AFF4, DEFAULT_CHUNKS_PER_SEGMENT, DEFAULT_CHUNK_SIZE,
    MAX_CHUNKS_PER_SEGMENT, MAX_CHUNK_SIZE, VERITAS,
};
use chrono::{DateTime, SecondsFormat, Utc};
use digest::Digest;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use veritas_hash::{Hashes, MultiHasher};

/// A run of unreadable sectors (zero-filled in the stream).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BadSectorRange {
    pub first_sector: u64,
    pub sector_count: u64,
}

/// Case metadata written to an `aff4:CaseDetails` resource.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseDetails {
    pub case_number: String,
    pub evidence_number: String,
    pub examiner: String,
    pub description: String,
    pub notes: String,
}

impl CaseDetails {
    pub fn is_empty(&self) -> bool {
        self.case_number.is_empty()
            && self.evidence_number.is_empty()
            && self.examiner.is_empty()
            && self.description.is_empty()
            && self.notes.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aff4Options {
    pub chunk_size: u32,
    pub chunks_per_segment: u32,
    pub compression: Compression,
    /// zlib level 0-9 for the deflate methods.
    pub level: u32,
    /// Sector size recorded as `aff4:blockSize` (and used for `aff4:sectorCount`).
    pub sector_size: u32,
    /// Fixed timestamp; also makes all URNs deterministic. `None`: now, random UUIDs.
    pub creation_time: Option<DateTime<Utc>>,
    /// `tool=` in version.txt and `aff4:tool`; defaults to `veritas-aff4 <version>`.
    pub tool: String,
    pub case: CaseDetails,
}

impl Default for Aff4Options {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            chunks_per_segment: DEFAULT_CHUNKS_PER_SEGMENT,
            compression: Compression::Deflate,
            level: 6,
            sector_size: 512,
            creation_time: None,
            tool: String::new(),
            case: CaseDetails::default(),
        }
    }
}

/// Result of a finished image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Aff4Summary {
    pub path: PathBuf,
    pub volume_urn: String,
    pub image_urn: String,
    pub map_urn: String,
    pub stream_urn: String,
    pub media_size: u64,
    pub chunk_size: u32,
    pub chunks_per_segment: u32,
    pub chunk_count: u64,
    pub bevy_count: u64,
    pub compression: Compression,
    pub compression_uri: String,
    /// MD5 / SHA-256 / SHA3-256 of the media.
    pub hashes: Hashes,
    pub sha1: String,
    pub bad_sectors: Vec<BadSectorRange>,
    /// Size of the .aff4 file.
    pub container_size: u64,
    pub creation_time: DateTime<Utc>,
}

/// Streaming AFF4 writer. Call [`write`](Self::write) with any buffer sizes, then
/// [`finish`](Self::finish).
pub struct Aff4Writer {
    path: PathBuf,
    opts: Aff4Options,
    zip: Option<ZipWriter<BufWriter<File>>>,
    created: DateTime<Utc>,
    volume_urn: String,
    image_urn: String,
    map_urn: String,
    stream_urn: String,
    case_urn: String,
    buf: Vec<u8>,
    hasher: MultiHasher,
    sha1: sha1::Sha1,
    input_bytes: u64,
    chunk_count: u64,
    bevy_count: u64,
    bevy_index: Vec<u8>,
    bevy_chunks: u32,
    bevy_len: u64,
    bad_sectors: Vec<BadSectorRange>,
}

/// AFF4 v1.0 member name for a URN (the `aff4://` prefix escaped, as Evimetry and pyaff4 do).
pub fn member_name(urn: &str) -> String {
    let rest = urn.strip_prefix("aff4://").unwrap_or(urn);
    let mut out = String::from("aff4%3A%2F%2F");
    for c in rest.chars() {
        if c.is_ascii_graphic() && c != '%' {
            out.push(c);
        } else {
            let mut b = [0u8; 4];
            for byte in c.encode_utf8(&mut b).bytes() {
                out.push_str(&format!("%{:02x}", byte));
            }
        }
    }
    out
}

fn derived_urn(seed: &[u8], label: &str) -> String {
    let mut h = sha2::Sha256::new();
    h.update(b"veritas-aff4\0");
    h.update(seed);
    h.update(label.as_bytes());
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0F) | 0x80; // UUID version 8 (custom)
    b[8] = (b[8] & 0x3F) | 0x80;
    format!("aff4://{}", uuid::Uuid::from_bytes(b))
}

fn random_urn() -> String {
    format!("aff4://{}", uuid::Uuid::new_v4())
}

impl Aff4Writer {
    /// Create `path` (never overwritten) and write the volume header members.
    pub fn create(path: impl AsRef<Path>, mut opts: Aff4Options) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if opts.chunk_size < 512 || opts.chunk_size > MAX_CHUNK_SIZE {
            return Err(Aff4Error::InvalidInput(format!(
                "chunk size must be between 512 and {} bytes",
                MAX_CHUNK_SIZE
            )));
        }
        if opts.chunks_per_segment == 0 || opts.chunks_per_segment > MAX_CHUNKS_PER_SEGMENT {
            return Err(Aff4Error::InvalidInput(format!(
                "chunks per segment must be between 1 and {}",
                MAX_CHUNKS_PER_SEGMENT
            )));
        }
        if !opts.compression.can_write() {
            return Err(Aff4Error::Unsupported(format!(
                "writing {:?} image streams",
                opts.compression
            )));
        }
        if opts.sector_size == 0 || !opts.sector_size.is_power_of_two() {
            return Err(Aff4Error::InvalidInput(
                "sector size must be a power of two".into(),
            ));
        }
        if opts.tool.is_empty() {
            opts.tool = format!("veritas-aff4 {}", env!("CARGO_PKG_VERSION"));
        }
        let created = opts.creation_time.unwrap_or_else(Utc::now);
        let (volume_urn, image_urn, map_urn, stream_urn, case_urn) = match opts.creation_time {
            Some(t) => {
                let seed = format!(
                    "{}\0{}\0{}\0{}",
                    t.to_rfc3339_opts(SecondsFormat::Nanos, true),
                    opts.case.case_number,
                    opts.case.evidence_number,
                    opts.case.description
                );
                let s = seed.as_bytes();
                (
                    derived_urn(s, "volume"),
                    derived_urn(s, "image"),
                    derived_urn(s, "map"),
                    derived_urn(s, "stream"),
                    derived_urn(s, "case"),
                )
            }
            None => (
                random_urn(),
                random_urn(),
                random_urn(),
                random_urn(),
                random_urn(),
            ),
        };
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Aff4Error::Exists(path.display().to_string())
                } else {
                    Aff4Error::Io(e)
                }
            })?;
        let mut zip = ZipWriter::new(
            BufWriter::with_capacity(1 << 20, file),
            dos_datetime(&created),
        );
        zip.add_stored("container.description", volume_urn.as_bytes())?;
        let version = format!(
            "major=1\nminor=0\ntool={}\n",
            opts.tool.replace(['\r', '\n'], " ")
        );
        zip.add_stored("version.txt", version.as_bytes())?;
        let chunk_size = opts.chunk_size as usize;
        Ok(Self {
            path,
            zip: Some(zip),
            created,
            volume_urn,
            image_urn,
            map_urn,
            stream_urn,
            case_urn,
            buf: Vec::with_capacity(chunk_size),
            hasher: MultiHasher::new(),
            sha1: sha1::Sha1::new(),
            input_bytes: 0,
            chunk_count: 0,
            bevy_count: 0,
            bevy_index: Vec::new(),
            bevy_chunks: 0,
            bevy_len: 0,
            bad_sectors: Vec::new(),
            opts,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bytes accepted so far.
    pub fn bytes_written(&self) -> u64 {
        self.input_bytes
    }

    /// Bytes of container written so far (approximate while a bevy is open).
    pub fn container_bytes(&self) -> u64 {
        self.zip.as_ref().map(|z| z.position()).unwrap_or(0)
    }

    /// Record a run of unreadable sectors (already zero-filled by the caller); adjacent and
    /// overlapping runs are merged. Written as `veritas:badSectors` on the image.
    pub fn record_bad_sectors(&mut self, first_sector: u64, sector_count: u64) {
        if sector_count == 0 {
            return;
        }
        if let Some(last) = self.bad_sectors.last_mut() {
            let end = last.first_sector + last.sector_count;
            if first_sector >= last.first_sector && first_sector <= end {
                last.sector_count = (first_sector + sector_count).max(end) - last.first_sector;
                return;
            }
        }
        self.bad_sectors.push(BadSectorRange {
            first_sector,
            sector_count,
        });
    }

    /// Append media bytes.
    pub fn write(&mut self, mut data: &[u8]) -> Result<()> {
        if self.zip.is_none() {
            return Err(Aff4Error::InvalidInput("writer is closed".into()));
        }
        self.hasher.update(data);
        self.sha1.update(data);
        self.input_bytes += data.len() as u64;
        let cs = self.opts.chunk_size as usize;
        while !data.is_empty() {
            let take = (cs - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == cs {
                let chunk = std::mem::replace(&mut self.buf, Vec::with_capacity(cs));
                self.emit_chunk(&chunk)?;
            }
        }
        Ok(())
    }

    fn bevy_name(&self, n: u64) -> String {
        format!("{}/{:08}", member_name(&self.stream_urn), n)
    }

    fn emit_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        let stored = self.opts.compression.encode(chunk, self.opts.level)?;
        let name = self.bevy_name(self.bevy_count);
        let zip = self
            .zip
            .as_mut()
            .ok_or_else(|| Aff4Error::InvalidInput("writer is closed".into()))?;
        if !zip.is_open() {
            zip.begin(&name)?;
            self.bevy_len = 0;
            self.bevy_chunks = 0;
            self.bevy_index.clear();
        }
        zip.write_open(&stored)?;
        self.bevy_index
            .extend_from_slice(&self.bevy_len.to_le_bytes());
        self.bevy_index
            .extend_from_slice(&(stored.len() as u32).to_le_bytes());
        self.bevy_len += stored.len() as u64;
        self.bevy_chunks += 1;
        self.chunk_count += 1;
        if self.bevy_chunks >= self.opts.chunks_per_segment {
            self.close_bevy()?;
        }
        Ok(())
    }

    fn close_bevy(&mut self) -> Result<()> {
        let name = format!("{}.index", self.bevy_name(self.bevy_count));
        let zip = self
            .zip
            .as_mut()
            .ok_or_else(|| Aff4Error::InvalidInput("writer is closed".into()))?;
        if !zip.is_open() {
            return Ok(());
        }
        zip.end()?;
        zip.add_stored(&name, &self.bevy_index)?;
        self.bevy_index.clear();
        self.bevy_chunks = 0;
        self.bevy_count += 1;
        Ok(())
    }

    fn turtle(&self, md5: &str, sha1: &str, sha256: &str) -> String {
        let size = self.input_bytes;
        let t = self.created.to_rfc3339_opts(SecondsFormat::Millis, true);
        let ss = self.opts.sector_size as u64;
        let mut s = String::new();
        s.push_str("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n");
        s.push_str("@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n");
        s.push_str(&format!("@prefix aff4: <{}> .\n", AFF4));
        s.push_str(&format!("@prefix veritas: <{}> .\n\n", VERITAS));

        let has_case = !self.opts.case.is_empty();
        s.push_str(&format!("<{}>\n    a aff4:ZipVolume ;\n", self.volume_urn));
        s.push_str(&format!(
            "    aff4:contains <{}>, <{}>, <{}>{} ;\n",
            self.image_urn,
            self.map_urn,
            self.stream_urn,
            if has_case {
                format!(", <{}>", self.case_urn)
            } else {
                String::new()
            }
        ));
        s.push_str(&format!(
            "    aff4:creationTime \"{}\"^^xsd:dateTime ;\n",
            t
        ));
        s.push_str(&format!(
            "    aff4:tool \"{}\" .\n\n",
            escape_literal(&self.opts.tool)
        ));

        s.push_str(&format!(
            "<{}>\n    a aff4:Image, aff4:DiskImage, aff4:ContiguousImage ;\n",
            self.image_urn
        ));
        s.push_str("    aff4:acquisitionCompletionState aff4:Completed ;\n");
        s.push_str(&format!("    aff4:blockSize \"{}\"^^xsd:int ;\n", ss));
        s.push_str(&format!(
            "    aff4:sectorCount \"{}\"^^xsd:long ;\n",
            size.div_ceil(ss)
        ));
        s.push_str(&format!("    aff4:size \"{}\"^^xsd:long ;\n", size));
        s.push_str(&format!("    aff4:dataStream <{}> ;\n", self.map_urn));
        s.push_str(&format!(
            "    aff4:hash \"{}\"^^aff4:MD5, \"{}\"^^aff4:SHA1, \"{}\"^^aff4:SHA256 ;\n",
            md5, sha1, sha256
        ));
        if !self.bad_sectors.is_empty() {
            let runs: Vec<String> = self
                .bad_sectors
                .iter()
                .map(|b| format!("\"{}+{}\"", b.first_sector, b.sector_count))
                .collect();
            s.push_str(&format!("    veritas:badSectors {} ;\n", runs.join(", ")));
        }
        s.push_str(&format!("    aff4:stored <{}> .\n\n", self.volume_urn));

        s.push_str(&format!("<{}>\n    a aff4:Map ;\n", self.map_urn));
        s.push_str(&format!(
            "    aff4:dependentStream <{}> ;\n",
            self.stream_urn
        ));
        s.push_str("    aff4:mapGapDefaultStream aff4:Zero ;\n");
        s.push_str(&format!("    aff4:size \"{}\"^^xsd:long ;\n", size));
        s.push_str(&format!("    aff4:stored <{}> ;\n", self.volume_urn));
        s.push_str(&format!("    aff4:target <{}> .\n\n", self.image_urn));

        s.push_str(&format!(
            "<{}>\n    a aff4:ImageStream ;\n",
            self.stream_urn
        ));
        s.push_str(&format!(
            "    aff4:chunkSize \"{}\"^^xsd:int ;\n",
            self.opts.chunk_size
        ));
        s.push_str(&format!(
            "    aff4:chunksInSegment \"{}\"^^xsd:int ;\n",
            self.opts.chunks_per_segment
        ));
        s.push_str(&format!(
            "    aff4:compressionMethod <{}> ;\n",
            self.opts.compression.uri()
        ));
        s.push_str(&format!("    aff4:size \"{}\"^^xsd:long ;\n", size));
        s.push_str(&format!("    aff4:stored <{}> ;\n", self.volume_urn));
        s.push_str(&format!("    aff4:target <{}> ;\n", self.image_urn));
        s.push_str("    aff4:version \"1\"^^xsd:int .\n");

        if has_case {
            let c = &self.opts.case;
            s.push_str(&format!(
                "\n<{}>\n    a aff4:CaseDetails ;\n",
                self.case_urn
            ));
            for (p, v) in [
                ("caseName", &c.case_number),
                ("evidenceNumber", &c.evidence_number),
                ("examiner", &c.examiner),
                ("caseDescription", &c.description),
                ("notes", &c.notes),
            ] {
                if !v.is_empty() {
                    s.push_str(&format!("    aff4:{} \"{}\" ;\n", p, escape_literal(v)));
                }
            }
            s.push_str(&format!("    aff4:target <{}> .\n", self.image_urn));
        }
        s
    }

    /// Flush the last chunk and write the map, metadata and central directory.
    pub fn finish(mut self) -> Result<Aff4Summary> {
        if !self.buf.is_empty() {
            let mut chunk = std::mem::take(&mut self.buf);
            chunk.resize(self.opts.chunk_size as usize, 0);
            self.emit_chunk(&chunk)?;
        }
        self.close_bevy()?;
        let hashes = std::mem::take(&mut self.hasher).finalize();
        let sha1 = hex::encode(std::mem::replace(&mut self.sha1, sha1::Sha1::new()).finalize());
        let turtle = self.turtle(&hashes.md5, &sha1, &hashes.sha256);
        let mut map = Vec::with_capacity(28);
        if self.input_bytes > 0 {
            map.extend_from_slice(&0u64.to_le_bytes());
            map.extend_from_slice(&self.input_bytes.to_le_bytes());
            map.extend_from_slice(&0u64.to_le_bytes());
            map.extend_from_slice(&0u32.to_le_bytes());
        }
        let mut zip = self
            .zip
            .take()
            .ok_or_else(|| Aff4Error::InvalidInput("writer is closed".into()))?;
        let map_member = member_name(&self.map_urn);
        zip.add_stored(&format!("{}/map", map_member), &map)?;
        zip.add_stored(&format!("{}/idx", map_member), self.stream_urn.as_bytes())?;
        zip.add_stored("information.turtle", turtle.as_bytes())?;
        let w = zip.finish(self.volume_urn.as_bytes())?;
        let file = w.into_inner().map_err(|e| Aff4Error::Io(e.into_error()))?;
        file.sync_all()?;
        let container_size = file.metadata()?.len();
        Ok(Aff4Summary {
            path: self.path.clone(),
            volume_urn: self.volume_urn.clone(),
            image_urn: self.image_urn.clone(),
            map_urn: self.map_urn.clone(),
            stream_urn: self.stream_urn.clone(),
            media_size: self.input_bytes,
            chunk_size: self.opts.chunk_size,
            chunks_per_segment: self.opts.chunks_per_segment,
            chunk_count: self.chunk_count,
            bevy_count: self.bevy_count,
            compression: self.opts.compression,
            compression_uri: self.opts.compression.uri().to_string(),
            hashes,
            sha1,
            bad_sectors: self.bad_sectors.clone(),
            container_size,
            creation_time: self.created,
        })
    }
}
