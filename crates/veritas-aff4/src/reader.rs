//! AFF4 reader: ZIP64 volume, Turtle metadata, `aff4:Map` and `aff4:ImageStream` resolution,
//! random access and verification.

use crate::compress::Compression;
use crate::turtle::{self, Graph, Term};
use crate::writer::{BadSectorRange, CaseDetails};
use crate::zip::{ReadSeek, ZipArchive, METHOD_STORED};
use crate::{
    Aff4Error, Result, AFF4, AFF4_LEGACY, MAX_CHUNKS_PER_SEGMENT, MAX_CHUNK_SIZE, RDF_TYPE, VERITAS,
};
use digest::Digest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use veritas_hash::{Hashes, MultiHasher};

/// Largest `information.turtle` accepted.
pub const MAX_TURTLE: u64 = 64 * 1024 * 1024;
/// Largest `version.txt` / `container.description` / map `idx` member accepted.
pub const MAX_SMALL_MEMBER: u64 = 16 * 1024 * 1024;
/// Largest map member accepted (28 bytes per range).
pub const MAX_MAP_MEMBER: u64 = 28 * (1 << 22);
/// Bevy indexes kept in memory at once.
const INDEX_CACHE: usize = 64;
/// Size of the tile pyaff4 repeats for `aff4:UnknownData` / `aff4:UnreadableData`.
const SYMBOLIC_TILE: u64 = 1 << 20;

fn aff4(term: &str) -> String {
    format!("{}{}", AFF4, term)
}

/// An `aff4:hash` value found in the metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredHash {
    /// `md5`, `sha1`, `sha256`, `sha512` or `blake2b`.
    pub algorithm: String,
    /// Lower-case hex.
    pub value: String,
    /// Resource the hash is attached to.
    pub subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamInfo {
    pub urn: String,
    pub size: u64,
    pub chunk_size: u32,
    pub chunks_per_segment: u32,
    pub compression: Compression,
    pub compression_uri: String,
    pub bevy_count: u64,
}

/// Summary for display (`aff4-tool info`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aff4Info {
    pub volume_urn: String,
    pub version: Option<String>,
    pub tool: Option<String>,
    pub image_urn: Option<String>,
    pub image_types: Vec<String>,
    pub data_stream_urn: String,
    /// `map` or `image_stream`.
    pub layout: String,
    pub media_size: u64,
    pub map_ranges: usize,
    pub map_targets: Vec<String>,
    pub streams: Vec<StreamInfo>,
    pub stored_hashes: Vec<StoredHash>,
    pub acquisition_errors: Vec<BadSectorRange>,
    pub case: CaseDetails,
    pub creation_time: Option<String>,
    pub images: Vec<String>,
    pub zip_members: usize,
    pub triples: usize,
}

/// Result of [`Aff4Reader::verify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    pub media_size: u64,
    pub computed: Hashes,
    pub computed_sha1: String,
    pub computed_sha512: String,
    pub stored: Vec<StoredHash>,
    pub md5_match: Option<bool>,
    pub sha1_match: Option<bool>,
    pub sha256_match: Option<bool>,
    pub sha512_match: Option<bool>,
    /// Hash algorithms present in the metadata that are not checked (e.g. blake2b).
    pub unchecked: Vec<String>,
    /// ZIP members whose CRC-32 does not match their data.
    pub crc_errors: Vec<String>,
    /// True when at least one stored hash was checked, all checked hashes match and every ZIP
    /// member's CRC-32 is correct.
    pub verified: bool,
}

#[derive(Debug, Clone)]
enum Target {
    Zero,
    /// Repeated tile (`aff4:UnknownData`, `aff4:UnreadableData`, `aff4:SymbolicStreamXX`).
    Pattern(Vec<u8>),
    /// A stored ZIP member read directly.
    Member(usize),
    Stream(usize),
}

#[derive(Debug, Clone, Copy)]
struct Range {
    map_offset: u64,
    length: u64,
    target_offset: u64,
    target: usize,
}

struct StreamState {
    info: StreamInfo,
    /// ZIP member of each bevy and of its index.
    bevies: Vec<(usize, usize)>,
    indexes: HashMap<u64, Vec<(u64, u32)>>,
}

enum Layout {
    Direct(Target),
    Map {
        ranges: Vec<Range>,
        targets: Vec<Target>,
        target_urns: Vec<String>,
        gap: Target,
    },
}

/// Random-access reader over the media of an AFF4 image. Implements [`Read`] and [`Seek`].
pub struct Aff4Reader {
    zip: ZipArchive,
    graph: Graph,
    volume_urn: String,
    version: Option<String>,
    tool: Option<String>,
    image_urn: Option<String>,
    data_stream_urn: String,
    media_size: u64,
    streams: Vec<StreamState>,
    layout: Layout,
    hashes: Vec<StoredHash>,
    bad_sectors: Vec<BadSectorRange>,
    case: CaseDetails,
    images: Vec<String>,
    position: u64,
    cache: Option<(usize, u64, Vec<u8>)>,
}

impl std::fmt::Debug for Aff4Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aff4Reader")
            .field("volume_urn", &self.volume_urn)
            .field("data_stream_urn", &self.data_stream_urn)
            .field("media_size", &self.media_size)
            .finish()
    }
}

/// URN a ZIP member name stands for (AFF4 v1.0: `%xx` escaped, relative to the volume).
fn urn_for_member(name: &str, volume_urn: &str) -> String {
    let bytes = name.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hexval = |b: u8| (b as char).to_digit(16);
            if let (Some(h), Some(l)) = (hexval(bytes[i + 1]), hexval(bytes[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    let s = String::from_utf8_lossy(&out).into_owned();
    if s.starts_with("aff4:") {
        s
    } else {
        format!("{}/{}", volume_urn.trim_end_matches('/'), s)
    }
}

fn symbolic(urn: &str) -> Option<Target> {
    let tile = |s: &[u8]| Target::Pattern(s.to_vec());
    let rest = urn.strip_prefix(AFF4)?;
    match rest {
        "Zero" => return Some(Target::Zero),
        "UnknownData" => return Some(tile(b"UNKNOWN")),
        "UnreadableData" => return Some(tile(b"UNREADABLEDATA")),
        _ => {}
    }
    let hex = rest.strip_prefix("SymbolicStream").unwrap_or(rest);
    if hex.len() == 2 {
        if let Ok(v) = u8::from_str_radix(hex, 16) {
            return Some(if v == 0 { Target::Zero } else { tile(&[v]) });
        }
    }
    None
}

fn hash_algorithm(datatype: &str) -> Option<&'static str> {
    match datatype.strip_prefix(AFF4)? {
        "MD5" => Some("md5"),
        "SHA1" => Some("sha1"),
        "SHA256" => Some("sha256"),
        "SHA512" => Some("sha512"),
        "Blake2b" => Some("blake2b"),
        _ => None,
    }
}

impl Aff4Reader {
    /// Open an `.aff4` file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let f = std::fs::File::open(path.as_ref())?;
        Self::from_reader(Box::new(f))
    }

    /// Open from any seekable byte source (used by fuzzing and in-memory tests).
    pub fn from_reader(src: Box<dyn ReadSeek>) -> Result<Self> {
        let mut zip = ZipArchive::new(src)?;
        let turtle_idx = zip.find("information.turtle").ok_or_else(|| {
            Aff4Error::NotAff4("ZIP archive has no information.turtle member".into())
        })?;
        let version = match zip.find("version.txt") {
            Some(i) => {
                Some(String::from_utf8_lossy(&zip.read_member(i, MAX_SMALL_MEMBER)?).into_owned())
            }
            None => None,
        };
        if let Some(v) = &version {
            let major = v
                .lines()
                .find_map(|l| l.trim().strip_prefix("major="))
                .map(|s| s.trim().to_string());
            if let Some(m) = major {
                if m != "1" {
                    return Err(Aff4Error::Unsupported(format!("AFF4 version major={}", m)));
                }
            }
        }
        let mut volume_urn = match zip.find("container.description") {
            Some(i) => String::from_utf8_lossy(&zip.read_member(i, MAX_SMALL_MEMBER)?)
                .trim()
                .to_string(),
            None => String::new(),
        };
        if volume_urn.is_empty() {
            volume_urn = String::from_utf8_lossy(zip.comment())
                .trim_end_matches('\0')
                .trim()
                .to_string();
        }
        let ttl = zip.read_member(turtle_idx, MAX_TURTLE)?;
        let graph = turtle::parse(&String::from_utf8_lossy(&ttl))?;

        // Member URN -> member index.
        let mut members: HashMap<String, usize> = HashMap::new();
        for (i, e) in zip.entries().iter().enumerate() {
            members.insert(urn_for_member(&e.name, &volume_urn), i);
            if e.name.starts_with("aff4:") {
                members.insert(e.name.clone(), i);
            }
        }

        if !graph.subjects_of_type(&aff4("EncryptedStream")).is_empty() {
            return Err(Aff4Error::Unsupported(
                "encrypted AFF4 (aff4:EncryptedStream)".into(),
            ));
        }
        let legacy = graph
            .triples
            .iter()
            .any(|t| t.p.starts_with(AFF4_LEGACY) || t.o.lexical().starts_with(AFF4_LEGACY));

        let mut images: Vec<String> = Vec::new();
        for ty in [
            "Image",
            "DiskImage",
            "ContiguousImage",
            "DiscontiguousImage",
            "VolumeImage",
        ] {
            for s in graph.subjects_of_type(&aff4(ty)) {
                if !images.contains(&s) {
                    images.push(s);
                }
            }
        }
        let ds_pred = aff4("dataStream");
        let mut image_urn = None;
        let mut data_stream = None;
        for img in &images {
            if let Some(ds) = graph.object(img, &ds_pred).and_then(|t| t.as_iri()) {
                image_urn = Some(img.clone());
                data_stream = Some(ds.to_string());
                break;
            }
        }
        if data_stream.is_none() {
            data_stream = graph
                .subjects_of_type(&aff4("Map"))
                .into_iter()
                .next()
                .or_else(|| {
                    graph
                        .subjects_of_type(&aff4("ImageStream"))
                        .into_iter()
                        .next()
                });
        }
        let data_stream_urn = match data_stream {
            Some(d) => d,
            None => {
                if !graph.subjects_of_type(&aff4("FileImage")).is_empty() {
                    return Err(Aff4Error::Unsupported(
                        "AFF4 Logical containers (aff4:FileImage)".into(),
                    ));
                }
                if legacy {
                    return Err(Aff4Error::Unsupported(
                        "pre-standard AFF4 (http://afflib.org/2009/aff4#)".into(),
                    ));
                }
                return Err(Aff4Error::NotAff4(
                    "no aff4:Image, aff4:Map or aff4:ImageStream in information.turtle".into(),
                ));
            }
        };

        let mut r = Self {
            zip,
            volume_urn,
            version,
            tool: None,
            image_urn,
            data_stream_urn: data_stream_urn.clone(),
            media_size: 0,
            streams: Vec::new(),
            layout: Layout::Direct(Target::Zero),
            hashes: Vec::new(),
            bad_sectors: Vec::new(),
            case: CaseDetails::default(),
            images,
            position: 0,
            cache: None,
            graph,
        };
        r.tool = r
            .graph
            .object(&r.volume_urn, &aff4("tool"))
            .map(|t| t.lexical().to_string());

        if r.graph.has_type(&data_stream_urn, &aff4("Map")) {
            r.load_map(&data_stream_urn, &members)?;
        } else {
            let t = r.resolve_target(&data_stream_urn, &members)?;
            r.media_size = match &t {
                Target::Stream(i) => r.streams[*i].info.size,
                Target::Member(i) => r.zip.entry(*i)?.size,
                _ => {
                    return Err(Aff4Error::Corrupt(
                        "image data stream is a symbolic stream".into(),
                    ))
                }
            };
            r.layout = Layout::Direct(t);
        }

        // Hashes on the image and on its data stream (both describe the media bytes).
        let mut subjects = Vec::new();
        if let Some(i) = &r.image_urn {
            subjects.push(i.clone());
        }
        subjects.push(data_stream_urn.clone());
        for s in subjects {
            for t in r.graph.objects(&s, &aff4("hash")) {
                if let Some(l) = t.as_literal() {
                    if let Some(alg) = l.datatype.as_deref().and_then(hash_algorithm) {
                        let h = StoredHash {
                            algorithm: alg.to_string(),
                            value: l.value.trim().to_ascii_lowercase(),
                            subject: s.clone(),
                        };
                        if !r.hashes.contains(&h) {
                            r.hashes.push(h);
                        }
                    }
                }
            }
        }
        if let Some(img) = r.image_urn.clone() {
            for t in r.graph.objects(&img, &format!("{}badSectors", VERITAS)) {
                if let Some((a, b)) = t.lexical().split_once('+') {
                    if let (Ok(first_sector), Ok(sector_count)) =
                        (a.trim().parse::<u64>(), b.trim().parse::<u64>())
                    {
                        r.bad_sectors.push(BadSectorRange {
                            first_sector,
                            sector_count,
                        });
                    }
                }
            }
            for cd in r.graph.subjects_of_type(&aff4("CaseDetails")) {
                let targets = r.graph.objects(&cd, &aff4("target"));
                if !targets.is_empty() && !targets.iter().any(|t| t.as_iri() == Some(&img)) {
                    continue;
                }
                let get = |p: &str| {
                    r.graph
                        .object(&cd, &aff4(p))
                        .map(|t| t.lexical().to_string())
                        .unwrap_or_default()
                };
                r.case = CaseDetails {
                    case_number: get("caseName"),
                    evidence_number: get("evidenceNumber"),
                    examiner: get("examiner"),
                    description: get("caseDescription"),
                    notes: get("notes"),
                };
                break;
            }
        }
        Ok(r)
    }

    fn resolve_target(&mut self, urn: &str, members: &HashMap<String, usize>) -> Result<Target> {
        if let Some(t) = symbolic(urn) {
            return Ok(t);
        }
        if self.graph.has_type(urn, &aff4("ImageStream")) {
            if let Some(i) = self.streams.iter().position(|s| s.info.urn == urn) {
                return Ok(Target::Stream(i));
            }
            let st = self.load_stream(urn, members)?;
            self.streams.push(st);
            return Ok(Target::Stream(self.streams.len() - 1));
        }
        if self.graph.has_type(urn, &aff4("Map")) {
            return Err(Aff4Error::Unsupported(format!(
                "map {} targets another map",
                urn
            )));
        }
        if self.graph.has_type(urn, &aff4("EncryptedStream")) {
            return Err(Aff4Error::Unsupported("encrypted AFF4 streams".into()));
        }
        if let Some(&i) = members.get(urn) {
            if self.zip.entry(i)?.method != METHOD_STORED {
                return Err(Aff4Error::Unsupported(format!(
                    "compressed ZIP segment {} as a map target",
                    urn
                )));
            }
            return Ok(Target::Member(i));
        }
        let legacy = self
            .graph
            .objects(urn, RDF_TYPE)
            .iter()
            .any(|t| t.lexical().starts_with(AFF4_LEGACY));
        if legacy {
            return Err(Aff4Error::Unsupported(
                "pre-standard AFF4 (http://afflib.org/2009/aff4#) streams".into(),
            ));
        }
        Err(Aff4Error::Corrupt(format!(
            "stream {} cannot be resolved",
            urn
        )))
    }

    fn load_stream(&mut self, urn: &str, members: &HashMap<String, usize>) -> Result<StreamState> {
        let g = &self.graph;
        let size = g
            .object(urn, &aff4("size"))
            .and_then(Term::as_u64)
            .ok_or_else(|| Aff4Error::Corrupt(format!("image stream {} has no aff4:size", urn)))?;
        let chunk_size = match g.object(urn, &aff4("chunkSize")) {
            Some(t) => t
                .as_u64()
                .ok_or_else(|| Aff4Error::Corrupt("bad aff4:chunkSize".into()))?,
            None => 32 * 1024,
        };
        let cis = match g.object(urn, &aff4("chunksInSegment")) {
            Some(t) => t
                .as_u64()
                .ok_or_else(|| Aff4Error::Corrupt("bad aff4:chunksInSegment".into()))?,
            None => 1024,
        };
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE as u64 {
            return Err(Aff4Error::Limit(format!("chunk size {}", chunk_size)));
        }
        if cis == 0 || cis > MAX_CHUNKS_PER_SEGMENT as u64 {
            return Err(Aff4Error::Limit(format!("chunks in segment {}", cis)));
        }
        let uri = g
            .object(urn, &aff4("compressionMethod"))
            .map(|t| t.lexical().to_string())
            .unwrap_or_else(|| crate::compress::URI_ZLIB.to_string());
        let compression = Compression::from_uri(&uri)
            .ok_or_else(|| Aff4Error::Unsupported(format!("compression method {}", uri)))?;
        let chunks = size.div_ceil(chunk_size);
        let bevy_count = chunks.div_ceil(cis);
        if bevy_count > crate::zip::MAX_ENTRIES {
            return Err(Aff4Error::Corrupt(format!(
                "stream {} would need {} bevies",
                urn, bevy_count
            )));
        }
        let mut bevies = Vec::with_capacity(bevy_count as usize);
        for n in 0..bevy_count {
            let bevy_urn = format!("{}/{:08}", urn, n);
            let bevy = *members
                .get(&bevy_urn)
                .ok_or_else(|| Aff4Error::Corrupt(format!("bevy {} of {} is missing", n, urn)))?;
            let index = *members.get(&format!("{}.index", bevy_urn)).ok_or_else(|| {
                Aff4Error::Corrupt(format!("index of bevy {} of {} is missing", n, urn))
            })?;
            if self.zip.entry(bevy)?.method != METHOD_STORED {
                return Err(Aff4Error::Unsupported(format!(
                    "compressed ZIP member for bevy {} of {}",
                    n, urn
                )));
            }
            bevies.push((bevy, index));
        }
        Ok(StreamState {
            info: StreamInfo {
                urn: urn.to_string(),
                size,
                chunk_size: chunk_size as u32,
                chunks_per_segment: cis as u32,
                compression,
                compression_uri: uri,
                bevy_count,
            },
            bevies,
            indexes: HashMap::new(),
        })
    }

    fn load_map(&mut self, urn: &str, members: &HashMap<String, usize>) -> Result<()> {
        let idx_member = *members
            .get(&format!("{}/idx", urn))
            .ok_or_else(|| Aff4Error::Corrupt(format!("map {} has no idx member", urn)))?;
        let map_member = *members
            .get(&format!("{}/map", urn))
            .ok_or_else(|| Aff4Error::Corrupt(format!("map {} has no map member", urn)))?;
        let idx = self.zip.read_member(idx_member, MAX_SMALL_MEMBER)?;
        let idx = String::from_utf8_lossy(&idx).into_owned();
        let target_urns: Vec<String> = idx
            .split('\n')
            .map(|l| l.trim_end_matches('\r').trim().to_string())
            .collect();
        let raw = self.zip.read_member(map_member, MAX_MAP_MEMBER)?;
        if raw.len() % 28 != 0 {
            return Err(Aff4Error::Corrupt(format!(
                "map {} is {} bytes, not a multiple of 28",
                urn,
                raw.len()
            )));
        }
        let mut ranges = Vec::with_capacity(raw.len() / 28);
        let mut used: Vec<Option<usize>> = vec![None; target_urns.len()];
        let mut targets: Vec<Target> = Vec::new();
        let mut target_names: Vec<String> = Vec::new();
        for k in 0..raw.len() / 28 {
            let rec = &raw[k * 28..k * 28 + 28];
            let u64_at = |o: usize| {
                let mut a = [0u8; 8];
                a.copy_from_slice(&rec[o..o + 8]);
                u64::from_le_bytes(a)
            };
            let map_offset = u64_at(0);
            let length = u64_at(8);
            let target_offset = u64_at(16);
            let tid = u32::from_le_bytes([rec[24], rec[25], rec[26], rec[27]]) as usize;
            if length == 0 {
                continue;
            }
            map_offset
                .checked_add(length)
                .ok_or_else(|| Aff4Error::Corrupt("map range overflows".into()))?;
            target_offset
                .checked_add(length)
                .ok_or_else(|| Aff4Error::Corrupt("map target range overflows".into()))?;
            let slot = used.get_mut(tid).ok_or_else(|| {
                Aff4Error::Corrupt(format!(
                    "map range refers to target {} of {}",
                    tid,
                    target_urns.len()
                ))
            })?;
            let target = match *slot {
                Some(t) => t,
                None => {
                    let name = target_urns[tid].clone();
                    if name.is_empty() {
                        return Err(Aff4Error::Corrupt("map target name is empty".into()));
                    }
                    let t = self.resolve_target(&name, members)?;
                    targets.push(t);
                    target_names.push(name);
                    *slot = Some(targets.len() - 1);
                    targets.len() - 1
                }
            };
            ranges.push(Range {
                map_offset,
                length,
                target_offset,
                target,
            });
        }
        ranges.sort_by_key(|r| r.map_offset);
        // Clip overlaps (a later-starting range wins) and merge contiguous pieces.
        let mut clean: Vec<Range> = Vec::with_capacity(ranges.len());
        for i in 0..ranges.len() {
            let mut r = ranges[i];
            if let Some(next) = ranges.get(i + 1) {
                if r.map_offset + r.length > next.map_offset {
                    r.length = next.map_offset - r.map_offset;
                }
            }
            if r.length == 0 {
                continue;
            }
            if let Some(last) = clean.last_mut() {
                if last.target == r.target
                    && last.map_offset + last.length == r.map_offset
                    && last.target_offset + last.length == r.target_offset
                {
                    last.length += r.length;
                    continue;
                }
            }
            clean.push(r);
        }
        let mapped_end = clean.last().map(|r| r.map_offset + r.length).unwrap_or(0);
        let declared = self
            .graph
            .object(urn, &aff4("size"))
            .and_then(Term::as_u64)
            .or_else(|| {
                self.image_urn
                    .as_ref()
                    .and_then(|i| self.graph.object(i, &aff4("size")))
                    .and_then(Term::as_u64)
            });
        let size = declared.unwrap_or(mapped_end);
        if size < mapped_end {
            clean.retain(|r| r.map_offset < size);
            if let Some(last) = clean.last_mut() {
                last.length = last.length.min(size - last.map_offset);
            }
        }
        // Every range must lie inside its target.
        for r in &clean {
            let limit = match &targets[r.target] {
                Target::Stream(i) => Some(self.streams[*i].info.size),
                Target::Member(i) => Some(self.zip.entry(*i)?.size),
                _ => None,
            };
            if let Some(l) = limit {
                if r.target_offset + r.length > l {
                    return Err(Aff4Error::Corrupt(format!(
                        "map range at {} reads past the end of its target",
                        r.map_offset
                    )));
                }
            }
        }
        let gap = match self
            .graph
            .object(urn, &aff4("mapGapDefaultStream"))
            .and_then(|t| t.as_iri())
            .map(|s| s.to_string())
        {
            Some(g) => symbolic(&g).unwrap_or(Target::Zero),
            None => Target::Zero,
        };
        self.media_size = size;
        self.layout = Layout::Map {
            ranges: clean,
            targets,
            target_urns: target_names,
            gap,
        };
        Ok(())
    }

    pub fn media_size(&self) -> u64 {
        self.media_size
    }
    pub fn volume_urn(&self) -> &str {
        &self.volume_urn
    }
    pub fn image_urn(&self) -> Option<&str> {
        self.image_urn.as_deref()
    }
    pub fn graph(&self) -> &Graph {
        &self.graph
    }
    pub fn stored_hashes(&self) -> &[StoredHash] {
        &self.hashes
    }
    fn stored(&self, alg: &str) -> Option<String> {
        self.hashes
            .iter()
            .find(|h| h.algorithm == alg)
            .map(|h| h.value.clone())
    }
    pub fn stored_md5(&self) -> Option<String> {
        self.stored("md5")
    }
    pub fn stored_sha1(&self) -> Option<String> {
        self.stored("sha1")
    }
    pub fn stored_sha256(&self) -> Option<String> {
        self.stored("sha256")
    }
    pub fn acquisition_errors(&self) -> &[BadSectorRange] {
        &self.bad_sectors
    }
    pub fn case(&self) -> &CaseDetails {
        &self.case
    }

    pub fn info(&self) -> Aff4Info {
        let (layout, map_ranges, map_targets) = match &self.layout {
            Layout::Direct(_) => ("image_stream".to_string(), 0, Vec::new()),
            Layout::Map {
                ranges,
                target_urns,
                ..
            } => ("map".to_string(), ranges.len(), target_urns.clone()),
        };
        let image_types = self
            .image_urn
            .as_ref()
            .map(|i| {
                self.graph
                    .objects(i, RDF_TYPE)
                    .iter()
                    .map(|t| t.lexical().to_string())
                    .collect()
            })
            .unwrap_or_default();
        Aff4Info {
            volume_urn: self.volume_urn.clone(),
            version: self.version.clone(),
            tool: self.tool.clone(),
            image_urn: self.image_urn.clone(),
            image_types,
            data_stream_urn: self.data_stream_urn.clone(),
            layout,
            media_size: self.media_size,
            map_ranges,
            map_targets,
            streams: self.streams.iter().map(|s| s.info.clone()).collect(),
            stored_hashes: self.hashes.clone(),
            acquisition_errors: self.bad_sectors.clone(),
            case: self.case.clone(),
            creation_time: self
                .graph
                .object(&self.volume_urn, &aff4("creationTime"))
                .map(|t| t.lexical().to_string()),
            images: self.images.clone(),
            zip_members: self.zip.entries().len(),
            triples: self.graph.len(),
        }
    }

    fn bevy_index(&mut self, si: usize, bevy: u64) -> Result<&Vec<(u64, u32)>> {
        let st = self
            .streams
            .get_mut(si)
            .ok_or_else(|| Aff4Error::Corrupt("stream index".into()))?;
        if !st.indexes.contains_key(&bevy) {
            let &(bevy_member, index_member) = st
                .bevies
                .get(bevy as usize)
                .ok_or_else(|| Aff4Error::Corrupt(format!("bevy {} out of range", bevy)))?;
            let cis = st.info.chunks_per_segment as u64;
            let raw = self.zip.read_member(index_member, cis * 12 + 12)?;
            let bevy_size = self.zip.entry(bevy_member)?.size;
            if raw.len() % 12 != 0 {
                return Err(Aff4Error::Corrupt(format!(
                    "bevy {} index is {} bytes, not a multiple of 12",
                    bevy,
                    raw.len()
                )));
            }
            let mut entries = Vec::with_capacity(raw.len() / 12);
            for k in 0..raw.len() / 12 {
                let rec = &raw[k * 12..k * 12 + 12];
                let mut a = [0u8; 8];
                a.copy_from_slice(&rec[..8]);
                let off = u64::from_le_bytes(a);
                let len = u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]);
                if off.checked_add(len as u64).map(|e| e > bevy_size) != Some(false) {
                    return Err(Aff4Error::Corrupt(format!(
                        "bevy {} index entry [{}, +{}) outside the bevy of {} bytes",
                        bevy, off, len, bevy_size
                    )));
                }
                entries.push((off, len));
            }
            if st.indexes.len() >= INDEX_CACHE {
                st.indexes.clear();
            }
            st.indexes.insert(bevy, entries);
        }
        st.indexes
            .get(&bevy)
            .ok_or_else(|| Aff4Error::Corrupt("bevy index cache".into()))
    }

    /// Decode chunk `chunk` of stream `si` to exactly its media length.
    fn read_chunk(&mut self, si: usize, chunk: u64) -> Result<Vec<u8>> {
        let info = self
            .streams
            .get(si)
            .ok_or_else(|| Aff4Error::Corrupt("stream index".into()))?
            .info
            .clone();
        let cs = info.chunk_size as u64;
        let start = chunk
            .checked_mul(cs)
            .filter(|&s| s < info.size)
            .ok_or_else(|| Aff4Error::InvalidInput(format!("chunk {} out of range", chunk)))?;
        let expected = cs.min(info.size - start) as usize;
        let cis = info.chunks_per_segment as u64;
        let bevy = chunk / cis;
        let within = (chunk % cis) as usize;
        let (off, len) = *self.bevy_index(si, bevy)?.get(within).ok_or_else(|| {
            Aff4Error::Corrupt(format!(
                "bevy {} of {} has no index entry for chunk {}",
                bevy, info.urn, chunk
            ))
        })?;
        if len as u64 > cs * 2 + 1024 {
            return Err(Aff4Error::Corrupt(format!(
                "chunk {} is stored in {} bytes",
                chunk, len
            )));
        }
        let bevy_member = self.streams[si].bevies[bevy as usize].0;
        let mut stored = vec![0u8; len as usize];
        self.zip.read_stored_at(bevy_member, off, &mut stored)?;
        let mut data = info.compression.decode(&stored, cs as usize)?;
        if data.len() < expected {
            return Err(Aff4Error::Corrupt(format!(
                "chunk {} of {} holds {} bytes, expected {}",
                chunk,
                info.urn,
                data.len(),
                expected
            )));
        }
        data.truncate(expected);
        Ok(data)
    }

    fn read_stream_at(&mut self, si: usize, offset: u64, buf: &mut [u8]) -> Result<()> {
        let (size, cs) = {
            let i = &self.streams[si].info;
            (i.size, i.chunk_size as u64)
        };
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| Aff4Error::Corrupt("stream offset overflow".into()))?;
        if end > size {
            return Err(Aff4Error::Corrupt(format!(
                "read past the end of image stream ({} > {})",
                end, size
            )));
        }
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let chunk = pos / cs;
            let within = (pos % cs) as usize;
            let hit = matches!(&self.cache, Some((s, c, _)) if *s == si && *c == chunk);
            if !hit {
                let data = self.read_chunk(si, chunk)?;
                self.cache = Some((si, chunk, data));
            }
            let data = match &self.cache {
                Some((_, _, d)) => d,
                None => return Err(Aff4Error::Corrupt("chunk cache empty".into())),
            };
            if within >= data.len() {
                return Err(Aff4Error::Corrupt(format!("offset {} outside chunk", pos)));
            }
            let n = (data.len() - within).min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&data[within..within + n]);
            done += n;
        }
        Ok(())
    }

    fn read_target(&mut self, t: &Target, offset: u64, buf: &mut [u8]) -> Result<()> {
        match t {
            Target::Zero => buf.fill(0),
            Target::Pattern(p) => {
                let pl = p.len().max(1) as u64;
                for (i, b) in buf.iter_mut().enumerate() {
                    let pos = (offset + i as u64) % SYMBOLIC_TILE;
                    *b = p.get((pos % pl) as usize).copied().unwrap_or(0);
                }
            }
            Target::Member(i) => self.zip.read_stored_at(*i, offset, buf)?,
            Target::Stream(si) => self.read_stream_at(*si, offset, buf)?,
        }
        Ok(())
    }

    /// Read media bytes at `offset`; returns the number of bytes read (0 at the end).
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let size = self.media_size;
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let want = (size - offset).min(buf.len() as u64) as usize;
        let buf = &mut buf[..want];
        // Temporarily take the layout so targets can borrow `self` mutably.
        let layout = std::mem::replace(&mut self.layout, Layout::Direct(Target::Zero));
        let res = self.read_layout(&layout, offset, buf);
        self.layout = layout;
        res.map(|_| want)
    }

    fn read_layout(&mut self, layout: &Layout, offset: u64, buf: &mut [u8]) -> Result<()> {
        match layout {
            Layout::Direct(t) => self.read_target(t, offset, buf),
            Layout::Map {
                ranges,
                targets,
                gap,
                ..
            } => {
                let mut done = 0usize;
                while done < buf.len() {
                    let pos = offset + done as u64;
                    let rest = buf.len() - done;
                    // Last range starting at or before `pos`.
                    let k = ranges.partition_point(|r| r.map_offset <= pos);
                    let inside = k
                        .checked_sub(1)
                        .and_then(|k| ranges.get(k))
                        .filter(|r| pos < r.map_offset + r.length);
                    match inside {
                        Some(r) => {
                            let n = ((r.map_offset + r.length - pos) as usize).min(rest);
                            let t = targets
                                .get(r.target)
                                .ok_or_else(|| Aff4Error::Corrupt("map target".into()))?;
                            self.read_target(
                                t,
                                r.target_offset + (pos - r.map_offset),
                                &mut buf[done..done + n],
                            )?;
                            done += n;
                        }
                        None => {
                            let next = ranges.get(k).map(|r| r.map_offset).unwrap_or(u64::MAX);
                            let n = (next.saturating_sub(pos)).min(rest as u64) as usize;
                            self.read_target(gap, pos, &mut buf[done..done + n])?;
                            done += n;
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Re-hash the whole media, compare with every stored hash and check each ZIP member's
    /// CRC-32.
    pub fn verify(&mut self) -> Result<VerifyReport> {
        let mut h = MultiHasher::new();
        let mut s1 = sha1::Sha1::new();
        let mut s512 = sha2::Sha512::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut pos = 0u64;
        while pos < self.media_size {
            let n = self.read_at(pos, &mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            s1.update(&buf[..n]);
            s512.update(&buf[..n]);
            pos += n as u64;
        }
        let computed = h.finalize();
        let computed_sha1 = hex::encode(s1.finalize());
        let computed_sha512 = hex::encode(s512.finalize());
        let check = |alg: &str, value: &str| -> Option<bool> {
            let stored: Vec<&StoredHash> =
                self.hashes.iter().filter(|x| x.algorithm == alg).collect();
            if stored.is_empty() {
                None
            } else {
                Some(stored.iter().all(|x| x.value == value))
            }
        };
        let md5_match = check("md5", &computed.md5);
        let sha1_match = check("sha1", &computed_sha1);
        let sha256_match = check("sha256", &computed.sha256);
        let sha512_match = check("sha512", &computed_sha512);
        let unchecked: Vec<String> = self
            .hashes
            .iter()
            .filter(|x| !matches!(x.algorithm.as_str(), "md5" | "sha1" | "sha256" | "sha512"))
            .map(|x| x.algorithm.clone())
            .collect();
        let mut crc_errors = Vec::new();
        for i in 0..self.zip.entries().len() {
            let name = self.zip.entry(i)?.name.clone();
            match self.zip.crc_ok(i) {
                Ok(true) => {}
                Ok(false) => crc_errors.push(name),
                Err(e) => crc_errors.push(format!("{}: {}", name, e)),
            }
        }
        let results = [md5_match, sha1_match, sha256_match, sha512_match];
        let verified = results.iter().any(|r| r.is_some())
            && results.iter().all(|r| *r != Some(false))
            && crc_errors.is_empty();
        Ok(VerifyReport {
            media_size: self.media_size,
            computed,
            computed_sha1,
            computed_sha512,
            stored: self.hashes.clone(),
            md5_match,
            sha1_match,
            sha256_match,
            sha512_match,
            unchecked,
            crc_errors,
            verified,
        })
    }
}

impl Read for Aff4Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(self.position, buf)?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for Aff4Reader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let size = self.media_size as i128;
        let target = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => size + d as i128,
            SeekFrom::Current(d) => self.position as i128 + d as i128,
        };
        if target < 0 || target > u64::MAX as i128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek out of range",
            ));
        }
        self.position = target as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_names_map_to_urns() {
        assert_eq!(
            urn_for_member("aff4%3A%2F%2Fabc/00000001.index", "aff4://vol"),
            "aff4://abc/00000001.index"
        );
        assert_eq!(
            urn_for_member("information.turtle", "aff4://vol"),
            "aff4://vol/information.turtle"
        );
        assert_eq!(urn_for_member("bad%zz%", "aff4://v"), "aff4://v/bad%zz%");
    }

    #[test]
    fn symbolic_streams() {
        assert!(matches!(symbolic(&aff4("Zero")), Some(Target::Zero)));
        assert!(
            matches!(symbolic(&aff4("SymbolicStreamFF")), Some(Target::Pattern(p)) if p == vec![0xFF])
        );
        assert!(matches!(symbolic(&aff4("FF")), Some(Target::Pattern(_))));
        assert!(symbolic("aff4://x").is_none());
    }
}
