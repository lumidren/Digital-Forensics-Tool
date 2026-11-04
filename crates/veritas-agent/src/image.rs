//! Physical / logical imaging to E01 or raw with streaming hashes and bad-sector handling.
//!
//! Reads are sequential in blocks (default 1 MiB). A block that fails after `retries` attempts
//! is re-read sector by sector; sectors that still fail are zero-filled and recorded in the
//! bad-sector map (and in the E01 `error2` section). The source stream is hashed with
//! [`MultiHasher`] as it is read, so the reported hashes are of exactly what was stored.
//!
//! Resume: a JSON state file next to the output records the completed segments (path, size,
//! SHA-256), the offset where the current segment began and the bad-sector map. Digest state is
//! not serialisable, so on resume the completed segment files are re-read from disk and fed to
//! the hasher (after their SHA-256 is checked against the state file), the partial current
//! segment is discarded, and the source is re-read from the start of that segment. Resume is
//! implemented for raw output. E01 segments depend on writer state (chunk tables, running
//! counts) that is not persisted, so an interrupted E01 acquisition restarts from offset 0 after
//! the partial segments are removed.
//!
//! Device size: files report their length; devices are sized by seeking to the end, which works
//! for Linux block devices and Windows volume handles. Windows `\\.\PhysicalDriveN` handles do not
//! support end-relative seeks, so their size comes from `Get-Disk`; if that fails the size is
//! unknown and the device is read until end of data. An explicit size may always be given.

use crate::{cmd, AgentError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use veritas_ewf::{BadSectorRange, Compression, EwfOptions, EwfSummary, EwfWriter, MediaType};
use veritas_hash::{Hashes, MultiHasher};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    E01,
    Raw,
}

impl OutputFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "e01" | "ewf" => Some(Self::E01),
            "raw" | "dd" => Some(Self::Raw),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImageOptions {
    pub format: OutputFormat,
    /// Output path without extension.
    pub out_base: PathBuf,
    /// Segment size in bytes; `None` means a single raw file / default E01 segment size.
    pub segment_size: Option<u64>,
    pub sector_size: u32,
    /// Sectors per sequential read.
    pub block_sectors: u32,
    /// Attempts per block and per sector before giving up on it.
    pub retries: u32,
    /// Overrides the detected source size.
    pub size: Option<u64>,
    pub compression: Compression,
    pub physical: bool,
    pub case_number: String,
    pub evidence_number: String,
    pub examiner: String,
    pub description: String,
    pub notes: String,
    /// State file for resume; `None` disables state tracking.
    pub state_file: Option<PathBuf>,
}

impl ImageOptions {
    pub fn new(format: OutputFormat, out_base: impl Into<PathBuf>) -> Self {
        Self {
            format,
            out_base: out_base.into(),
            segment_size: None,
            sector_size: 512,
            block_sectors: 2048,
            retries: 3,
            size: None,
            compression: Compression::Fast,
            physical: false,
            case_number: String::new(),
            evidence_number: String::new(),
            examiner: String::new(),
            description: String::new(),
            notes: String::new(),
            state_file: None,
        }
    }
}

/// Progress report passed to the callback.
#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    pub bytes_done: u64,
    pub total: Option<u64>,
    pub bad_sectors: u64,
    pub segment: usize,
}

/// One output file with its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentInfo {
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageResult {
    pub format: OutputFormat,
    pub source: String,
    pub segments: Vec<SegmentInfo>,
    /// Hashes of the bytes read from the source (zero-filled where unreadable).
    pub hashes: Hashes,
    pub bytes: u64,
    pub sector_size: u32,
    pub bad_sectors: Vec<BadSectorRange>,
    pub ewf: Option<EwfSummary>,
    pub resumed_from: Option<u64>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}

/// Persisted acquisition state (raw resume).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageState {
    pub source: String,
    pub format: OutputFormat,
    pub out_base: PathBuf,
    pub segment_size: Option<u64>,
    pub sector_size: u32,
    pub total: Option<u64>,
    pub completed_segments: Vec<SegmentInfo>,
    pub current_segment_start: u64,
    pub bytes_done: u64,
    pub bad_sectors: Vec<BadSectorRange>,
    pub complete: bool,
    pub updated_at: DateTime<Utc>,
}

impl ImageState {
    pub fn load(path: &Path) -> Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(b) => Ok(Some(serde_json::from_slice(&b)?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

fn add_bad(map: &mut Vec<BadSectorRange>, sector: u64) {
    if let Some(last) = map.last_mut() {
        if last.first_sector + last.sector_count == sector {
            last.sector_count += 1;
            return;
        }
    }
    map.push(BadSectorRange { first_sector: sector, sector_count: 1 });
}

/// Read until `buf` is full or end of data; returns bytes read.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

fn read_at_with_retry<R: Read + Seek>(src: &mut R, offset: u64, buf: &mut [u8], retries: u32) -> io::Result<usize> {
    let mut last = None;
    for _ in 0..retries.max(1) {
        match src.seek(SeekFrom::Start(offset)).and_then(|_| read_full(src, buf)) {
            Ok(n) => return Ok(n),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("read failed")))
}

/// Read one block; unreadable sectors are zero-filled and appended to `bad`.
/// Returns the number of bytes delivered (short only at end of data).
fn read_block<R: Read + Seek>(src: &mut R, offset: u64, buf: &mut [u8], sector: usize, retries: u32, bad: &mut Vec<BadSectorRange>) -> usize {
    if let Ok(n) = read_at_with_retry(src, offset, buf, retries) {
        return n;
    }
    let mut done = 0usize;
    while done < buf.len() {
        let n = sector.min(buf.len() - done);
        let piece = &mut buf[done..done + n];
        match read_at_with_retry(src, offset + done as u64, piece, retries) {
            Ok(0) => break,
            Ok(got) if got < n => {
                done += got;
                break;
            }
            Ok(_) => done += n,
            Err(_) => {
                piece.iter_mut().for_each(|b| *b = 0);
                add_bad(bad, (offset + done as u64) / sector as u64);
                done += n;
            }
        }
    }
    done
}

/// Raw output: `<base>.raw` (unsegmented) or `<base>.000`, `<base>.001`, ...
struct RawSink {
    base: PathBuf,
    segment_size: Option<u64>,
    file: Option<(BufWriter<File>, PathBuf, sha2::Sha256, u64)>,
    completed: Vec<SegmentInfo>,
    /// Source offset where the open segment began.
    segment_start: u64,
}

impl RawSink {
    fn path_for(&self, index: usize) -> PathBuf {
        match self.segment_size {
            None => PathBuf::from(format!("{}.raw", self.base.display())),
            Some(_) => PathBuf::from(format!("{}.{:03}", self.base.display(), index)),
        }
    }

    fn open_next(&mut self) -> Result<()> {
        let path = self.path_for(self.completed.len());
        let f = OpenOptions::new().write(true).create_new(true).open(&path).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                AgentError::Invalid(format!("refusing to overwrite {}", path.display()))
            } else {
                e.into()
            }
        })?;
        self.file = Some((BufWriter::with_capacity(1 << 20, f), path, <sha2::Sha256 as sha2::Digest>::new(), 0));
        Ok(())
    }

    fn close_current(&mut self) -> Result<()> {
        if let Some((mut w, path, h, size)) = self.file.take() {
            w.flush()?;
            w.get_ref().sync_all()?;
            self.completed.push(SegmentInfo { path, size, sha256: hex::encode(sha2::Digest::finalize(h)) });
            self.segment_start += size;
        }
        Ok(())
    }

    /// Write `data`; returns true when a segment was completed during this call.
    fn write(&mut self, mut data: &[u8]) -> Result<bool> {
        let mut rolled = false;
        while !data.is_empty() {
            if self.file.is_none() {
                self.open_next()?;
            }
            let limit = self.segment_size.unwrap_or(u64::MAX);
            let (w, _, h, size) = self.file.as_mut().ok_or_else(|| AgentError::Invalid("no open segment".into()))?;
            let room = (limit - *size).min(data.len() as u64) as usize;
            w.write_all(&data[..room])?;
            sha2::Digest::update(h, &data[..room]);
            *size += room as u64;
            data = &data[room..];
            if *size >= limit {
                self.close_current()?;
                rolled = true;
            }
        }
        Ok(rolled)
    }
}

enum Sink {
    Ewf(Box<EwfWriter>),
    Raw(RawSink),
}

/// Image an already-open source. `total` is the number of bytes to read (`None`: until end of
/// data). `progress` returns `false` to request a clean stop (state is saved for resume).
pub fn image_reader<R: Read + Seek>(src: &mut R, source_label: &str, total: Option<u64>, opts: &ImageOptions, progress: &mut dyn FnMut(&Progress) -> bool) -> Result<ImageResult> {
    let started_at = Utc::now();
    let sector = opts.sector_size as usize;
    if sector == 0 || !sector.is_power_of_two() || sector > 65536 {
        return Err(AgentError::Invalid("sector size must be a power of two up to 65536".into()));
    }
    let block = sector * opts.block_sectors.max(1) as usize;
    let mut hasher = MultiHasher::new();
    let mut bad: Vec<BadSectorRange> = Vec::new();
    let mut offset = 0u64;
    let mut resumed_from = None;

    let previous = match &opts.state_file {
        Some(p) => ImageState::load(p)?,
        None => None,
    };
    let mut sink = match opts.format {
        OutputFormat::E01 => {
            if let Some(st) = previous.filter(|s| !s.complete) {
                // E01 cannot resume; remove the partial segments recorded by the interrupted run.
                for seg in &st.completed_segments {
                    let _ = std::fs::remove_file(&seg.path);
                }
            }
            let mut eo = EwfOptions { compression: opts.compression, physical: opts.physical, bytes_per_sector: opts.sector_size, ..Default::default() };
            eo.media_type = if opts.physical { MediaType::Fixed } else { MediaType::Removable };
            if let Some(s) = opts.segment_size {
                eo.segment_size = s;
            }
            if opts.sector_size != 512 {
                eo.sectors_per_chunk = (32768 / opts.sector_size).max(1);
            }
            eo.header.case_number = opts.case_number.clone();
            eo.header.evidence_number = opts.evidence_number.clone();
            eo.header.examiner_name = opts.examiner.clone();
            eo.header.description = if opts.description.is_empty() { source_label.to_string() } else { opts.description.clone() };
            eo.header.notes = opts.notes.clone();
            eo.header.acquiry_software_version = format!("{} {}", crate::AGENT_NAME, crate::AGENT_VERSION);
            Sink::Ewf(Box::new(EwfWriter::create(&opts.out_base, eo)?))
        }
        OutputFormat::Raw => {
            let mut raw = RawSink { base: opts.out_base.clone(), segment_size: opts.segment_size, file: None, completed: Vec::new(), segment_start: 0 };
            if let Some(st) = previous.filter(|s| !s.complete) {
                if st.source != source_label || st.format != OutputFormat::Raw || st.out_base != opts.out_base || st.segment_size != opts.segment_size || st.sector_size != opts.sector_size {
                    return Err(AgentError::Invalid("state file does not match this acquisition".into()));
                }
                // Re-hash completed segments from disk; their bytes are the source bytes already read.
                for seg in &st.completed_segments {
                    let mut f = File::open(&seg.path)?;
                    let mut sha = <sha2::Sha256 as sha2::Digest>::new();
                    let mut buf = vec![0u8; 1 << 20];
                    loop {
                        let n = read_full(&mut f, &mut buf)?;
                        if n == 0 {
                            break;
                        }
                        hasher.update(&buf[..n]);
                        sha2::Digest::update(&mut sha, &buf[..n]);
                    }
                    let got = hex::encode(sha2::Digest::finalize(sha));
                    if got != seg.sha256 {
                        return Err(AgentError::Integrity(format!("{} changed since it was written (sha256 {} != {})", seg.path.display(), got, seg.sha256)));
                    }
                }
                let partial = raw.path_for(st.completed_segments.len());
                if partial.exists() {
                    std::fs::remove_file(&partial)?;
                }
                raw.completed = st.completed_segments.clone();
                raw.segment_start = st.current_segment_start;
                offset = st.current_segment_start;
                bad = st.bad_sectors.into_iter().filter(|b| b.first_sector * (sector as u64) < offset).collect();
                resumed_from = Some(offset);
            }
            Sink::Raw(raw)
        }
    };

    let save_state = |sink: &Sink, bad: &[BadSectorRange], done: u64, complete: bool| -> Result<()> {
        let Some(path) = &opts.state_file else { return Ok(()) };
        let (completed, start) = match sink {
            Sink::Raw(r) => (r.completed.clone(), r.segment_start),
            Sink::Ewf(w) => (w.segments().iter().map(|p| SegmentInfo { path: p.clone(), size: 0, sha256: String::new() }).collect(), 0),
        };
        ImageState {
            source: source_label.to_string(),
            format: opts.format,
            out_base: opts.out_base.clone(),
            segment_size: opts.segment_size,
            sector_size: opts.sector_size,
            total,
            completed_segments: completed,
            current_segment_start: start,
            bytes_done: done,
            bad_sectors: bad.to_vec(),
            complete,
            updated_at: Utc::now(),
        }
        .save(path)
    };

    let mut buf = vec![0u8; block];
    let mut last_saved = offset;
    loop {
        let want = match total {
            Some(t) if offset >= t => break,
            Some(t) => (t - offset).min(block as u64) as usize,
            None => block,
        };
        let got = read_block(src, offset, &mut buf[..want], sector, opts.retries, &mut bad);
        if got == 0 {
            break;
        }
        let data = &buf[..got];
        hasher.update(data);
        let rolled = match &mut sink {
            Sink::Ewf(w) => {
                w.write(data)?;
                false
            }
            Sink::Raw(r) => r.write(data)?,
        };
        offset += got as u64;
        if rolled || offset - last_saved >= 64 * 1024 * 1024 {
            save_state(&sink, &bad, offset, false)?;
            last_saved = offset;
        }
        let segment = match &sink {
            Sink::Ewf(w) => w.segments().len(),
            Sink::Raw(r) => r.completed.len() + 1,
        };
        let bad_count = bad.iter().map(|b| b.sector_count).sum();
        if !progress(&Progress { bytes_done: offset, total, bad_sectors: bad_count, segment }) {
            if let Sink::Raw(r) = &mut sink {
                if let Some((w, _, _, _)) = r.file.as_mut() {
                    w.flush()?;
                }
            }
            save_state(&sink, &bad, offset, false)?;
            return Err(AgentError::Interrupted(offset));
        }
        if got < want {
            break;
        }
    }

    let (segments, ewf) = match sink {
        Sink::Ewf(mut w) => {
            for b in &bad {
                w.record_bad_sectors(b.first_sector, b.sector_count);
            }
            let summary = w.finish()?;
            let mut segs = Vec::new();
            for p in &summary.segments {
                segs.push(SegmentInfo { path: p.clone(), size: std::fs::metadata(p)?.len(), sha256: crate::sha256_file(p)? });
            }
            (segs, Some(summary))
        }
        Sink::Raw(mut r) => {
            if r.file.is_none() && r.completed.is_empty() {
                r.open_next()?;
            }
            r.close_current()?;
            let segs = r.completed.clone();
            let tmp = Sink::Raw(r);
            save_state(&tmp, &bad, offset, true)?;
            (segs, None)
        }
    };
    if ewf.is_some() {
        if let Some(p) = &opts.state_file {
            let _ = std::fs::remove_file(p);
        }
    }
    Ok(ImageResult {
        format: opts.format,
        source: source_label.to_string(),
        segments,
        hashes: hasher.finalize(),
        bytes: offset,
        sector_size: opts.sector_size,
        bad_sectors: bad,
        ewf,
        resumed_from,
        started_at,
        finished_at: Utc::now(),
    })
}

/// Size of a Windows physical drive via `Get-Disk` (no IOCTL, so no unsafe code).
fn windows_disk_size(path: &str) -> Option<u64> {
    let n = crate::writeblock::physical_drive_number(path)?;
    let out = cmd::powershell(&format!("(Get-Disk -Number {}).Size", n), std::time::Duration::from_secs(60)).ok()?;
    out.stdout_lossy().trim().parse().ok()
}

/// Determine the size of a file or device.
pub fn source_size(file: &mut File, path: &Path) -> Option<u64> {
    if let Ok(m) = file.metadata() {
        if m.is_file() {
            return Some(m.len());
        }
    }
    let path_s = path.to_string_lossy();
    if std::env::consts::OS == "windows" {
        if let Some(n) = windows_disk_size(&path_s) {
            return Some(n);
        }
    }
    match file.seek(SeekFrom::End(0)) {
        Ok(n) if n > 0 => {
            let _ = file.seek(SeekFrom::Start(0));
            Some(n)
        }
        _ => {
            let _ = file.seek(SeekFrom::Start(0));
            None
        }
    }
}

/// Open a file or device read-only and image it.
pub fn image_path(source: &Path, opts: &ImageOptions, progress: &mut dyn FnMut(&Progress) -> bool) -> Result<ImageResult> {
    let mut f = File::open(source)?;
    let total = opts.size.or_else(|| source_size(&mut f, source));
    image_reader(&mut f, &source.display().to_string(), total, opts, progress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_sector_runs_merge() {
        let mut v = Vec::new();
        add_bad(&mut v, 5);
        add_bad(&mut v, 6);
        add_bad(&mut v, 9);
        assert_eq!(v, vec![BadSectorRange { first_sector: 5, sector_count: 2 }, BadSectorRange { first_sector: 9, sector_count: 1 }]);
    }

    #[test]
    fn formats_parse() {
        assert_eq!(OutputFormat::parse("E01"), Some(OutputFormat::E01));
        assert_eq!(OutputFormat::parse("dd"), Some(OutputFormat::Raw));
        assert_eq!(OutputFormat::parse("vmdk"), None);
    }
}
