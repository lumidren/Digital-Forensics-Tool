//! Random-access byte sources: in-memory buffers, files, sub-ranges (partitions) and the media
//! of E01 and AFF4 images.
use crate::error::{FsError, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Largest single contiguous read any parser may request (guards allocation from hostile lengths).
pub const MAX_SINGLE_READ: u64 = 512 * 1024 * 1024;

pub trait ReadAt: Send + Sync {
    fn size(&self) -> u64;
    /// Read up to `buf.len()` bytes at `offset`; returns bytes read (short only at end of source).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;
}

pub type Source = Arc<dyn ReadAt>;

/// Read exactly `len` bytes at `offset` or fail with `Truncated`.
pub fn read_vec(src: &dyn ReadAt, offset: u64, len: u64) -> Result<Vec<u8>> {
    if len > MAX_SINGLE_READ {
        return Err(FsError::Limit(format!(
            "read of {len} bytes exceeds MAX_SINGLE_READ"
        )));
    }
    let end = offset
        .checked_add(len)
        .ok_or_else(|| FsError::invalid(offset, "offset overflow"))?;
    if end > src.size() {
        return Err(FsError::Truncated {
            offset,
            needed: len,
            available: src.size().saturating_sub(offset),
        });
    }
    let mut buf = vec![0u8; len as usize];
    let mut done = 0usize;
    while done < buf.len() {
        let n = src.read_at(offset + done as u64, &mut buf[done..])?;
        if n == 0 {
            return Err(FsError::Truncated {
                offset,
                needed: len,
                available: done as u64,
            });
        }
        done += n;
    }
    Ok(buf)
}

/// Read up to `len` bytes, zero-filling whatever lies beyond the end of the source.
pub fn read_vec_padded(src: &dyn ReadAt, offset: u64, len: u64) -> Result<Vec<u8>> {
    if len > MAX_SINGLE_READ {
        return Err(FsError::Limit(format!(
            "read of {len} bytes exceeds MAX_SINGLE_READ"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    let size = src.size();
    if offset < size {
        let avail = (size - offset).min(len) as usize;
        let mut done = 0usize;
        while done < avail {
            let n = src.read_at(offset + done as u64, &mut buf[done..avail])?;
            if n == 0 {
                break;
            }
            done += n;
        }
    }
    Ok(buf)
}

pub struct MemSource {
    data: Arc<Vec<u8>>,
}

impl MemSource {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: Arc::new(data),
        }
    }
    pub fn source(data: Vec<u8>) -> Source {
        Arc::new(Self::new(data))
    }
}

impl ReadAt for MemSource {
    fn size(&self) -> u64 {
        self.data.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.data.len() as u64 {
            return Ok(0);
        }
        let start = offset as usize;
        let n = buf.len().min(self.data.len() - start);
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(n)
    }
}

pub struct FileSource {
    file: Mutex<File>,
    size: u64,
}

impl FileSource {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            file: Mutex::new(file),
            size,
        })
    }
    pub fn source(path: &Path) -> Result<Source> {
        Ok(Arc::new(Self::open(path)?))
    }
}

impl ReadAt for FileSource {
    fn size(&self) -> u64 {
        self.size
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }
        let mut f = self
            .file
            .lock()
            .map_err(|_| FsError::Io("file lock poisoned".into()))?;
        f.seek(SeekFrom::Start(offset))?;
        let remaining = self.size - offset;
        let want = if (buf.len() as u64) < remaining {
            buf.len()
        } else {
            remaining as usize
        };
        let mut done = 0;
        while done < want {
            let n = f.read(&mut buf[done..want])?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }
}

/// A window `[start, start+len)` of another source (a partition or an embedded volume).
pub struct SubSource {
    inner: Source,
    start: u64,
    len: u64,
}

impl SubSource {
    pub fn new(inner: Source, start: u64, len: u64) -> Result<Self> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| FsError::invalid(start, "sub-range overflow"))?;
        let len = if end > inner.size() {
            inner.size().saturating_sub(start)
        } else {
            len
        };
        Ok(Self { inner, start, len })
    }
    pub fn source(inner: Source, start: u64, len: u64) -> Result<Source> {
        Ok(Arc::new(Self::new(inner, start, len)?))
    }
}

impl ReadAt for SubSource {
    fn size(&self) -> u64 {
        self.len
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(self.len - offset) as usize;
        self.inner.read_at(self.start + offset, &mut buf[..n])
    }
}

/// Media of an Expert Witness (E01) segment set, read through `veritas-ewf`.
pub struct EwfSource {
    reader: Mutex<veritas_ewf::reader::EwfReader>,
    size: u64,
}

impl EwfSource {
    pub fn open(first_segment: &Path) -> Result<Self> {
        let r = veritas_ewf::reader::EwfReader::open(first_segment)
            .map_err(|e| FsError::Io(format!("E01: {e}")))?;
        let size = r.media_size();
        Ok(Self {
            reader: Mutex::new(r),
            size,
        })
    }
}

impl ReadAt for EwfSource {
    fn size(&self) -> u64 {
        self.size
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }
        let mut r = self
            .reader
            .lock()
            .map_err(|_| FsError::Io("EWF reader lock poisoned".into()))?;
        let want = buf.len().min((self.size - offset) as usize);
        let mut done = 0;
        while done < want {
            let n = r
                .read_at(offset + done as u64, &mut buf[done..want])
                .map_err(|e| FsError::Io(format!("E01: {e}")))?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }
}

/// Media of an AFF4 (Standard v1.0 image stream) container, read through `veritas-aff4`.
pub struct Aff4Source {
    reader: Mutex<veritas_aff4::Aff4Reader>,
    size: u64,
}

impl Aff4Source {
    pub fn open(path: &Path) -> Result<Self> {
        let r =
            veritas_aff4::Aff4Reader::open(path).map_err(|e| FsError::Io(format!("AFF4: {e}")))?;
        let size = r.media_size();
        Ok(Self {
            reader: Mutex::new(r),
            size,
        })
    }
}

impl ReadAt for Aff4Source {
    fn size(&self) -> u64 {
        self.size
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }
        let mut r = self
            .reader
            .lock()
            .map_err(|_| FsError::Io("AFF4 reader lock poisoned".into()))?;
        let want = buf.len().min((self.size - offset) as usize);
        let mut done = 0;
        while done < want {
            let n = r
                .read_at(offset + done as u64, &mut buf[done..want])
                .map_err(|e| FsError::Io(format!("AFF4: {e}")))?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }
}

/// Open an evidence file: E01 segment sets and AFF4 containers (a ZIP whose central directory
/// lists `information.turtle` or `container.description`) are read as their media; anything
/// else as raw bytes.
pub fn open_evidence(path: &Path) -> Result<Source> {
    let mut sig = [0u8; 8];
    let head_ok = File::open(path)
        .and_then(|mut f| f.read_exact(&mut sig))
        .is_ok();
    if head_ok && &sig == b"EVF\x09\x0d\x0a\xff\x00" {
        return Ok(Arc::new(EwfSource::open(path)?));
    }
    if head_ok && sig.starts_with(b"PK\x03\x04") && veritas_aff4::is_aff4_file(path) {
        return Ok(Arc::new(Aff4Source::open(path)?));
    }
    FileSource::source(path)
}
