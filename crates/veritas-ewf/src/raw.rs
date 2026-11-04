//! Reader for plain raw images (`.raw`, `.dd`, `.img`) and split raw sets (`.000/.001/...`,
//! `.001/.002/...`, `aa/ab/...`) presented as one contiguous byte stream.

use crate::{EwfError, Result};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

struct Part {
    path: PathBuf,
    file: File,
    start: u64,
    len: u64,
}

/// Contiguous view over one or more raw segment files. Implements [`Read`] and [`Seek`].
pub struct RawSegmented {
    parts: Vec<Part>,
    size: u64,
    position: u64,
}

/// Resolve the files of a split raw set starting at `first`. Numeric extensions (any width,
/// starting at 0 or 1) and two-letter `aa`, `ab` .. extensions are recognised; anything else is a
/// single file.
pub fn resolve_raw_segments(first: &Path) -> Result<Vec<PathBuf>> {
    if !first.is_file() {
        return Err(EwfError::MissingSegment(first.display().to_string()));
    }
    let ext = first.extension().and_then(|e| e.to_str()).unwrap_or("");
    let mut out = vec![first.to_path_buf()];
    if !ext.is_empty() && ext.len() <= 4 && ext.bytes().all(|b| b.is_ascii_digit()) {
        let width = ext.len();
        let start: u64 = ext.parse().unwrap_or(0);
        if start > 1 {
            return Ok(out);
        }
        let mut n = start + 1;
        loop {
            let e = format!("{:0width$}", n, width = width);
            if e.len() > width {
                break;
            }
            let p = first.with_extension(&e);
            if !p.is_file() {
                break;
            }
            out.push(p);
            n += 1;
        }
    } else if ext == "aa" || ext == "AA" {
        let base = if ext == "aa" { b'a' } else { b'A' };
        'outer: for c1 in 0..26u8 {
            for c2 in 0..26u8 {
                if c1 == 0 && c2 == 0 {
                    continue;
                }
                let e: String = [(base + c1) as char, (base + c2) as char].iter().collect();
                let p = first.with_extension(&e);
                if !p.is_file() {
                    break 'outer;
                }
                out.push(p);
            }
        }
    }
    Ok(out)
}

impl RawSegmented {
    /// Open a raw image or the first file of a split raw set.
    pub fn open(first: impl AsRef<Path>) -> Result<Self> {
        let paths = resolve_raw_segments(first.as_ref())?;
        Self::open_parts(&paths)
    }

    /// Open an explicit ordered list of parts.
    pub fn open_parts(paths: &[PathBuf]) -> Result<Self> {
        if paths.is_empty() {
            return Err(EwfError::InvalidInput("no raw segment files".into()));
        }
        let mut parts = Vec::with_capacity(paths.len());
        let mut start = 0u64;
        for p in paths {
            let file = File::open(p)?;
            let len = file.metadata()?.len();
            parts.push(Part {
                path: p.clone(),
                file,
                start,
                len,
            });
            start = start
                .checked_add(len)
                .ok_or_else(|| EwfError::Corrupt("total size overflow".into()))?;
        }
        Ok(Self {
            parts,
            size: start,
            position: 0,
        })
    }

    pub fn media_size(&self) -> u64 {
        self.size
    }

    pub fn segment_paths(&self) -> Vec<PathBuf> {
        self.parts.iter().map(|p| p.path.clone()).collect()
    }

    /// Read at `offset`; returns bytes read (0 at the end).
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let mut done = 0usize;
        let mut pos = offset;
        while done < buf.len() && pos < self.size {
            let i = match self
                .parts
                .iter()
                .position(|p| pos >= p.start && pos < p.start + p.len)
            {
                Some(i) => i,
                None => break,
            };
            let part = &mut self.parts[i];
            let within = pos - part.start;
            let n = ((part.len - within) as usize).min(buf.len() - done);
            part.file.seek(SeekFrom::Start(within))?;
            part.file.read_exact(&mut buf[done..done + n])?;
            done += n;
            pos += n as u64;
        }
        Ok(done)
    }
}

impl Read for RawSegmented {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(self.position, buf)?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for RawSegmented {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.size as i128 + d as i128,
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
