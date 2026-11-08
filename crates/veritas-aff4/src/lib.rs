//! AFF4 Standard v1.0 disk images: an `aff4:ImageStream` stored in a ZIP64 `aff4:ZipVolume`.
//!
//! Container layout written by [`Aff4Writer`] (the shape pyaff4 and Evimetry produce):
//!
//! ```text
//! container.description            volume URN (also the ZIP archive comment)
//! version.txt                      major=1 / minor=0 / tool=...
//! aff4%3A%2F%2F<stream>/00000000   bevy 0: compressed chunks back to back
//! aff4%3A%2F%2F<stream>/00000000.index   (u64 offset, u32 length) per chunk, little endian
//! ...                              further bevies
//! aff4%3A%2F%2F<map>/map           aff4:Map ranges (u64 map offset, u64 length, u64 target
//! aff4%3A%2F%2F<map>/idx           offset, u32 target index) and the newline separated targets
//! information.turtle               RDF Turtle: ZipVolume, Image/DiskImage, Map, ImageStream
//! ```
//!
//! [`Aff4Reader`] parses the ZIP64 central directory, the Turtle metadata (with a small, bounded
//! Turtle parser, [`turtle`]), resolves `aff4:Image -> aff4:dataStream -> aff4:Map ->` target
//! streams (image streams, zip segments and the symbolic streams `aff4:Zero`,
//! `aff4:UnknownData`, `aff4:UnreadableData`, `aff4:SymbolicStreamXX`) and serves random-access
//! reads. Every length and offset read from the file is bounds checked and every allocation is
//! capped; malformed input yields [`Aff4Error`], never a panic.
//!
//! Not supported: AFF4 Logical (`aff4:FileImage`) containers, encrypted streams
//! (`aff4:EncryptedStream`), pre-standard (`http://afflib.org/2009/aff4#`) streams, multi-part
//! volumes and hash-based (deduplicated) images.
#![forbid(unsafe_code)]

pub mod compress;
pub mod reader;
pub mod turtle;
pub mod writer;
pub mod zip;

pub use compress::Compression;
pub use reader::{Aff4Info, Aff4Reader, StoredHash, VerifyReport};
pub use writer::{Aff4Options, Aff4Summary, Aff4Writer, BadSectorRange, CaseDetails};

use thiserror::Error;

/// AFF4 namespace.
pub const AFF4: &str = "http://aff4.org/Schema#";
/// Pre-standard AFF4 namespace (Evimetry 1.x / Wirespeed); recognised for error messages only.
pub const AFF4_LEGACY: &str = "http://afflib.org/2009/aff4#";
pub const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
pub const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
/// Namespace for Veritas-specific metadata (bad-sector map) written alongside standard terms.
pub const VERITAS: &str = "https://github.com/lumidren/Digital-Forensics-Tool/aff4#";

/// Default chunk size (32 KiB), as used by pyaff4 and Evimetry.
pub const DEFAULT_CHUNK_SIZE: u32 = 32 * 1024;
/// Default chunks per bevy (64 MiB bevies with 32 KiB chunks).
pub const DEFAULT_CHUNKS_PER_SEGMENT: u32 = 2048;
/// Largest accepted chunk size (read and write).
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;
/// Largest accepted chunks-per-segment value.
pub const MAX_CHUNKS_PER_SEGMENT: u32 = 1 << 20;

#[derive(Debug, Error)]
pub enum Aff4Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not an AFF4 container: {0}")]
    NotAff4(String),
    #[error("zip: {0}")]
    Zip(String),
    #[error("turtle: {0}")]
    Turtle(String),
    #[error("truncated {0}")]
    Truncated(&'static str),
    #[error("corrupt image: {0}")]
    Corrupt(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("limit exceeded: {0}")]
    Limit(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("refusing to overwrite existing file {0}")]
    Exists(String),
}

pub type Result<T> = std::result::Result<T, Aff4Error>;

impl From<Aff4Error> for std::io::Error {
    fn from(e: Aff4Error) -> Self {
        match e {
            Aff4Error::Io(io) => io,
            other => std::io::Error::new(std::io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}

/// True when `head` (the first bytes of a file) starts with a ZIP local header whose member name
/// is one of the AFF4 volume entries. Cheap pre-check; [`is_aff4_file`] is authoritative.
pub fn looks_like_aff4(head: &[u8]) -> bool {
    if head.len() < 30 || &head[..4] != b"PK\x03\x04" {
        return false;
    }
    let n = u16::from_le_bytes([head[26], head[27]]) as usize;
    let name = match head.get(30..30 + n) {
        Some(n) => n,
        None => return false,
    };
    matches!(
        name,
        b"container.description" | b"version.txt" | b"information.turtle"
    ) || name.starts_with(b"aff4%3A%2F%2F")
}

/// True when `path` is a ZIP archive whose central directory lists `information.turtle` or
/// `container.description`.
pub fn is_aff4_file(path: &std::path::Path) -> bool {
    let Ok(f) = std::fs::File::open(path) else {
        return false;
    };
    match zip::ZipArchive::new(Box::new(f)) {
        Ok(z) => {
            z.find("information.turtle").is_some() || z.find("container.description").is_some()
        }
        Err(_) => false,
    }
}
