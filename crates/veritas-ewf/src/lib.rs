//! Expert Witness Format (EWF-E01, "EnCase 6" variant) writer and reader, plus split-raw reading.
//!
//! The writer streams arbitrary input into zlib-compressed 32 KiB chunks (64 sectors of 512
//! bytes by default), splits the output into `.E01`, `.E02`, ... `.EAA` segment files at a
//! configurable size, and finishes the last segment with `digest` (MD5 + SHA-1) and `hash` (MD5)
//! sections. The reader resolves the segment chain, maps every chunk through the `table`
//! sections, and re-verifies the stored MD5 on request.
//!
//! All parsing is bounds-checked; malformed or truncated input yields [`EwfError`], never a panic.
#![forbid(unsafe_code)]

pub mod format;
pub mod raw;
pub mod reader;
pub mod writer;

pub use format::{BadSectorRange, Compression, EwfHeader, MediaType, VolumeInfo};
pub use raw::RawSegmented;
pub use reader::{EwfReader, VerifyReport};
pub use writer::{EwfOptions, EwfSummary, EwfWriter};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EwfError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not an EWF-E01 segment (bad signature)")]
    InvalidSignature,
    #[error("truncated {0}")]
    Truncated(&'static str),
    #[error("{what} checksum mismatch: stored {stored:#010x}, calculated {calculated:#010x}")]
    Checksum { what: String, stored: u32, calculated: u32 },
    #[error("corrupt image: {0}")]
    Corrupt(String),
    #[error("missing segment: {0}")]
    MissingSegment(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("refusing to overwrite existing file {0}")]
    Exists(String),
}

pub type Result<T> = std::result::Result<T, EwfError>;

impl From<EwfError> for std::io::Error {
    fn from(e: EwfError) -> Self {
        match e {
            EwfError::Io(io) => io,
            other => std::io::Error::new(std::io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}
