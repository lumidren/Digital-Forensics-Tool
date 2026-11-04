//! Error type shared by every file-system parser in this crate.
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FsError {
    #[error("truncated input: needed {needed} bytes at offset {offset}, have {available}")]
    Truncated {
        offset: u64,
        needed: u64,
        available: u64,
    },
    #[error("bad signature at offset {offset}: expected {expected}, found {found}")]
    BadSignature {
        offset: u64,
        expected: String,
        found: String,
    },
    #[error("invalid value at offset {offset}: {reason}")]
    Invalid { offset: u64, reason: String },
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("limit exceeded: {0}")]
    Limit(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("i/o error: {0}")]
    Io(String),
}

impl FsError {
    pub fn invalid(offset: u64, reason: impl Into<String>) -> Self {
        FsError::Invalid {
            offset,
            reason: reason.into(),
        }
    }
    pub fn sig(offset: u64, expected: &str, found: &[u8]) -> Self {
        FsError::BadSignature {
            offset,
            expected: expected.to_string(),
            found: hex::encode(found),
        }
    }
}

impl From<std::io::Error> for FsError {
    fn from(e: std::io::Error) -> Self {
        FsError::Io(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, FsError>;
