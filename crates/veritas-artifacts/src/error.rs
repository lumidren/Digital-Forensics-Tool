//! Shared error type for artifact parsers.
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParseError {
    #[error("truncated input: needed {needed} bytes at offset {offset}, have {available}")]
    Truncated {
        offset: usize,
        needed: usize,
        available: usize,
    },
    #[error("bad signature at offset {offset}: expected {expected}, found {found}")]
    BadSignature {
        offset: usize,
        expected: String,
        found: String,
    },
    #[error("invalid value at offset {offset}: {reason}")]
    Invalid { offset: usize, reason: String },
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("limit exceeded: {0}")]
    Limit(String),
}

pub type Result<T> = std::result::Result<T, ParseError>;
