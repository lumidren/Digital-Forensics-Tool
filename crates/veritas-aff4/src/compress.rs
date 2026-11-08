//! Chunk compression methods (`aff4:compressionMethod`).
//!
//! | method      | URI                                      | write | read |
//! |-------------|------------------------------------------|-------|------|
//! | stored      | `http://aff4.org/Schema#NullCompressor`  | yes   | yes (also `#compression/stored`) |
//! | deflate     | `https://www.ietf.org/rfc/rfc1950.txt`   | yes   | yes (zlib framing, as pyaff4) |
//! | raw-deflate | `https://tools.ietf.org/html/rfc1951`    | yes   | yes (Evimetry) |
//! | snappy      | `http://code.google.com/p/snappy/`       | yes   | yes (also `https://github.com/google/snappy`) |
//! | lz4         | `https://code.google.com/p/lz4/`         | no    | yes (raw LZ4 block) |
//!
//! As in pyaff4 and Evimetry, a chunk whose compressed form is not at least 16 bytes smaller
//! than the chunk size is stored uncompressed, and a stored chunk of exactly the chunk size is
//! never decompressed.

use crate::{Aff4Error, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

pub const URI_STORED: &str = "http://aff4.org/Schema#NullCompressor";
pub const URI_STORED_ALT: &str = "http://aff4.org/Schema#compression/stored";
pub const URI_ZLIB: &str = "https://www.ietf.org/rfc/rfc1950.txt";
pub const URI_DEFLATE: &str = "https://tools.ietf.org/html/rfc1951";
pub const URI_SNAPPY: &str = "http://code.google.com/p/snappy/";
pub const URI_SNAPPY_ALT: &str = "https://github.com/google/snappy";
pub const URI_LZ4: &str = "https://code.google.com/p/lz4/";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Compression {
    /// Chunks stored as is.
    Stored,
    /// DEFLATE in zlib framing (RFC 1950); what pyaff4 writes and reads as "zlib".
    Deflate,
    /// Raw DEFLATE (RFC 1951), as Evimetry writes. Not readable by pyaff4.
    RawDeflate,
    /// Snappy raw block format.
    Snappy,
    /// LZ4 raw block format (read only).
    Lz4,
}

impl Compression {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "stored" | "none" | "null" => Some(Self::Stored),
            "deflate" | "zlib" => Some(Self::Deflate),
            "raw-deflate" | "rawdeflate" | "rfc1951" => Some(Self::RawDeflate),
            "snappy" => Some(Self::Snappy),
            "lz4" => Some(Self::Lz4),
            _ => None,
        }
    }

    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            URI_STORED | URI_STORED_ALT => Some(Self::Stored),
            URI_ZLIB => Some(Self::Deflate),
            URI_DEFLATE => Some(Self::RawDeflate),
            URI_SNAPPY | URI_SNAPPY_ALT => Some(Self::Snappy),
            URI_LZ4 => Some(Self::Lz4),
            _ => None,
        }
    }

    pub fn uri(self) -> &'static str {
        match self {
            Self::Stored => URI_STORED,
            Self::Deflate => URI_ZLIB,
            Self::RawDeflate => URI_DEFLATE,
            Self::Snappy => URI_SNAPPY,
            Self::Lz4 => URI_LZ4,
        }
    }

    pub fn can_write(self) -> bool {
        !matches!(self, Self::Lz4)
    }

    /// Encode one chunk (always exactly `chunk_size` bytes). Returns the bytes to store; equal to
    /// `chunk` when compression does not save at least 16 bytes.
    pub fn encode(self, chunk: &[u8], level: u32) -> Result<Vec<u8>> {
        let level = flate2::Compression::new(level.min(9));
        let compressed = match self {
            Self::Stored => return Ok(chunk.to_vec()),
            Self::Deflate => {
                let mut e = flate2::write::ZlibEncoder::new(Vec::new(), level);
                e.write_all(chunk)?;
                e.finish()?
            }
            Self::RawDeflate => {
                let mut e = flate2::write::DeflateEncoder::new(Vec::new(), level);
                e.write_all(chunk)?;
                e.finish()?
            }
            Self::Snappy => snap::raw::Encoder::new()
                .compress_vec(chunk)
                .map_err(|e| Aff4Error::InvalidInput(format!("snappy: {}", e)))?,
            Self::Lz4 => return Err(Aff4Error::Unsupported("writing LZ4 image streams".into())),
        };
        if compressed.len() + 16 <= chunk.len() {
            Ok(compressed)
        } else {
            Ok(chunk.to_vec())
        }
    }

    /// Decode one stored chunk into at most `chunk_size` bytes.
    pub fn decode(self, stored: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
        if self == Self::Stored || stored.len() == chunk_size {
            return Ok(stored.to_vec());
        }
        match self {
            Self::Stored => Ok(stored.to_vec()),
            Self::Deflate => {
                let d = flate2::read::ZlibDecoder::new(stored);
                read_capped(d, chunk_size)
            }
            Self::RawDeflate => inflate_raw(stored, chunk_size),
            Self::Snappy => {
                let n = snap::raw::decompress_len(stored)
                    .map_err(|e| Aff4Error::Corrupt(format!("snappy chunk: {}", e)))?;
                if n > chunk_size {
                    return Err(Aff4Error::Corrupt(format!(
                        "snappy chunk decompresses to {} bytes, chunk size is {}",
                        n, chunk_size
                    )));
                }
                snap::raw::Decoder::new()
                    .decompress_vec(stored)
                    .map_err(|e| Aff4Error::Corrupt(format!("snappy chunk: {}", e)))
            }
            Self::Lz4 => {
                let mut out = vec![0u8; chunk_size];
                let n = lz4_flex::block::decompress_into(stored, &mut out)
                    .map_err(|e| Aff4Error::Corrupt(format!("lz4 chunk: {}", e)))?;
                out.truncate(n);
                Ok(out)
            }
        }
    }
}

fn read_capped<R: Read>(r: R, cap: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(cap.min(1 << 20));
    let mut limited = r.take(cap as u64 + 1);
    limited
        .read_to_end(&mut out)
        .map_err(|e| Aff4Error::Corrupt(format!("inflate: {}", e)))?;
    if out.len() > cap {
        return Err(Aff4Error::Corrupt(format!(
            "data inflates beyond {} bytes",
            cap
        )));
    }
    Ok(out)
}

/// Inflate raw DEFLATE data into at most `cap` bytes.
pub fn inflate_raw(data: &[u8], cap: usize) -> Result<Vec<u8>> {
    read_capped(flate2::read::DeflateDecoder::new(data), cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_writable() {
        let mut chunk = vec![0u8; 32768];
        for (i, b) in chunk.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        for c in [
            Compression::Stored,
            Compression::Deflate,
            Compression::RawDeflate,
            Compression::Snappy,
        ] {
            let enc = c.encode(&chunk, 6).unwrap();
            assert_eq!(c.decode(&enc, chunk.len()).unwrap(), chunk, "{:?}", c);
            assert_eq!(Compression::from_uri(c.uri()), Some(c));
        }
    }

    #[test]
    fn incompressible_is_stored_raw() {
        let chunk: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let enc = Compression::Snappy.encode(&chunk, 6).unwrap();
        assert!(enc.len() < chunk.len() || enc == chunk);
    }

    #[test]
    fn bombs_are_capped() {
        let big = vec![0u8; 1 << 20];
        let enc = Compression::Deflate.encode(&big, 9).unwrap();
        assert!(Compression::Deflate.decode(&enc, 4096).is_err());
        let enc = Compression::Snappy.encode(&big, 0).unwrap();
        assert!(Compression::Snappy.decode(&enc, 4096).is_err());
    }
}
