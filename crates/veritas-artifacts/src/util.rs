//! Bounds-checked little-endian readers shared by all parsers.
use crate::error::{ParseError, Result};

pub fn need(data: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    match offset.checked_add(len) {
        Some(end) if end <= data.len() => Ok(&data[offset..end]),
        _ => Err(ParseError::Truncated {
            offset,
            needed: len,
            available: data.len().saturating_sub(offset),
        }),
    }
}
pub fn u8_at(d: &[u8], o: usize) -> Result<u8> {
    Ok(need(d, o, 1)?[0])
}
pub fn u16_at(d: &[u8], o: usize) -> Result<u16> {
    let b = need(d, o, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}
pub fn u32_at(d: &[u8], o: usize) -> Result<u32> {
    let b = need(d, o, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
pub fn u64_at(d: &[u8], o: usize) -> Result<u64> {
    let b = need(d, o, 8)?;
    Ok(u64::from_le_bytes(b.try_into().expect("8 bytes")))
}
pub fn i32_at(d: &[u8], o: usize) -> Result<i32> {
    Ok(u32_at(d, o)? as i32)
}
pub fn i64_at(d: &[u8], o: usize) -> Result<i64> {
    Ok(u64_at(d, o)? as i64)
}
pub fn u16_be_at(d: &[u8], o: usize) -> Result<u16> {
    let b = need(d, o, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}
pub fn u32_be_at(d: &[u8], o: usize) -> Result<u32> {
    let b = need(d, o, 4)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}
pub fn u64_be_at(d: &[u8], o: usize) -> Result<u64> {
    let b = need(d, o, 8)?;
    Ok(u64::from_be_bytes(b.try_into().expect("8 bytes")))
}

/// Decode UTF-16LE, stopping at the first NUL if `stop_at_nul`. Lossy on unpaired surrogates.
pub fn utf16le(bytes: &[u8], stop_at_nul: bool) -> String {
    let mut units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    if stop_at_nul {
        if let Some(p) = units.iter().position(|&u| u == 0) {
            units.truncate(p);
        }
    }
    String::from_utf16_lossy(&units)
}

/// Decode a NUL-terminated or length-bounded ASCII/Latin-1 string.
pub fn ascii(bytes: &[u8], stop_at_nul: bool) -> String {
    let end = if stop_at_nul {
        bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())
    } else {
        bytes.len()
    };
    bytes[..end].iter().map(|&b| b as char).collect()
}

pub fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}
