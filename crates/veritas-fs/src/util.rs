//! Bounds-checked little/big-endian readers (same contract as `veritas-artifacts::util`):
//! every accessor returns `Err(FsError::Truncated)` instead of panicking.
use crate::error::{FsError, Result};

pub fn need(data: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    match offset.checked_add(len) {
        Some(end) if end <= data.len() => Ok(&data[offset..end]),
        _ => Err(FsError::Truncated { offset: offset as u64, needed: len as u64, available: data.len().saturating_sub(offset) as u64 }),
    }
}
pub fn u8_at(d: &[u8], o: usize) -> Result<u8> { Ok(need(d, o, 1)?[0]) }
pub fn u16_at(d: &[u8], o: usize) -> Result<u16> { let b = need(d, o, 2)?; Ok(u16::from_le_bytes([b[0], b[1]])) }
pub fn u32_at(d: &[u8], o: usize) -> Result<u32> { let b = need(d, o, 4)?; Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]])) }
pub fn u64_at(d: &[u8], o: usize) -> Result<u64> {
    let b = need(d, o, 8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Ok(u64::from_le_bytes(a))
}
pub fn i32_at(d: &[u8], o: usize) -> Result<i32> { Ok(u32_at(d, o)? as i32) }
pub fn i64_at(d: &[u8], o: usize) -> Result<i64> { Ok(u64_at(d, o)? as i64) }
pub fn u16_be_at(d: &[u8], o: usize) -> Result<u16> { let b = need(d, o, 2)?; Ok(u16::from_be_bytes([b[0], b[1]])) }
pub fn u32_be_at(d: &[u8], o: usize) -> Result<u32> { let b = need(d, o, 4)?; Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]])) }
pub fn u64_be_at(d: &[u8], o: usize) -> Result<u64> {
    let b = need(d, o, 8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Ok(u64::from_be_bytes(a))
}

/// Decode UTF-16LE, optionally stopping at the first NUL. Lossy on unpaired surrogates.
pub fn utf16le(bytes: &[u8], stop_at_nul: bool) -> String {
    let mut units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    if stop_at_nul {
        if let Some(p) = units.iter().position(|&u| u == 0) {
            units.truncate(p);
        }
    }
    String::from_utf16_lossy(&units)
}

/// Decode an ASCII/Latin-1 string, optionally stopping at the first NUL.
pub fn ascii(bytes: &[u8], stop_at_nul: bool) -> String {
    let end = if stop_at_nul { bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len()) } else { bytes.len() };
    bytes[..end].iter().map(|&b| b as char).collect()
}

/// Decode UTF-8 lossily, stopping at the first NUL.
pub fn utf8z(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

pub fn hex_upper(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{:02X}", b)).collect() }

/// Format a little-endian (Microsoft mixed-endian) GUID as `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
pub fn guid_le(b: &[u8]) -> Result<String> {
    let b = need(b, 0, 16)?;
    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ))
}

/// Format a big-endian (RFC 4122 byte order) UUID.
pub fn uuid_be(b: &[u8]) -> Result<String> {
    let b = need(b, 0, 16)?;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ))
}

/// Round `v` up to a multiple of `align` (power of two), saturating.
pub fn align_up(v: usize, align: usize) -> usize {
    if align == 0 {
        return v;
    }
    match v.checked_add(align - 1) {
        Some(x) => x & !(align - 1),
        None => usize::MAX & !(align - 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readers_are_bounds_checked() {
        let d = [1u8, 2, 3];
        assert!(u32_at(&d, 0).is_err());
        assert_eq!(u16_at(&d, 1).unwrap(), 0x0302);
        assert!(u16_at(&d, usize::MAX).is_err());
        assert_eq!(align_up(13, 8), 16);
        assert_eq!(guid_le(&[0x6b, 0x87, 0x08, 0x38, 0x76, 0xc1, 0x48, 0x4e, 0xb7, 0xae, 0x04, 0x04, 0x6e, 0x6c, 0xc7, 0x52]).unwrap(), "3808876b-c176-4e48-b7ae-04046e6cc752");
    }
}
