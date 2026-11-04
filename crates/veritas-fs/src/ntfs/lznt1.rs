//! LZNT1 decompression (NTFS compressed attributes). Output is capped by the caller. THREAT:T3.5
use crate::error::{FsError, Result};

const CHUNK: usize = 4096;

/// Decompress an LZNT1 buffer, producing at most `max_out` bytes.
pub fn decompress(input: &[u8], max_out: usize) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(max_out.min(1 << 20));
    let mut pos = 0usize;
    while pos + 2 <= input.len() && out.len() < max_out {
        let hdr = u16::from_le_bytes([input[pos], input[pos + 1]]);
        if hdr == 0 {
            break;
        }
        let size = (hdr & 0x0FFF) as usize + 1;
        let compressed = hdr & 0x8000 != 0;
        let start = pos + 2;
        let end = start.checked_add(size).filter(|&e| e <= input.len()).ok_or_else(|| FsError::invalid(pos as u64, "LZNT1 chunk exceeds input"))?;
        let chunk = &input[start..end];
        if !compressed {
            let take = chunk.len().min(max_out - out.len());
            out.extend_from_slice(&chunk[..take]);
        } else {
            decompress_chunk(chunk, &mut out, max_out)?;
        }
        pos = end;
    }
    out.truncate(max_out);
    Ok(out)
}

fn decompress_chunk(chunk: &[u8], out: &mut Vec<u8>, max_out: usize) -> Result<()> {
    let base = out.len();
    let mut i = 0usize;
    while i < chunk.len() {
        let flags = chunk[i];
        i += 1;
        for bit in 0..8 {
            if i >= chunk.len() || out.len() >= max_out || out.len() - base >= CHUNK {
                return Ok(());
            }
            if flags & (1 << bit) == 0 {
                out.push(chunk[i]);
                i += 1;
            } else {
                if i + 1 >= chunk.len() {
                    return Err(FsError::invalid(i as u64, "LZNT1 truncated token"));
                }
                let token = u16::from_le_bytes([chunk[i], chunk[i + 1]]) as usize;
                i += 2;
                let cur = out.len() - base;
                if cur == 0 {
                    return Err(FsError::invalid(i as u64, "LZNT1 back-reference at chunk start"));
                }
                let mut len_mask = 0x0FFFusize;
                let mut shift = 12u32;
                let mut p = cur - 1;
                while p >= 0x10 {
                    len_mask >>= 1;
                    shift -= 1;
                    p >>= 1;
                }
                let length = (token & len_mask) + 3;
                let disp = (token >> shift) + 1;
                if disp > cur {
                    return Err(FsError::invalid(i as u64, "LZNT1 displacement before chunk start"));
                }
                let from = out.len() - disp;
                for k in 0..length {
                    if out.len() >= max_out || out.len() - base >= CHUNK {
                        break;
                    }
                    let b = out[from + k];
                    out.push(b);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncompressed_chunk() {
        let mut v = vec![0x02, 0x30]; // size 3, not compressed
        v.extend_from_slice(b"abc");
        assert_eq!(decompress(&v, 100).unwrap(), b"abc");
    }

    #[test]
    fn compressed_repeat() {
        // "abcabcabcabc": literals a,b,c then back-ref disp 3 len 9.
        // Flags byte: bits 0..2 literals, bit 3 token.  At cur=3, p=2 < 0x10: len_mask 0xFFF, shift 12.
        // token = ((3-1) << 12) | (9-3) = 0x2006.
        let body = [0x08u8, b'a', b'b', b'c', 0x06, 0x20];
        let mut v = vec![(body.len() - 1) as u8, 0xB0];
        v.extend_from_slice(&body);
        assert_eq!(decompress(&v, 100).unwrap(), b"abcabcabcabc");
    }

    #[test]
    fn malformed_does_not_panic() {
        assert!(decompress(&[0xFF, 0xBF, 0xFF], 100).is_err());
        let _ = decompress(&[0x05, 0xB0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], 100);
    }
}
