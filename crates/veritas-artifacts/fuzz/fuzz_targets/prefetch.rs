//! Fuzz the prefetch parser, including the MAM/LZXPRESS Huffman decompressor.
//! THREAT:T3.2 every length field read by the parser is bounds-checked; this target proves
//! malformed input yields `Err`, never a panic or out-of-bounds access.
#![no_main]
use libfuzzer_sys::fuzz_target;
use veritas_artifacts::prefetch;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = prefetch::parse(data) {
        let _ = prefetch::events(&p, "", "");
    }
    if data.len() > 4 {
        let n = u16::from_le_bytes([data[0], data[1]]) as usize * 16;
        let _ = prefetch::lzxpress_huffman_decompress(&data[2..], n);
    }
});
