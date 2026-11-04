//! Fuzz the systemd journal parser and the LZ4 block decoder.
#![no_main]
use libfuzzer_sys::fuzz_target;
use veritas_artifacts::journald;

fuzz_target!(|data: &[u8]| {
    if let Ok(j) = journald::parse(data) {
        let _ = journald::events(&j, "", "");
    }
    let _ = journald::lz4_block_decompress(data, 0, 1 << 20);
});
