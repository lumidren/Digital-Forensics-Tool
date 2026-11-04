//! Fuzz the EVTX file/chunk/BinXml parser and the legacy EVT scanner.
#![no_main]
use libfuzzer_sys::fuzz_target;
use veritas_artifacts::evtx;

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = evtx::parse(data) {
        let _ = evtx::events(&f, "", "");
    }
    // Also exercise a chunk built from the input (bypasses the file-header signature check).
    let mut file = b"ElfFile\0".to_vec();
    file.resize(4096, 0);
    file.extend_from_slice(b"ElfChnk\0");
    file.extend_from_slice(data);
    let _ = evtx::parse(&file);
    let _ = evtx::parse_evt(data);
});
