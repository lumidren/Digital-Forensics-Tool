//! Fuzz the Windows Shell Link parser (header, link info, strings, extra data blocks).
#![no_main]
use libfuzzer_sys::fuzz_target;
use veritas_artifacts::lnk;

fuzz_target!(|data: &[u8]| {
    if let Ok(l) = lnk::parse(data) {
        let _ = lnk::events(&l, "", "", 0);
    }
    let _ = lnk::parse_property_store(data);
});
