#![no_main]
use libfuzzer_sys::fuzz_target;
use veritas_fs::io::MemSource;

fuzz_target!(|data: &[u8]| {
    let src = MemSource::source(data.to_vec());
    let _ = veritas_fs::carve::carve(src.as_ref());
});
