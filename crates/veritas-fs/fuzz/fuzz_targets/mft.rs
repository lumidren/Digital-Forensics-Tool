#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = veritas_fs::ntfs::parse_mft_file(data);
});
