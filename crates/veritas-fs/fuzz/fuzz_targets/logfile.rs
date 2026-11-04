#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = veritas_fs::ntfs::logfile::parse_logfile(data, 4096, 1024);
});
