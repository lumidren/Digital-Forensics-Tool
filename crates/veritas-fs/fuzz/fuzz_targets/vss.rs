#![no_main]
use libfuzzer_sys::fuzz_target;
use veritas_fs::io::MemSource;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = veritas_fs::vss::Vss::open(MemSource::source(data.to_vec())) {
        for s in v.stores.iter().take(4) {
            let _ = v.read_store(s.index, 0, 65536.min(v.volume_size));
        }
    }
});
