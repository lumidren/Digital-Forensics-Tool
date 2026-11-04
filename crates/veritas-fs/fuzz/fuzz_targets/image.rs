//! Whole-image entry point: partition tables, then every recognised file system (NTFS, FAT/exFAT,
//! ext2/3/4, APFS) fully walked into timeline events. Malformed input must return Err, never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use veritas_fs::{events, image, io::MemSource};

fuzz_target!(|data: &[u8]| {
    if let Ok(vols) = image::volumes(MemSource::source(data.to_vec())) {
        let ctx = events::Ctx::default();
        for v in vols.iter().take(8) {
            let _ = events::volume_events(&ctx, v);
        }
    }
});
