//! Whole-container entry point: ZIP64 directory, Turtle metadata, map and image-stream
//! resolution, then a full verify and a few random-access reads. Malformed input must return
//! Err, never panic, and allocations stay within the reader's caps.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use veritas_aff4::Aff4Reader;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut r) = Aff4Reader::from_reader(Box::new(Cursor::new(data.to_vec()))) {
        let _ = r.info();
        let mut buf = vec![0u8; 65536];
        let _ = r.read_at(0, &mut buf);
        let _ = r.read_at(r.media_size().saturating_sub(100), &mut buf);
        if r.media_size() <= 64 * 1024 * 1024 {
            let _ = r.verify();
        }
    }
});
