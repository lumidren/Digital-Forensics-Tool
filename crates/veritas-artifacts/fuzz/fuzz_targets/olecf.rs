//! Fuzz the OLE compound file reader and the jump list parsers built on it.
#![no_main]
use libfuzzer_sys::fuzz_target;
use veritas_artifacts::{jumplist, olecf};

fuzz_target!(|data: &[u8]| {
    if let Ok(o) = olecf::Olecf::parse(data) {
        for (_, i) in o.walk() {
            let _ = o.read_stream(i);
        }
        let _ = o.summary_information();
    }
    if let Ok(a) = jumplist::parse_automatic(data) {
        let _ = jumplist::automatic_events(&a, "", "");
    }
    let _ = jumplist::parse_custom(data);
    let _ = jumplist::parse_dest_list(data);
});
