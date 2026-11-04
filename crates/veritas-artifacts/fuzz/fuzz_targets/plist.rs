//! Fuzz binary/XML plist parsing, NSKeyedArchiver unarchiving and event extraction.
#![no_main]
use libfuzzer_sys::fuzz_target;
use veritas_artifacts::plist;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = plist::parse(data) {
        let _ = p.to_json();
        let _ = plist::unarchive(&p);
        let _ = plist::events(&p, "", "com.apple.bluetooth.plist");
    }
});
