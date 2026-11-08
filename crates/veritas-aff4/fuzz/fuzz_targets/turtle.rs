//! Turtle parser entry point: arbitrary text must parse or return Err, never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = veritas_aff4::turtle::parse(&String::from_utf8_lossy(data));
});
