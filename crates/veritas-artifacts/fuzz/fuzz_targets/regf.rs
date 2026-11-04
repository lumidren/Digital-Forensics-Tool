//! cargo-fuzz target: REGF hive parsing, walking, deleted-cell recovery, log replay and the
//! registry plugins must never panic. THREAT:T3.2
#![no_main]
use libfuzzer_sys::fuzz_target;
use veritas_artifacts::regf::Hive;
use veritas_artifacts::registry::{events_from_hive, HiveKind, Provenance};

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = Hive::parse(data) {
        let _ = h.walk(|_, _, k| {
            let _ = k.values();
        });
        let _ = h.recover_deleted();
        let kind = HiveKind::detect(&h);
        let _ = events_from_hive(&h, kind, &Provenance::default());
    }
    // Treat the input as both primary and log to exercise HvLE parsing.
    let _ = Hive::parse_with_logs(data, &[data]);
});
