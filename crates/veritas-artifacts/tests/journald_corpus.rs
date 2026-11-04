//! systemd journal corpus tests. No reference library is available on Windows; expected values
//! were cross-checked against an independent pure-Python reader
//! (python/tests/parity/test_journald.py) and against Plaso's systemd journal parser test
//! expectations for system.journal (first entry "Started User Manager for UID 1000.").
use proptest::prelude::*;
use std::path::PathBuf;
use veritas_artifacts::journald;

fn corpus(rel: &str) -> Option<Vec<u8>> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/plaso").join(rel);
    match std::fs::read(&p) {
        Ok(d) => Some(d),
        Err(_) if std::env::var("VERITAS_REQUIRE_CORPUS").is_err() => {
            eprintln!("skipping: corpus file {} missing (run testdata/fetch.py)", p.display());
            None
        }
        Err(e) => panic!("corpus file {} missing: {e}", p.display()),
    }
}

#[test]
fn system_journal_xz() {
    let Some(d) = corpus("systemd/journal/system.journal") else { return };
    let j = journald::parse(&d).unwrap();
    assert_eq!(j.header.incompatible_flags, 1); // COMPRESSED_XZ
    assert_eq!(j.header.n_entries, 2101);
    assert_eq!(j.entries.len(), 2101);
    assert!(j.errors.is_empty());
    let e = &j.entries[0];
    assert_eq!(e.seqnum, 4585);
    assert_eq!(e.realtime_us, 1485510055913258);
    assert_eq!(e.get("MESSAGE"), Some("Started User Manager for UID 1000."));
    // XZ payloads are reported per field, not fatal.
    let xz = j.entries.iter().filter(|e| e.unsupported.iter().any(|u| u.contains("xz"))).count();
    assert_eq!(xz, 165);
    let ev = journald::events(&j, "sha", "system.journal");
    assert_eq!(ev.len(), 2101);
    assert_eq!(ev[0].data_type, "systemd:journal");
    assert_eq!(ev[0].timestamp, Some(1485510055913258000));
    assert_eq!(ev[0].attrs["body"], "Started User Manager for UID 1000.");
}

#[test]
fn system_journal_lz4() {
    let Some(d) = corpus("systemd/journal/system.journal.lz4") else { return };
    let j = journald::parse(&d).unwrap();
    assert_eq!(j.header.incompatible_flags, 2); // COMPRESSED_LZ4
    assert_eq!(j.entries.len(), 85);
    assert_eq!(j.entries[0].get("MESSAGE"), Some("Reached target Paths."));
    assert_eq!(j.entries[0].realtime_us, 1530630016682340);
    assert!(j.entries.iter().all(|e| e.unsupported.is_empty()));
}

#[test]
fn dirty_journal_tolerated() {
    let Some(d) = corpus("systemd/journal/system@00053f9c9a4c1e0e-2e18a70e8b327fed.journal~") else { return };
    let j = journald::parse(&d).unwrap();
    assert_eq!(j.header.n_entries, 2257);
    assert_eq!(j.entries.len(), 2212);
    assert_eq!(j.errors.len(), 45);
    assert_eq!(j.entries[0].get("MESSAGE"), Some("Runtime journal (/run/log/journal/) is 1.2M, max 9.9M, 8.6M free."));
}

#[test]
fn compact_zstd_journal() {
    let Some(d) = corpus("systemd/journal/user-1000.journal") else { return };
    let j = journald::parse(&d).unwrap();
    assert!(j.header.compact);
    assert_eq!(j.entries.len(), 1);
    let e = &j.entries[0];
    assert_eq!(e.get("SYSLOG_IDENTIFIER"), Some("testapp"));
    assert_eq!(e.get("_HOSTNAME"), Some("DESKTOP-QCDE2BT"));
    assert_eq!(e.realtime_us, 1695714166445209);
    // MESSAGE is ZSTD-compressed: unsupported, reported as an attribute.
    assert_eq!(e.get("MESSAGE"), None);
    assert!(e.unsupported[0].contains("zstd"));
    let ev = journald::events(&j, "s", "p");
    assert!(ev[0].attrs.contains_key("unsupported_fields"));
}

#[test]
fn determinism() {
    let Some(d) = corpus("systemd/journal/system.journal.lz4") else { return };
    let a = serde_json::to_string(&journald::events(&journald::parse(&d).unwrap(), "s", "p")).unwrap();
    let b = serde_json::to_string(&journald::events(&journald::parse(&d).unwrap(), "s", "p")).unwrap();
    assert_eq!(a, b);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]
    #[test]
    fn journal_mutations_never_panic(muts in proptest::collection::vec((0usize..8_388_608, any::<u8>()), 1..64), cut in 0usize..8_388_608) {
        if let Some(mut d) = corpus("systemd/journal/system.journal.lz4") {
            let n = d.len();
            // Concentrate half the mutations in the header and first objects.
            for (i, (o, b)) in muts.iter().enumerate() { let o = if i % 2 == 0 { o % 65536 } else { o % n }; d[o] = *b; }
            if let Ok(j) = journald::parse(&d) { let _ = journald::events(&j, "", ""); }
            let _ = journald::parse(&d[..cut % n]);
        }
    }

    #[test]
    fn lz4_random_never_panics(d in proptest::collection::vec(any::<u8>(), 0..1024), n in 0usize..100_000) {
        let _ = journald::lz4_block_decompress(&d, n, 1 << 20);
    }
}
