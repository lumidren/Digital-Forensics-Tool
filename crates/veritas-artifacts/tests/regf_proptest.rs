//! Mutation robustness: no byte-level mutation or truncation of a real hive may panic the
//! parser, the walker, deleted-cell recovery, log replay or the registry plugins. THREAT:T3.2
use proptest::prelude::*;
use std::path::PathBuf;
use std::sync::OnceLock;
use veritas_artifacts::regf::Hive;
use veritas_artifacts::registry::{events_from_hive, HiveKind, Provenance};

fn sample() -> &'static Option<Vec<u8>> {
    static S: OnceLock<Option<Vec<u8>>> = OnceLock::new();
    S.get_or_init(|| {
        std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../testdata/corpus/plaso/NTUSER.DAT"),
        )
        .ok()
    })
}

fn exercise(data: &[u8]) {
    if let Ok(h) = Hive::parse(data) {
        let _ = h.walk(|_, _, k| {
            let _ = k.values();
            let _ = k.class_name.as_ref();
        });
        let _ = h.recover_deleted();
        let _ = events_from_hive(&h, HiveKind::NtUser, &Provenance::default());
    }
    let _ = Hive::parse_with_logs(data, &[data]);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, .. ProptestConfig::default() })]

    #[test]
    fn regf_mutated_ntuser_never_panics(muts in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..64)) {
        let Some(orig) = sample() else { return Ok(()) };
        let mut d = orig.clone();
        for (i, b) in muts {
            let idx = i.index(d.len());
            d[idx] = b;
        }
        exercise(&d);
    }

    #[test]
    fn regf_mutated_structures_never_panic(muts in prop::collection::vec((0usize..16384, any::<u32>()), 1..16)) {
        // Hit the base block and the first hive bins (root key, lists) with 32-bit writes.
        let Some(orig) = sample() else { return Ok(()) };
        let mut d = orig.clone();
        for (o, v) in muts {
            let o = (o & !3).min(d.len() - 4);
            d[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
        exercise(&d);
    }

    #[test]
    fn regf_truncated_never_panics(len in 0usize..65536) {
        let Some(orig) = sample() else { return Ok(()) };
        exercise(&orig[..len.min(orig.len())]);
    }

    #[test]
    fn regf_random_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..10000)) {
        let mut d = data;
        if d.len() >= 4 { d[..4].copy_from_slice(b"regf"); }
        exercise(&d);
    }
}
