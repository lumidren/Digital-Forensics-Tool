//! Regressions found by cargo-fuzz (`scripts/fuzz_smoke.py`). Inputs must parse to Ok or Err,
//! never panic. The 2026-11 finding: an entry-array offset near usize::MAX made `o + 8` overflow.

use std::path::PathBuf;

fn sample() -> Option<Vec<u8>> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/plaso/systemd/journal/system.journal");
    std::fs::read(p).ok()
}

fn with_u64(mut d: Vec<u8>, at: usize, v: u64) -> Vec<u8> {
    d[at..at + 8].copy_from_slice(&v.to_le_bytes());
    d
}

#[test]
fn hostile_entry_array_offsets_do_not_panic() {
    let Some(base) = sample() else { return };
    for v in [u64::MAX, u64::MAX - 4, u64::MAX - 15, (usize::MAX as u64).wrapping_sub(7), base.len() as u64, base.len() as u64 - 1, 1 << 62] {
        let d = with_u64(base.clone(), 176, v); // header.entry_array_offset
        let j = veritas_artifacts::journald::parse(&d).expect("header still valid");
        assert!(j.entries.is_empty());
        assert!(!j.errors.is_empty(), "offset {v:#x} should be reported");
    }
}

#[test]
fn hostile_entry_offsets_inside_array_do_not_panic() {
    let Some(base) = sample() else { return };
    let j = veritas_artifacts::journald::parse(&base).unwrap();
    assert!(!j.entries.is_empty());
    let arr = u64::from_le_bytes(base[176..184].try_into().unwrap()) as usize;
    // Overwrite the first entry offsets in the first entry array with values near usize::MAX.
    let mut d = base.clone();
    for k in 0..4 {
        let at = arr + 24 + k * if j.header.compact { 4 } else { 8 };
        if j.header.compact {
            d[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        } else {
            d[at..at + 8].copy_from_slice(&(u64::MAX - k as u64).to_le_bytes());
        }
    }
    let _ = veritas_artifacts::journald::parse(&d);
}
