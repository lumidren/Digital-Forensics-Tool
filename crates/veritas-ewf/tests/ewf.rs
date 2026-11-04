use proptest::prelude::*;
use rand::{Rng, RngCore, SeedableRng};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use veritas_ewf::{Compression, EwfError, EwfOptions, EwfReader, EwfWriter, RawSegmented};

fn corpus(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus").join(rel)
}

fn random_data(len: usize, seed: u64, compressible: bool) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut v = vec![0u8; len];
    if compressible {
        for (i, b) in v.iter_mut().enumerate() {
            *b = if (i / 4096) % 3 == 0 { 0 } else { (i % 97) as u8 ^ rng.gen::<u8>() & 0x3 };
        }
    } else {
        rng.fill_bytes(&mut v);
    }
    v
}

fn write_e01(dir: &Path, name: &str, data: &[u8], opts: EwfOptions, write_size: usize) -> veritas_ewf::EwfSummary {
    let mut w = EwfWriter::create(dir.join(name), opts).unwrap();
    if write_size == 0 {
        w.write(data).unwrap();
    } else {
        for piece in data.chunks(write_size) {
            w.write(piece).unwrap();
        }
    }
    w.finish().unwrap()
}

fn read_all(r: &mut EwfReader) -> Vec<u8> {
    let mut out = Vec::new();
    r.seek(SeekFrom::Start(0)).unwrap();
    r.read_to_end(&mut out).unwrap();
    out
}

#[test]
fn roundtrip_various_sizes_and_compressions() {
    let dir = tempfile::tempdir().unwrap();
    let sizes = [0usize, 512, 32768, 32768 * 3 + 512, 1_000_448, 777 * 512];
    for (i, &size) in sizes.iter().enumerate() {
        for (j, comp) in [Compression::None, Compression::Fast, Compression::Best].iter().enumerate() {
            let data = random_data(size, i as u64 * 7 + j as u64, j % 2 == 0);
            let opts = EwfOptions { compression: *comp, ..Default::default() };
            let name = format!("img_{}_{}", i, j);
            let summary = write_e01(dir.path(), &name, &data, opts, 10_007);
            assert_eq!(summary.media_size, size as u64);
            assert_eq!(summary.hashes, veritas_hash::hash_bytes(&data));
            let mut r = EwfReader::open(dir.path().join(format!("{}.E01", name))).unwrap();
            assert_eq!(r.media_size(), size as u64);
            assert_eq!(read_all(&mut r), data, "size {} compression {:?}", size, comp);
            let rep = r.verify().unwrap();
            assert!(rep.verified, "{:?}", rep);
            assert_eq!(rep.computed_sha1, summary.sha1);
        }
    }
}

#[test]
fn unaligned_input_is_zero_padded_to_sector() {
    let dir = tempfile::tempdir().unwrap();
    let data = random_data(32768 + 100, 3, false);
    let s = write_e01(dir.path(), "pad", &data, EwfOptions::default(), 0);
    assert_eq!(s.input_bytes, data.len() as u64);
    assert_eq!(s.padding_bytes, 412);
    let mut padded = data.clone();
    padded.resize(32768 + 512, 0);
    assert_eq!(s.hashes, veritas_hash::hash_bytes(&padded));
    let mut r = EwfReader::open(&s.segments[0]).unwrap();
    assert_eq!(read_all(&mut r), padded);
}

#[test]
fn multi_segment_with_tiny_segment_size() {
    let dir = tempfile::tempdir().unwrap();
    let data = random_data(3 * 1024 * 1024 + 4096, 11, false);
    let opts = EwfOptions { segment_size: 256 * 1024, compression: Compression::Fast, ..Default::default() };
    let s = write_e01(dir.path(), "multi", &data, opts, 65_536);
    assert!(s.segments.len() >= 12, "segments: {}", s.segments.len());
    for p in &s.segments {
        assert!(std::fs::metadata(p).unwrap().len() <= 256 * 1024, "{} too large", p.display());
    }
    let mut r = EwfReader::open(&s.segments[0]).unwrap();
    assert_eq!(r.segment_paths().len(), s.segments.len());
    assert_eq!(read_all(&mut r), data);
    assert!(r.verify().unwrap().verified);
    // Random access across segment boundaries.
    let mut buf = vec![0u8; 100_000];
    let off = 1_234_567u64;
    assert_eq!(r.read_at(off, &mut buf).unwrap(), buf.len());
    assert_eq!(&buf[..], &data[off as usize..off as usize + buf.len()]);
}

#[test]
fn more_than_one_hundred_segments_use_letter_extensions() {
    let dir = tempfile::tempdir().unwrap();
    let data = random_data(7 * 1024 * 1024, 5, false);
    let opts = EwfOptions { segment_size: 64 * 1024, compression: Compression::None, sectors_per_chunk: 8, ..Default::default() };
    let s = write_e01(dir.path(), "many", &data, opts, 0);
    assert!(s.segments.len() > 100);
    assert!(s.segments.iter().any(|p| p.extension().unwrap() == "EAA"));
    let mut r = EwfReader::open(&s.segments[0]).unwrap();
    assert_eq!(read_all(&mut r), data);
}

#[test]
fn bad_sectors_are_recorded_in_error2() {
    let dir = tempfile::tempdir().unwrap();
    let mut w = EwfWriter::create(dir.path().join("bad"), EwfOptions::default()).unwrap();
    w.write(&vec![0u8; 512 * 100]).unwrap();
    w.record_bad_sectors(10, 2);
    w.record_bad_sectors(12, 1);
    w.record_bad_sectors(50, 1);
    let s = w.finish().unwrap();
    assert_eq!(s.bad_sectors.len(), 2);
    let r = EwfReader::open(&s.segments[0]).unwrap();
    assert_eq!(r.acquisition_errors(), &s.bad_sectors[..]);
    assert_eq!(r.acquisition_errors()[0].sector_count, 3);
}

#[test]
fn header_values_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let mut opts = EwfOptions::default();
    opts.header.case_number = "CASE-42".into();
    opts.header.evidence_number = "EV-7".into();
    opts.header.examiner_name = "Alice Examiner".into();
    opts.header.notes = "seized from desk".into();
    opts.header.description = "laptop disk".into();
    let s = write_e01(dir.path(), "hdr", &random_data(65536, 1, true), opts, 0);
    let r = EwfReader::open(&s.segments[0]).unwrap();
    let h = r.header();
    assert_eq!(h.case_number, "CASE-42");
    assert_eq!(h.evidence_number, "EV-7");
    assert_eq!(h.examiner_name, "Alice Examiner");
    assert_eq!(h.notes, "seized from desk");
    assert_eq!(h.description, "laptop disk");
    assert!(h.acquiry_date.is_some());
    assert!(h.acquiry_software_version.starts_with("veritas-ewf"));
}

#[test]
fn refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    write_e01(dir.path(), "x", b"", EwfOptions::default(), 0);
    assert!(matches!(EwfWriter::create(dir.path().join("x"), EwfOptions::default()), Err(EwfError::Exists(_))));
}

#[test]
fn reads_dfvfs_ext2_e01_identical_to_raw() {
    let raw = std::fs::read(corpus("dfvfs/ext2.raw")).unwrap();
    for name in ["dfvfs/ext2.E01", "dfvfs/ext2.split.E01"] {
        let mut r = EwfReader::open(corpus(name)).unwrap();
        assert_eq!(r.media_size(), raw.len() as u64, "{}", name);
        assert_eq!(read_all(&mut r), raw, "{}", name);
        let rep = r.verify().unwrap();
        assert!(rep.verified, "{}: {:?}", name, rep);
        assert_eq!(r.header().case_number, "case");
        assert_eq!(r.header().examiner_name, "examiner");
    }
    let r = EwfReader::open(corpus("dfvfs/ext2.split.E01")).unwrap();
    assert_eq!(r.segment_paths().len(), 2);
}

#[test]
fn plaso_images_open_and_verify() {
    let mut r = EwfReader::open(corpus("plaso/image.E01")).unwrap();
    assert_eq!(r.media_size(), 102_400);
    assert_eq!(r.header().examiner_name, "John Doe");
    let rep = r.verify().unwrap();
    assert!(rep.verified, "{:?}", rep);
    assert_eq!(rep.computed.md5, "d73c51f10c7ee6a681b7b619ccc6f1c4");

    let mut r = EwfReader::open(corpus("plaso/image-split.E01")).unwrap();
    assert_eq!(r.segment_paths().len(), 2);
    assert!(r.verify().unwrap().verified);
}

#[test]
fn raw_segmented_matches_single_raw() {
    let raw = std::fs::read(corpus("dfvfs/ext2.raw")).unwrap();
    let mut split = RawSegmented::open(corpus("dfvfs/ext2.splitraw.000")).unwrap();
    assert_eq!(split.segment_paths().len(), 2);
    assert_eq!(split.media_size(), raw.len() as u64);
    let mut all = Vec::new();
    split.read_to_end(&mut all).unwrap();
    assert_eq!(all, raw);
    let mut buf = vec![0u8; 8192];
    let off = 2 * 1024 * 1024 - 4096;
    assert_eq!(split.read_at(off as u64, &mut buf).unwrap(), 8192);
    assert_eq!(&buf[..], &raw[off..off + 8192]);
    let mut single = RawSegmented::open(corpus("dfvfs/ext2.raw")).unwrap();
    assert_eq!(single.segment_paths().len(), 1);
    let mut all = Vec::new();
    single.read_to_end(&mut all).unwrap();
    assert_eq!(all, raw);
}

#[test]
fn truncated_and_corrupted_inputs_fail_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let src = std::fs::read(corpus("dfvfs/ext2.E01")).unwrap();
    // Truncations at many points: open or full read must return Err, never panic.
    for cut in [0usize, 5, 13, 50, 100, 600, 800, 1900, 5000, 9600, 10300, 11000, 12000, src.len() - 1] {
        let p = dir.path().join(format!("t{}.E01", cut));
        std::fs::write(&p, &src[..cut]).unwrap();
        let ok = EwfReader::open(&p).and_then(|mut r| r.verify().map(|v| v.verified));
        assert!(!matches!(ok, Ok(true)), "truncated at {} still verified", cut);
    }
    // Flip a byte inside chunk data: verify must not pass.
    let mut bad = src.clone();
    bad[3000] ^= 0xff;
    let p = dir.path().join("flip.E01");
    std::fs::write(&p, &bad).unwrap();
    let res = EwfReader::open(&p).and_then(|mut r| r.verify());
    assert!(!matches!(res, Ok(ref v) if v.verified));
    // Missing second segment of a split set.
    let p1 = dir.path().join("split.E01");
    std::fs::copy(corpus("dfvfs/ext2.split.E01"), &p1).unwrap();
    assert!(matches!(EwfReader::open(&p1), Err(EwfError::MissingSegment(_))));
    // Not an EWF file.
    let p = dir.path().join("plain.E01");
    std::fs::write(&p, b"definitely not ewf").unwrap();
    assert!(EwfReader::open(&p).is_err());
}

#[test]
fn uncompressed_chunk_checksum_detects_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let data = random_data(65536, 9, false);
    let s = write_e01(dir.path(), "u", &data, EwfOptions { compression: Compression::None, ..Default::default() }, 0);
    let mut bytes = std::fs::read(&s.segments[0]).unwrap();
    let i = bytes.windows(8).position(|w| w == &data[100..108]).unwrap();
    bytes[i] ^= 1;
    let p = dir.path().join("u2.E01");
    std::fs::write(&p, &bytes).unwrap();
    let mut r = EwfReader::open(&p).unwrap();
    assert!(matches!(r.verify(), Err(EwfError::Checksum { .. })));
}

fn small_image() -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let mut opts = EwfOptions::default();
    opts.header.case_number = "p".into();
    let s = write_e01(dir.path(), "m", &random_data(3 * 32768 + 1024, 2, true), opts, 0);
    std::fs::read(&s.segments[0]).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 300, .. ProptestConfig::default() })]
    #[test]
    fn random_mutations_never_panic(mutations in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8), cut in any::<prop::sample::Index>()) {
        thread_local! {
            static BASE: Vec<u8> = small_image();
            static DIR: tempfile::TempDir = tempfile::tempdir().unwrap();
        }
        let mut bytes = BASE.with(|b| b.clone());
        for (idx, val) in &mutations {
            let i = idx.index(bytes.len());
            bytes[i] = *val;
        }
        if cut.index(4) == 0 {
            let n = cut.index(bytes.len());
            bytes.truncate(n);
        }
        let p = DIR.with(|d| d.path().join(format!("fuzz{}.E01", rand::random::<u64>())));
        std::fs::write(&p, &bytes).unwrap();
        if let Ok(mut r) = EwfReader::open(&p) {
            let _ = r.verify();
            let mut buf = vec![0u8; 70_000];
            let _ = r.read_at(1000, &mut buf);
            let _ = r.read_at(u64::MAX - 10, &mut buf);
        }
        let _ = std::fs::remove_file(&p);
    }
}
