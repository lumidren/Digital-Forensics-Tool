use proptest::prelude::*;
use rand::{Rng, RngCore, SeedableRng};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use veritas_aff4::zip::ZipWriter;
use veritas_aff4::{Aff4Error, Aff4Options, Aff4Reader, Aff4Writer, CaseDetails, Compression};

fn corpus(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/corpus")
        .join(rel)
}

fn data(len: usize, seed: u64, compressible: bool) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut v = vec![0u8; len];
    if compressible {
        for (i, b) in v.iter_mut().enumerate() {
            *b = if (i / 4096) % 3 == 0 {
                0
            } else {
                (i % 97) as u8 ^ (rng.gen::<u8>() & 0x3)
            };
        }
    } else {
        rng.fill_bytes(&mut v);
    }
    v
}

fn write(path: &Path, bytes: &[u8], opts: Aff4Options, piece: usize) -> veritas_aff4::Aff4Summary {
    let mut w = Aff4Writer::create(path, opts).unwrap();
    if piece == 0 {
        w.write(bytes).unwrap();
    } else {
        for p in bytes.chunks(piece) {
            w.write(p).unwrap();
        }
    }
    w.finish().unwrap()
}

fn read_all(r: &mut Aff4Reader) -> Vec<u8> {
    let mut out = Vec::new();
    r.seek(SeekFrom::Start(0)).unwrap();
    r.read_to_end(&mut out).unwrap();
    out
}

const WRITABLE: [Compression; 4] = [
    Compression::Stored,
    Compression::Deflate,
    Compression::RawDeflate,
    Compression::Snappy,
];

#[test]
fn roundtrip_sizes_compressions_and_bevies() {
    let dir = tempfile::tempdir().unwrap();
    let sizes = [0usize, 1, 511, 32768, 32768 * 3 + 17, 1_000_003];
    for (i, &size) in sizes.iter().enumerate() {
        for (j, comp) in WRITABLE.iter().enumerate() {
            let bytes = data(size, (i * 10 + j) as u64, j % 2 == 0);
            let opts = Aff4Options {
                compression: *comp,
                chunks_per_segment: 3, // several bevies for the larger inputs
                ..Default::default()
            };
            let p = dir.path().join(format!("rt{}_{}.aff4", i, j));
            let s = write(&p, &bytes, opts, 7777);
            let expect = veritas_hash::hash_bytes(&bytes);
            assert_eq!(s.media_size, size as u64);
            assert_eq!(s.hashes, expect);
            assert_eq!(s.chunk_count, (size as u64).div_ceil(32768));
            assert_eq!(s.bevy_count, s.chunk_count.div_ceil(3));
            let mut r = Aff4Reader::open(&p).unwrap();
            assert_eq!(r.media_size(), size as u64);
            assert_eq!(read_all(&mut r), bytes, "size {} {:?}", size, comp);
            assert_eq!(r.stored_md5().as_deref(), Some(expect.md5.as_str()));
            assert_eq!(r.stored_sha256().as_deref(), Some(expect.sha256.as_str()));
            let v = r.verify().unwrap();
            assert!(v.verified, "{:?}", v);
            assert_eq!(v.sha1_match, Some(true));
            assert!(veritas_aff4::is_aff4_file(&p));
        }
    }
}

#[test]
fn large_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = data(9 * 1024 * 1024 + 5, 99, true);
    for comp in [Compression::Deflate, Compression::Stored] {
        let p = dir.path().join(format!("large_{:?}.aff4", comp));
        let opts = Aff4Options {
            chunk_size: 4 * 1024 * 1024,
            chunks_per_segment: 2,
            compression: comp,
            ..Default::default()
        };
        let s = write(&p, &bytes, opts, 0);
        assert_eq!(s.chunk_count, 3);
        assert_eq!(s.bevy_count, 2);
        let mut r = Aff4Reader::open(&p).unwrap();
        assert_eq!(read_all(&mut r), bytes);
        assert!(r.verify().unwrap().verified);
    }
}

#[test]
fn random_access_matches_source() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = data(700_001, 5, false);
    let p = dir.path().join("ra.aff4");
    write(
        &p,
        &bytes,
        Aff4Options {
            chunks_per_segment: 4,
            compression: Compression::Snappy,
            ..Default::default()
        },
        4096,
    );
    let mut r = Aff4Reader::open(&p).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    for _ in 0..300 {
        let off = rng.gen_range(0..bytes.len() as u64 + 10);
        let len = rng.gen_range(0..100_000usize);
        let mut buf = vec![0u8; len];
        let n = r.read_at(off, &mut buf).unwrap();
        let start = (off as usize).min(bytes.len());
        let end = (start + len).min(bytes.len());
        assert_eq!(n, end - start);
        assert_eq!(&buf[..n], &bytes[start..end]);
    }
    assert_eq!(r.seek(SeekFrom::End(-10)).unwrap(), bytes.len() as u64 - 10);
    let mut tail = Vec::new();
    r.read_to_end(&mut tail).unwrap();
    assert_eq!(tail, &bytes[bytes.len() - 10..]);
}

#[test]
fn corpus_images_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["dfvfs/ntfs.raw", "dfvfs/ext2.raw"] {
        let src = std::fs::read(corpus(name)).unwrap();
        let p = dir.path().join(format!("{}.aff4", name.replace('/', "_")));
        let s = write(&p, &src, Aff4Options::default(), 1 << 20);
        assert!(s.container_size < src.len() as u64);
        let mut r = Aff4Reader::open(&p).unwrap();
        assert_eq!(read_all(&mut r), src, "{}", name);
        assert!(r.verify().unwrap().verified);
    }
}

#[test]
fn deterministic_with_fixed_time() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = data(300_000, 3, true);
    let t = chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let opts = Aff4Options {
        creation_time: Some(t),
        chunks_per_segment: 2,
        case: CaseDetails {
            case_number: "C-1".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let a = dir.path().join("a.aff4");
    let b = dir.path().join("b.aff4");
    write(&a, &bytes, opts.clone(), 1000);
    write(&b, &bytes, opts.clone(), 65536);
    assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    // Without a fixed time URNs are random, so containers differ.
    let c = dir.path().join("c.aff4");
    let d = dir.path().join("d.aff4");
    write(&c, &bytes, Aff4Options::default(), 0);
    write(&d, &bytes, Aff4Options::default(), 0);
    assert_ne!(std::fs::read(&c).unwrap(), std::fs::read(&d).unwrap());
}

#[test]
fn metadata_case_and_bad_sectors() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("meta.aff4");
    let case = CaseDetails {
        case_number: "CASE \"7\"".into(),
        evidence_number: "EV-1".into(),
        examiner: "Ex\\aminer".into(),
        description: "line1\nline2".into(),
        notes: "n".into(),
    };
    let mut w = Aff4Writer::create(
        &p,
        Aff4Options {
            case: case.clone(),
            ..Default::default()
        },
    )
    .unwrap();
    w.write(&vec![0u8; 512 * 20]).unwrap();
    w.record_bad_sectors(3, 2);
    w.record_bad_sectors(5, 1);
    w.record_bad_sectors(10, 1);
    let s = w.finish().unwrap();
    assert_eq!(s.bad_sectors.len(), 2);
    let r = Aff4Reader::open(&p).unwrap();
    assert_eq!(r.case(), &case);
    assert_eq!(r.acquisition_errors(), s.bad_sectors.as_slice());
    let info = r.info();
    assert_eq!(info.layout, "map");
    assert_eq!(info.image_urn.as_deref(), Some(s.image_urn.as_str()));
}

#[test]
fn refuses_overwrite_and_bad_options() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x.aff4");
    std::fs::write(&p, b"x").unwrap();
    assert!(matches!(
        Aff4Writer::create(&p, Aff4Options::default()),
        Err(Aff4Error::Exists(_))
    ));
    let q = dir.path().join("y.aff4");
    for opts in [
        Aff4Options {
            chunk_size: 100,
            ..Default::default()
        },
        Aff4Options {
            chunks_per_segment: 0,
            ..Default::default()
        },
        Aff4Options {
            compression: Compression::Lz4,
            ..Default::default()
        },
    ] {
        assert!(Aff4Writer::create(&q, opts).is_err());
        assert!(!q.exists());
    }
}

fn small_image() -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("small.aff4");
    let bytes = data(3 * 4096 + 100, 11, true);
    write(
        &p,
        &bytes,
        Aff4Options {
            chunk_size: 4096,
            chunks_per_segment: 2,
            ..Default::default()
        },
        0,
    );
    std::fs::read(&p).unwrap()
}

#[test]
fn truncated_input_is_an_error() {
    let full = small_image();
    for cut in (0..full.len()).step_by(37) {
        let r = Aff4Reader::from_reader(Box::new(Cursor::new(full[..cut].to_vec())));
        assert!(r.is_err(), "prefix of {} bytes opened", cut);
    }
    assert!(Aff4Reader::from_reader(Box::new(Cursor::new(full))).is_ok());
}

#[test]
fn corruption_is_detected() {
    let full = small_image();
    // Flip one byte inside the first bevy's chunk data (just after the bevy's local header).
    let name = b"/00000000";
    let pos = full
        .windows(name.len())
        .position(|w| w == name)
        .expect("bevy member");
    let mut bad = full.clone();
    bad[pos + name.len() + 20 + 10] ^= 0x55;
    // Either opening or verifying fails, or verification reports the damage.
    if let Ok(mut r) = Aff4Reader::from_reader(Box::new(Cursor::new(bad))) {
        if let Ok(v) = r.verify() {
            assert!(!v.verified, "{:?}", v);
            assert!(!v.crc_errors.is_empty() || v.md5_match == Some(false));
        }
    }
    // Change the stored MD5 in the Turtle: verification must fail.
    let mut r = Aff4Reader::from_reader(Box::new(Cursor::new(full.clone()))).unwrap();
    let md5 = r.stored_md5().unwrap();
    assert!(r.verify().unwrap().verified);
    let mut bad = full.clone();
    let at = bad
        .windows(md5.len())
        .position(|w| w == md5.as_bytes())
        .unwrap();
    bad[at] = if bad[at] == b'0' { b'1' } else { b'0' };
    // The ZIP CRC-32 of information.turtle catches the edit at open time...
    assert!(Aff4Reader::from_reader(Box::new(Cursor::new(bad.clone()))).is_err());
    // ...and with the CRC fixed up as well, the hash comparison catches it.
    let z = veritas_aff4::zip::ZipArchive::new(Box::new(Cursor::new(full.clone()))).unwrap();
    let old_crc = z
        .entry(z.find("information.turtle").unwrap())
        .unwrap()
        .crc32;
    let mut z = veritas_aff4::zip::ZipArchive::new(Box::new(Cursor::new(bad.clone()))).unwrap();
    let ti = z.find("information.turtle").unwrap();
    let start = z.data_start(ti).unwrap() as usize;
    let len = z.entry(ti).unwrap().size as usize;
    let new_crc = crc32fast::hash(&bad[start..start + len]);
    let mut fixed = 0;
    for i in 0..bad.len() - 4 {
        if bad[i..i + 4] == old_crc.to_le_bytes() {
            bad[i..i + 4].copy_from_slice(&new_crc.to_le_bytes());
            fixed += 1;
        }
    }
    assert!(fixed >= 2);
    let mut r = Aff4Reader::from_reader(Box::new(Cursor::new(bad))).unwrap();
    let v = r.verify().unwrap();
    assert_eq!(v.md5_match, Some(false));
    assert!(!v.verified);
    // Not a ZIP / a ZIP without AFF4 metadata.
    assert!(matches!(
        Aff4Reader::from_reader(Box::new(Cursor::new(vec![0u8; 4096]))),
        Err(Aff4Error::NotAff4(_))
    ));
    let mut zw = ZipWriter::new(Cursor::new(Vec::new()), (0, 0x21));
    zw.add_stored("readme.txt", b"hi").unwrap();
    let plain = zw.finish(b"").unwrap().into_inner();
    assert!(matches!(
        Aff4Reader::from_reader(Box::new(Cursor::new(plain))),
        Err(Aff4Error::NotAff4(_))
    ));
}

/// A hand-built container: a map with a gap (default stream), a symbolic range and an image
/// stream range at a non-zero target offset.
#[test]
fn map_with_gaps_and_symbolic_targets() {
    let stream_data: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
    let mut zw = ZipWriter::new(Cursor::new(Vec::new()), (0, 0x21));
    zw.add_stored("container.description", b"aff4://vol")
        .unwrap();
    zw.add_stored("version.txt", b"major=1\nminor=0\ntool=test\n")
        .unwrap();
    // Stored compression, 512-byte chunks, 4 chunks in one bevy.
    zw.add_stored("aff4%3A%2F%2Fstream/00000000", &stream_data)
        .unwrap();
    let mut idx = Vec::new();
    for k in 0..4u64 {
        idx.extend_from_slice(&(k * 512).to_le_bytes());
        idx.extend_from_slice(&512u32.to_le_bytes());
    }
    zw.add_stored("aff4%3A%2F%2Fstream/00000000.index", &idx)
        .unwrap();
    let mut map = Vec::new();
    for (mo, len, to, t) in [(0u64, 1000u64, 100u64, 0u32), (5000, 1000, 0, 1)] {
        map.extend_from_slice(&mo.to_le_bytes());
        map.extend_from_slice(&len.to_le_bytes());
        map.extend_from_slice(&to.to_le_bytes());
        map.extend_from_slice(&t.to_le_bytes());
    }
    zw.add_stored("aff4%3A%2F%2Fmap/map", &map).unwrap();
    zw.add_stored(
        "aff4%3A%2F%2Fmap/idx",
        b"aff4://stream\nhttp://aff4.org/Schema#UnknownData",
    )
    .unwrap();
    let ttl = r#"@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
<aff4://img> a aff4:Image ; aff4:dataStream <aff4://map> ; aff4:size "8000"^^xsd:long .
<aff4://map> a aff4:Map ; aff4:mapGapDefaultStream aff4:SymbolicStream41 .
<aff4://stream> a aff4:ImageStream ; aff4:chunkSize 512 ; aff4:chunksInSegment 4 ;
    aff4:compressionMethod <http://aff4.org/Schema#NullCompressor> ; aff4:size 2048 .
"#;
    zw.add_stored("information.turtle", ttl.as_bytes()).unwrap();
    let bytes = zw.finish(b"aff4://vol").unwrap().into_inner();
    let mut r = Aff4Reader::from_reader(Box::new(Cursor::new(bytes))).unwrap();
    assert_eq!(r.media_size(), 8000);
    let all = read_all(&mut r);
    assert_eq!(&all[..1000], &stream_data[100..1100]);
    assert!(all[1000..5000].iter().all(|&b| b == 0x41));
    // Symbolic streams are addressed by target offset (0 here), as pyaff4 does.
    let unknown: Vec<u8> = b"UNKNOWN".iter().cycle().take(1000).copied().collect();
    assert_eq!(&all[5000..6000], &unknown[..]);
    assert!(all[6000..].iter().all(|&b| b == 0x41));
    assert_eq!(r.info().map_ranges, 2);
    // No stored hash: verification cannot succeed.
    assert!(!r.verify().unwrap().verified);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 400, .. ProptestConfig::default() })]
    #[test]
    fn random_mutations_never_panic(
        mutations in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
        cut in any::<prop::sample::Index>(),
    ) {
        thread_local! {
            static BASE: Vec<u8> = small_image();
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
        if let Ok(mut r) = Aff4Reader::from_reader(Box::new(Cursor::new(bytes))) {
            let _ = r.info();
            let _ = r.verify();
            let mut buf = vec![0u8; 20_000];
            let _ = r.read_at(1000, &mut buf);
            let _ = r.read_at(u64::MAX - 5, &mut buf);
        }
    }

    #[test]
    fn turtle_never_panics(s in "\\PC{0,200}") {
        let _ = veritas_aff4::turtle::parse(&s);
    }
}
