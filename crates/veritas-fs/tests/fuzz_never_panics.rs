//! Property tests: random mutations (bit flips concentrated on metadata regions, truncation) of real
//! corpus images must never panic, hang or abort any parser. Errors are fine. THREAT:T3.2
mod common;
use common::*;
use proptest::prelude::*;
use std::sync::{Arc, OnceLock};
use veritas_fs::events::{self, Ctx};
use veritas_fs::image::{self, AnyFs};
use veritas_fs::io::{MemSource, Source};
use veritas_fs::ntfs::{self, Ntfs};

/// Byte ranges where flips land: (start, len). Metadata-heavy areas of each image.
fn hot(name: &str) -> Vec<(usize, usize)> {
    match name {
        "dfvfs/ntfs.raw" => vec![(0, 512), (4 * 4096, 70656)],
        "dfvfs/fat12.raw" => vec![(0, 32768)],
        "dfvfs/ext4.raw" | "dfvfs/ext2.raw" => vec![(0, 300 * 1024)],
        "plaso/syslog_image.dd" => vec![(0, 102400)],
        "dfvfs/apfs.raw" => vec![
            (0, 4096),
            (1 * 4096, 120 * 4096),
            (1026 * 4096, 4096),
            (1028 * 4096, 4096),
        ],
        "dfvfs/mbr.raw" | "dfvfs/gpt.raw" | "plaso/tsk_volume_system.raw" => vec![(0, 65536)],
        "dfvfs/vss.raw" => vec![
            (0, 512),
            (0x1E00, 128),
            (25051136, 65536),
            (8208384, 3 * 16384),
            (8290304, 16384),
            (37945344, 3 * 16384),
            (38043648, 2 * 16384),
        ],
        _ => vec![],
    }
}

fn base(name: &'static str) -> Arc<Vec<u8>> {
    static CACHE: OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<&'static str, Arc<Vec<u8>>>>,
    > = OnceLock::new();
    let m = CACHE.get_or_init(Default::default);
    let mut g = m.lock().unwrap();
    g.entry(name)
        .or_insert_with(|| Arc::new(bytes(name)))
        .clone()
}

fn mutate(name: &'static str, flips: &[(usize, u8)], trunc: Option<usize>) -> Vec<u8> {
    let b = base(name);
    let mut d = b.as_ref().clone();
    let regions = hot(name);
    let total: usize = if regions.is_empty() {
        d.len()
    } else {
        regions.iter().map(|r| r.1).sum()
    };
    for &(p, x) in flips {
        let mut p = p % total.max(1);
        let pos = if regions.is_empty() {
            p
        } else {
            let mut at = 0;
            for &(s, l) in &regions {
                if p < l {
                    at = s + p;
                    break;
                }
                p -= l;
            }
            at
        };
        if pos < d.len() {
            d[pos] ^= x;
        }
    }
    if let Some(t) = trunc {
        d.truncate(t % (d.len() + 1));
    }
    d
}

/// Run every parser entry point that applies; any `Err` is acceptable, a panic fails the test.
fn exercise(src: Source) {
    let _ = veritas_fs::volume::detect(src.as_ref());
    let Ok(vols) = image::volumes(src) else {
        return;
    };
    for v in vols {
        let Ok(fs) = AnyFs::open(&v) else { continue };
        let _ = fs.entries(true);
        let _ = events::volume_events(&Ctx::default(), &v);
        match &fs {
            AnyFs::Ntfs(n) => {
                let _ = n.list_dir(5);
                let _ = n.logfile();
                let _ = n.usn_records();
                let _ = n.read_file("/a_directory/a_file");
                if let Ok(e) = n.entries() {
                    let _ = ntfs::timestomp::detect(&e, &[]);
                }
                let _ = veritas_fs::recover::recover_ntfs(n);
                if veritas_fs::vss::probe(v.src.as_ref()) {
                    if let Ok(s) = veritas_fs::vss::Vss::open(v.src.clone()) {
                        for i in 0..s.stores.len().min(2) {
                            let _ = s.read_store(i, 0, 1 << 16);
                            let _ = s.read_store(i, 25460736, 1 << 16);
                        }
                    }
                }
            }
            AnyFs::Fat(f) => {
                let _ = f.read_file("/a_directory/a_file");
                let _ = veritas_fs::recover::recover_fat(f);
            }
            AnyFs::Ext(x) => {
                let _ = x.journal();
                let _ = x.deleted_inodes();
                let _ = x.read_file("/a_directory/a_file");
            }
            AnyFs::Apfs(a) => {
                for i in 0..a.volumes.len() {
                    let _ = a.snapshots(i);
                    let _ = a.read_file(i, "/a_directory/a_file");
                }
            }
        }
    }
}

/// `VERITAS_FUZZ_MULT=20 cargo test --test fuzz_never_panics` scales every case count.
fn mult() -> u32 {
    std::env::var("VERITAS_FUZZ_MULT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
}

fn flips() -> impl Strategy<Value = Vec<(usize, u8)>> {
    prop::collection::vec((any::<usize>(), 1u8..=255), 1..48)
}

macro_rules! image_fuzz {
    ($name:ident, $file:expr, $cases:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig { cases: $cases * mult(), failure_persistence: None, ..ProptestConfig::default() })]
            #[test]
            fn $name(f in flips(), trunc in prop::option::weighted(0.15, any::<usize>())) {
                exercise(MemSource::source(mutate($file, &f, trunc)));
            }
        }
    };
}

image_fuzz!(ntfs_image_never_panics, "dfvfs/ntfs.raw", 96);
image_fuzz!(fat12_image_never_panics, "dfvfs/fat12.raw", 96);
image_fuzz!(ext4_image_never_panics, "dfvfs/ext4.raw", 64);
image_fuzz!(ext2_image_never_panics, "dfvfs/ext2.raw", 48);
image_fuzz!(syslog_ext_image_never_panics, "plaso/syslog_image.dd", 48);
image_fuzz!(apfs_image_never_panics, "dfvfs/apfs.raw", 96);
image_fuzz!(mbr_image_never_panics, "dfvfs/mbr.raw", 48);
image_fuzz!(gpt_image_never_panics, "dfvfs/gpt.raw", 48);
image_fuzz!(
    tsk_volume_image_never_panics,
    "plaso/tsk_volume_system.raw",
    32
);
image_fuzz!(vss_image_never_panics, "dfvfs/vss.raw", 12);

proptest! {
    #![proptest_config(ProptestConfig { cases: 32 * mult(), failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn mft_extract_never_panics(f in flips(), trunc in prop::option::weighted(0.2, any::<usize>())) {
        let d = mutate("plaso/MFT", &f, trunc);
        let _ = ntfs::parse_mft_file(&d[..d.len().min(2 << 20)]);
    }

    #[test]
    fn usn_never_panics(f in flips(), trunc in prop::option::weighted(0.3, any::<usize>())) {
        let d = mutate("plaso/UsnJrnl.raw", &f, trunc);
        let r = ntfs::usn::parse_usn_records(&d, 0);
        let _ = events::usn_events(&Ctx::default(), &r, "x");
    }

    #[test]
    fn logfile_never_panics(f in prop::collection::vec((any::<usize>(), 1u8..=255), 1..96), trunc in prop::option::weighted(0.2, any::<usize>())) {
        static LOG: OnceLock<Vec<u8>> = OnceLock::new();
        let log = LOG.get_or_init(|| Ntfs::open(src("dfvfs/vss.raw")).unwrap().read_entry_data(2, "").unwrap());
        let mut d = log.clone();
        for (p, x) in f {
            // Concentrate on restart pages and the first record pages.
            let p = p % (16 * 4096).min(d.len());
            d[p] ^= x;
        }
        if let Some(t) = trunc { d.truncate(t % (d.len() + 1)); }
        let _ = ntfs::logfile::parse_logfile(&d, 512, 1024);
    }

    #[test]
    fn carve_never_panics(f in flips(), trunc in prop::option::weighted(0.2, any::<usize>())) {
        let mut d = mutate("plaso/syslog_image.dd", &f, trunc);
        d.extend_from_slice(&bytes("plaso/test_pe.exe"));
        d.extend_from_slice(b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR");
        d.extend_from_slice(b"\xFF\xD8\xFF\xE0\x00");
        d.extend_from_slice(b"SQLite format 3\0\x10\x00");
        let _ = veritas_fs::carve::carve(MemSource::source(d).as_ref());
    }

    #[test]
    fn lznt1_never_panics(data in prop::collection::vec(any::<u8>(), 0..8192)) {
        let _ = ntfs::lznt1::decompress(&data, 65536);
    }

    #[test]
    fn record_parsers_never_panic(data in prop::collection::vec(any::<u8>(), 0..1100)) {
        let mut d = data.clone();
        if d.len() >= 4 { d[0..4].copy_from_slice(b"FILE"); }
        let _ = ntfs::record::MftRecord::parse(&d, 1);
        let _ = ntfs::record::decode_runs(&data, 0);
        let _ = ntfs::record::FileName::parse(&data);
        let _ = ntfs::record::ReparsePoint::parse(&data);
        let _ = ntfs::record::parse_attribute_list(&data);
        let _ = ntfs::index::parse_index_root(&data);
        let _ = ntfs::index::parse_index_allocation(&data, 512, 512);
        let _ = veritas_fs::ext4::journal::parse(&data);
    }
}
