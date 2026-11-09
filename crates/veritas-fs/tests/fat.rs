mod common;
use common::*;
use veritas_fs::fat::{FatFs, FatType};
use veritas_fs::io::MemSource;
use veritas_timeline::fat_datetime_to_ns;

// Expected names / sizes / identifiers from pyfsfat 20260826 on dfvfs fat12.raw
// (pyfsfat `identifier` == byte offset of the short directory entry).

#[test]
fn fat12_listing() {
    let fs = FatFs::open(src("dfvfs/fat12.raw")).unwrap();
    assert_eq!(fs.kind, FatType::Fat12);
    assert_eq!(fs.label, "FAT12_TEST");
    let w = fs.walk(false).unwrap();
    let got: Vec<(&str, u64, u64, bool)> = w
        .iter()
        .map(|e| (e.path.as_str(), e.size, e.dir_entry_offset, e.is_dir))
        .collect();
    assert_eq!(
        got,
        vec![
            ("/a_directory", 0, 6720, true),
            ("/a_directory/a_file", 53, 25184, false),
            ("/a_directory/another_file", 22, 25248, false),
            ("/passwords.txt", 116, 6784, false),
        ]
    );
    let pw = &w[3];
    assert_eq!(pw.short_name, "PASSWO~1.TXT");
    // FAT times are local time stored as-is (treated as UTC): 2021-04-18 15:09:10.90 creation.
    assert_eq!(pw.crtime, Some(1618758550900000000));
    assert_eq!(pw.mtime, Some(1618758550000000000));
    assert_eq!(pw.atime, Some(1618704000000000000));
    assert_eq!(fs.read_file("/a_directory/a_file").unwrap(), A_FILE);
    assert_eq!(fs.read_file("/PASSWO~1.TXT").unwrap().len(), 116);
}

#[test]
fn fat12_deleted_entry_with_lfn() {
    let mut d = bytes("dfvfs/fat12.raw");
    d[6784] = 0xE5; // short entry of passwords.txt
    d[6752] = 0xE5; // its LFN entry
    let fs = FatFs::open(MemSource::source(d)).unwrap();
    assert!(fs.lookup("/passwords.txt").is_err());
    let w = fs.walk(true).unwrap();
    let del = w.iter().find(|e| e.deleted).expect("deleted entry");
    assert_eq!(del.name, "passwords.txt"); // recovered from the deleted LFN chain
    assert_eq!(del.size, 116);
    assert_eq!(del.dir_entry_offset, 6784);
    assert_eq!(fs.read(del).unwrap().len(), 116);
}

fn exfat_ts(y: u16, mo: u16, d: u16, h: u16, mi: u16, s: u16) -> u32 {
    let date = ((y - 1980) << 9) | (mo << 5) | d;
    let time = (h << 11) | (mi << 5) | (s / 2);
    ((date as u32) << 16) | time as u32
}

/// Build a small exFAT volume: 512-byte sectors and clusters, root with a label, a NoFatChain file,
/// a directory holding a FAT-chained file, and a deleted entry set.
fn build_exfat() -> Vec<u8> {
    let mut img = vec![0u8; 2048 * 512];
    let b = &mut img[..512];
    b[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
    b[3..11].copy_from_slice(b"EXFAT   ");
    b[0x48..0x50].copy_from_slice(&2048u64.to_le_bytes());
    b[0x50..0x54].copy_from_slice(&24u32.to_le_bytes());
    b[0x54..0x58].copy_from_slice(&8u32.to_le_bytes());
    b[0x58..0x5C].copy_from_slice(&32u32.to_le_bytes());
    b[0x5C..0x60].copy_from_slice(&2000u32.to_le_bytes());
    b[0x60..0x64].copy_from_slice(&2u32.to_le_bytes());
    b[0x64..0x68].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    b[0x6C] = 9;
    b[0x6D] = 0;
    b[0x6E] = 1;
    b[510] = 0x55;
    b[511] = 0xAA;
    let fat = 24 * 512;
    let set = |img: &mut Vec<u8>, c: usize, v: u32| {
        img[fat + c * 4..fat + c * 4 + 4].copy_from_slice(&v.to_le_bytes())
    };
    set(&mut img, 0, 0xFFFF_FFF8);
    set(&mut img, 1, 0xFFFF_FFFF);
    set(&mut img, 2, 0xFFFF_FFFF);
    set(&mut img, 3, 0xFFFF_FFFF);
    set(&mut img, 4, 5);
    set(&mut img, 5, 0xFFFF_FFFF);
    let cl = |c: usize| 32 * 512 + (c - 2) * 512;
    let entry_set =
        |name: &str, attrs: u16, first: u32, size: u64, nofat: bool, deleted: bool| -> Vec<u8> {
            let units: Vec<u16> = name.encode_utf16().collect();
            let nnames = units.len().div_ceil(15);
            let mut v = vec![0u8; 32 * (2 + nnames)];
            v[0] = if deleted { 0x05 } else { 0x85 };
            v[1] = (1 + nnames) as u8;
            v[4..6].copy_from_slice(&attrs.to_le_bytes());
            let ts = exfat_ts(2021, 4, 18, 15, 9, 10);
            v[8..12].copy_from_slice(&ts.to_le_bytes());
            v[12..16].copy_from_slice(&ts.to_le_bytes());
            v[16..20].copy_from_slice(&ts.to_le_bytes());
            v[20] = 50; // +0.50 s
            v[22] = 0x80 | 0x08; // UTC+2h
            v[23] = 0x80 | 0x08;
            v[24] = 0x80 | 0x08;
            let s = &mut v[32..64];
            s[0] = if deleted { 0x40 } else { 0xC0 };
            s[1] = if nofat { 0x03 } else { 0x01 };
            s[3] = units.len() as u8;
            s[8..16].copy_from_slice(&size.to_le_bytes());
            s[20..24].copy_from_slice(&first.to_le_bytes());
            s[24..32].copy_from_slice(&size.to_le_bytes());
            for k in 0..nnames {
                let f = &mut v[64 + k * 32..96 + k * 32];
                f[0] = if deleted { 0x41 } else { 0xC1 };
                for (j, u) in units.iter().skip(k * 15).take(15).enumerate() {
                    f[2 + j * 2..4 + j * 2].copy_from_slice(&u.to_le_bytes());
                }
            }
            v
        };
    let mut root = vec![0x83u8, 4];
    root.extend("TEST".encode_utf16().flat_map(|u| u.to_le_bytes()));
    root.resize(32, 0);
    root.extend(entry_set("hello.txt", 0x20, 6, 12, true, false));
    root.extend(entry_set("docs", 0x10, 3, 512, false, false));
    root.extend(entry_set("gone.txt", 0x20, 7, 5, true, true));
    img[cl(2)..cl(2) + root.len()].copy_from_slice(&root);
    let docs = entry_set("a rather long file name.txt", 0x20, 4, 700, false, false);
    img[cl(3)..cl(3) + docs.len()].copy_from_slice(&docs);
    img[cl(6)..cl(6) + 12].copy_from_slice(b"hello exfat\n");
    img[cl(7)..cl(7) + 5].copy_from_slice(b"bye!\n");
    for i in 0..700 {
        // cluster 4 then 5 (chain)
        let c = if i < 512 { cl(4) + i } else { cl(5) + i - 512 };
        img[c] = b'A' + (i % 26) as u8;
    }
    img
}

#[test]
fn exfat_synthetic_volume() {
    let fs = FatFs::open(MemSource::source(build_exfat())).unwrap();
    assert_eq!(fs.kind, FatType::ExFat);
    assert_eq!(fs.label, "TEST");
    let w = fs.walk(true).unwrap();
    let paths: Vec<(&str, bool, bool)> = w
        .iter()
        .map(|e| (e.path.as_str(), e.is_dir, e.deleted))
        .collect();
    assert_eq!(
        paths,
        vec![
            ("/docs", true, false),
            ("/docs/a rather long file name.txt", false, false),
            ("/gone.txt", false, true),
            ("/hello.txt", false, false)
        ]
    );
    assert_eq!(fs.read_file("/hello.txt").unwrap(), b"hello exfat\n");
    let big = fs.read_file("/docs/a rather long file name.txt").unwrap();
    assert_eq!(big.len(), 700);
    assert_eq!(&big[510..515], b"QRSTU");
    let h = w.iter().find(|e| e.name == "hello.txt").unwrap();
    // 2021-04-18 15:09:10.50 at UTC+2 -> 13:09:10.50 UTC.
    let local = fat_datetime_to_ns(
        ((2021 - 1980) << 9) | (4 << 5) | 18,
        (15 << 11) | (9 << 5) | 5,
        50,
    )
    .unwrap();
    assert_eq!(h.crtime, Some(local - 2 * 3600 * 1_000_000_000));
    let gone = w.iter().find(|e| e.deleted).unwrap();
    assert_eq!(fs.read(gone).unwrap(), b"bye!\n");
    let rec = veritas_fs::recover::recover_fat(&fs).unwrap();
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0].data, b"bye!\n");
    assert_eq!(rec[0].recovered_confidence, 90);
}

#[test]
fn fat_malformed_boot_is_error() {
    let mut d = bytes("dfvfs/fat12.raw");
    d[11] = 3; // bytes per sector
    assert!(FatFs::open(MemSource::source(d)).is_err());
    assert!(FatFs::open(MemSource::source(vec![0u8; 100])).is_err());
}

/// Regression (fuzz `image` crash): an exFAT boot sector claiming u32::MAX clusters made the
/// cluster bounds check overflow. Opening and walking it must return results or errors, not panic.
#[test]
fn exfat_with_u32_max_clusters_does_not_overflow() {
    let mut b = vec![0u8; 64 * 1024];
    b[3..11].copy_from_slice(b"EXFAT   ");
    b[0x50..0x54].copy_from_slice(&24u32.to_le_bytes()); // FAT at sector 24
    b[0x54..0x58].copy_from_slice(&8u32.to_le_bytes()); // FAT length 8 sectors
    b[0x58..0x5C].copy_from_slice(&32u32.to_le_bytes()); // data area at sector 32
    b[0x5C..0x60].copy_from_slice(&u32::MAX.to_le_bytes()); // cluster count
    b[0x60..0x64].copy_from_slice(&u32::MAX.to_le_bytes()); // root directory cluster
    b[0x6C] = 9; // 512-byte sectors
    b[0x6D] = 0; // 1 sector per cluster
    b[510] = 0x55;
    b[511] = 0xAA;
    if let Ok(fs) = FatFs::open(MemSource::source(b)) {
        assert_eq!(fs.kind, FatType::ExFat);
        assert!(fs.cluster_offset(u32::MAX).is_some());
        let _ = fs.next_cluster(u32::MAX);
        let _ = fs.chain(u32::MAX, 16);
    }
}
