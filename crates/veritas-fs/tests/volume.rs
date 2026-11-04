mod common;
use common::*;
use veritas_fs::image::{self, FsKind};
use veritas_fs::volume;

/// (start sector, sector count, description) of allocated partitions.
/// Expected values from pytsk3 4.15.0 `Volume_Info` (flags == TSK_VS_PART_FLAG_ALLOC).
fn parts(rel: &str) -> Vec<(u64, u64, String)> {
    let vs = volume::detect(src(rel).as_ref())
        .unwrap()
        .expect("partition table");
    vs.partitions
        .iter()
        .map(|p| (p.start_lba, p.num_sectors, p.description.clone()))
        .collect()
}

#[test]
fn mbr_with_extended_partition() {
    assert_eq!(
        parts("dfvfs/mbr.raw"),
        vec![
            (1, 129, "Linux (0x83)".into()),
            (131, 129, "Linux (0x83)".into())
        ]
    );
    let vs = volume::detect(src("dfvfs/mbr.raw").as_ref())
        .unwrap()
        .unwrap();
    assert!(!vs.partitions[0].logical && vs.partitions[1].logical);
}

#[test]
fn plaso_tsk_volume_system() {
    assert_eq!(
        parts("plaso/tsk_volume_system.raw"),
        vec![
            (1, 350, "Linux (0x83)".into()),
            (352, 2528, "Linux (0x83)".into())
        ]
    );
}

#[test]
fn gpt_with_crc_validation() {
    assert_eq!(
        parts("dfvfs/gpt.raw"),
        vec![
            (2048, 128, "Linux filesystem".into()),
            (4096, 128, "Linux filesystem".into())
        ]
    );
    let vs = volume::detect(src("dfvfs/gpt.raw").as_ref())
        .unwrap()
        .unwrap();
    assert_eq!(vs.scheme, "gpt");
    assert_eq!(vs.gpt_header_crc_ok, Some(true));
    assert_eq!(vs.gpt_entries_crc_ok, Some(true));
    assert_eq!(
        vs.partitions[0].type_id,
        "0fc63daf-8483-4772-8e79-3d69d8477de4"
    );
}

#[test]
fn gpt_crc_mismatch_is_reported() {
    let mut d = bytes("dfvfs/gpt.raw");
    d[1024 + 60] ^= 0x01; // first entry name byte -> entry array CRC mismatch
    let vs = volume::detect(veritas_fs::io::MemSource::source(d).as_ref())
        .unwrap()
        .unwrap();
    assert_eq!(vs.gpt_entries_crc_ok, Some(false));
}

#[test]
fn gpt_in_mbr_and_apple_dmg() {
    assert_eq!(
        parts("dfvfs/gpt_in_mbr.raw"),
        vec![(128, 8192, "Linux (0x83)".into())]
    );
    assert_eq!(
        parts("dfvfs/apfs_encrypted.dmg"),
        vec![(40, 8112, "disk image".into())]
    );
    let vs = volume::detect(src("dfvfs/apfs_encrypted.dmg").as_ref())
        .unwrap()
        .unwrap();
    assert_eq!(vs.partitions[0].type_name, "Apple APFS");
}

#[test]
fn bare_file_systems_have_no_table() {
    for f in [
        "dfvfs/ntfs.raw",
        "dfvfs/fat12.raw",
        "dfvfs/ext4.raw",
        "dfvfs/apfs.raw",
    ] {
        assert!(volume::detect(src(f).as_ref()).unwrap().is_none(), "{f}");
    }
}

#[test]
fn file_system_detection_per_volume() {
    let k = |f: &str| {
        image::volumes(src(f))
            .unwrap()
            .iter()
            .map(|v| v.fs)
            .collect::<Vec<_>>()
    };
    assert_eq!(k("dfvfs/ntfs.raw"), vec![FsKind::Ntfs]);
    assert_eq!(k("dfvfs/fat12.raw"), vec![FsKind::Fat]);
    assert_eq!(k("dfvfs/ext2.raw"), vec![FsKind::Ext]);
    assert_eq!(k("dfvfs/apfs.raw"), vec![FsKind::Apfs]);
    assert_eq!(k("dfvfs/mbr.raw"), vec![FsKind::Ext, FsKind::Ext]);
    assert_eq!(k("dfvfs/apfs_encrypted.dmg"), vec![FsKind::Apfs]);
}
