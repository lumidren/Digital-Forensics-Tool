mod common;
use common::*;
use std::collections::BTreeMap;
use veritas_fs::events::{self, Ctx};
use veritas_fs::harvest;
use veritas_fs::image;
use veritas_timeline::{desc, write_jsonl, Event};

fn events_jsonl(rel: &str) -> (Vec<u8>, Vec<Event>) {
    let ctx = Ctx {
        evidence_sha256: veritas_hash::sha256_hex(&bytes(rel)),
        volume_prefix: String::new(),
    };
    let mut evs = Vec::new();
    for v in image::volumes(src(rel)).unwrap() {
        evs.extend(events::volume_events(&ctx, &v).unwrap());
    }
    let mut out = Vec::new();
    write_jsonl(&mut evs, &mut out).unwrap();
    (out, evs)
}

fn by_type(evs: &[Event]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for e in evs {
        *m.entry(e.data_type.clone()).or_insert(0) += 1;
    }
    m
}

#[test]
fn events_are_deterministic_on_ntfs_raw() {
    let (a, evs) = events_jsonl("dfvfs/ntfs.raw");
    let (b, _) = events_jsonl("dfvfs/ntfs.raw");
    assert_eq!(a, b, "byte-identical JSONL");
    assert_eq!(
        by_type(&evs),
        BTreeMap::from([("fs:stat:ntfs".to_string(), 204)])
    );
    let e = evs
        .iter()
        .find(|e| {
            e.attrs.get("path").and_then(|p| p.as_str()) == Some("/a_directory/a_file")
                && e.attrs["attribute_type"] == 0x10
                && e.timestamp_desc == desc::MODIFICATION
        })
        .unwrap();
    assert_eq!(
        e.timestamp,
        veritas_timeline::filetime_to_ns(132117205799581788)
    );
    assert_eq!(e.attrs["file_reference"], "65-1");
    assert_eq!(e.attrs["parent_file_reference"], "64-1");
    assert_eq!(e.attrs["is_allocated"], true);
    assert_eq!(e.attrs["file_size"], 53);
    assert_eq!(e.attrs["display_name"], "NTFS:/a_directory/a_file");
    assert_eq!(e.offset, 65);
}

#[test]
fn events_other_file_systems() {
    let (_, vss) = events_jsonl("dfvfs/vss.raw");
    let t = by_type(&vss);
    assert_eq!(t.get("fs:vss:snapshot"), Some(&2));
    assert_eq!(t.get("fs:ntfs:logfile"), Some(&782));
    let snap = vss
        .iter()
        .find(|e| e.data_type == "fs:vss:snapshot" && e.attrs["store_index"] == 0)
        .unwrap();
    assert_eq!(
        snap.timestamp,
        veritas_timeline::filetime_to_ns(132643644032230304)
    );
    let (_, fat) = events_jsonl("dfvfs/fat12.raw");
    assert_eq!(by_type(&fat), BTreeMap::from([("fs:stat".to_string(), 12)]));
    let (_, ext) = events_jsonl("dfvfs/ext4.raw");
    assert_eq!(by_type(&ext), BTreeMap::from([("fs:stat".to_string(), 24)]));
    assert!(ext.iter().all(|e| e.attrs["file_system_type"] == "EXT4"));
    let (_, apfs) = events_jsonl("dfvfs/apfs.raw");
    assert_eq!(
        by_type(&apfs),
        BTreeMap::from([("fs:stat".to_string(), 50)])
    );
}

#[test]
fn usn_events() {
    let recs = veritas_fs::ntfs::usn::parse_usn_records(&bytes("plaso/UsnJrnl.raw"), 0);
    let ev = events::usn_events(&Ctx::default(), &recs, "UsnJrnl.raw");
    assert_eq!(ev.len(), 19);
    assert!(ev.iter().all(|e| e.data_type == "fs:ntfs:usn_change"));
    assert_eq!(ev[0].attrs["update_reason"], "FILE_CREATE");
    assert_eq!(ev[0].timestamp, Some(1448918127203125000));
}

fn read_manifest(dir: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(dir.join("manifest.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn harvest_ntfs_raw() {
    let d1 = tempfile::tempdir().unwrap();
    let rep = harvest::harvest(
        src("dfvfs/ntfs.raw"),
        d1.path(),
        None,
        harvest::DEFAULT_MAX_FILE_SIZE,
    )
    .unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    let m = read_manifest(d1.path());
    let paths: Vec<&str> = m.iter().map(|e| e["path"].as_str().unwrap()).collect();
    assert_eq!(paths, vec!["/$LogFile", "/$MFT"]);
    let mft = veritas_fs::ntfs::Ntfs::open(src("dfvfs/ntfs.raw"))
        .unwrap()
        .read_entry_data(0, "")
        .unwrap();
    assert_eq!(m[1]["sha256"], veritas_hash::sha256_hex(&mft));
    assert_eq!(
        (
            m[1]["mft_entry"].as_u64(),
            m[1]["kind"].as_str(),
            m[1]["fs_type"].as_str(),
            m[1]["partition"].as_u64()
        ),
        (Some(0), Some("ntfs_meta"), Some("NTFS"), Some(0))
    );
    assert_eq!(
        std::fs::read(d1.path().join("0").join("$MFT")).unwrap(),
        mft
    );
    // Determinism: a second harvest writes a byte-identical manifest.
    let d2 = tempfile::tempdir().unwrap();
    harvest::harvest(
        src("dfvfs/ntfs.raw"),
        d2.path(),
        None,
        harvest::DEFAULT_MAX_FILE_SIZE,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(d1.path().join("manifest.jsonl")).unwrap(),
        std::fs::read(d2.path().join("manifest.jsonl")).unwrap()
    );
    // Size cap: everything skipped and logged, nothing fails.
    let d3 = tempfile::tempdir().unwrap();
    let rep = harvest::harvest(src("dfvfs/ntfs.raw"), d3.path(), None, 1024).unwrap();
    assert!(rep.manifest.is_empty());
    assert_eq!(rep.errors.len(), 2);
}

#[test]
fn harvest_ext4_and_apfs() {
    let d = tempfile::tempdir().unwrap();
    let rep = harvest::harvest(
        src("dfvfs/ext4.raw"),
        d.path(),
        None,
        harvest::DEFAULT_MAX_FILE_SIZE,
    )
    .unwrap();
    assert!(rep.manifest.is_empty() && rep.errors.is_empty());
    assert!(d.path().join("manifest.jsonl").exists());
    let d = tempfile::tempdir().unwrap();
    let rep = harvest::harvest(
        src("dfvfs/apfs.raw"),
        d.path(),
        None,
        harvest::DEFAULT_MAX_FILE_SIZE,
    )
    .unwrap();
    let got: Vec<(&str, &str, Option<u64>, u64)> = rep
        .manifest
        .iter()
        .map(|e| (e.path.as_str(), e.kind.as_str(), e.inode, e.size))
        .collect();
    assert_eq!(
        got,
        vec![
            ("/.fseventsd/000000001714941a", "macos", Some(25), 164),
            ("/.fseventsd/000000001714941b", "macos", Some(26), 72),
            ("/.fseventsd/fseventsd-uuid", "macos", Some(22), 36)
        ]
    );
    assert!(d
        .path()
        .join("0")
        .join(".fseventsd")
        .join("fseventsd-uuid")
        .exists());
}

#[test]
fn harvest_partitioned_image_selects_partition() {
    let d = tempfile::tempdir().unwrap();
    let rep = harvest::harvest(
        src("dfvfs/mbr.raw"),
        d.path(),
        Some(1),
        harvest::DEFAULT_MAX_FILE_SIZE,
    )
    .unwrap();
    assert!(rep.errors.is_empty());
    assert!(rep.manifest.iter().all(|e| e.partition == 1));
}
