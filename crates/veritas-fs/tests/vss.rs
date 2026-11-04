mod common;
use common::*;
use std::sync::Arc;
use veritas_fs::ntfs::Ntfs;
use veritas_fs::vss::Vss;

// Expected values from pyvshadow 20260714 on dfvfs vss.raw: store identifiers, creation times,
// SHA-256 of the first MiB and of the complete store data.

#[test]
fn vss_stores_metadata() {
    let v = Vss::open(src("dfvfs/vss.raw")).unwrap();
    assert_eq!(v.stores.len(), 2);
    assert_eq!(v.volume_size, 82771968);
    let s0 = &v.stores[0];
    assert_eq!(s0.identifier, "de81cc22-aa8b-11eb-9339-8cdcd4557abc");
    assert_eq!(s0.copy_identifier, "2c6c6cc8-2b97-41da-a030-4add838ae8f6");
    assert_eq!(s0.copy_set_identifier, "6c5c9cd2-ea46-4c70-a4a8-568fdabd27c1");
    assert_eq!(s0.creation_time_raw, 132643644032230304);
    let s1 = &v.stores[1];
    assert_eq!(s1.identifier, "de81cc2b-aa8b-11eb-9339-8cdcd4557abc");
    assert_eq!(s1.creation_time_raw, 132643644882249863);
    assert_eq!(s1.operating_machine, "eternal");
    assert_eq!((s0.descriptor_count, s1.descriptor_count), (31, 38));
}

#[test]
fn vss_store_data_matches_pyvshadow() {
    let v = Vss::open(src("dfvfs/vss.raw")).unwrap();
    let first = |i| veritas_hash::sha256_hex(&v.read_store(i, 0, 1 << 20).unwrap());
    assert_eq!(first(0), "711785ebb1bfe4aa5a1f202e9765cf9d6ff3325af31b924dbd934cc68f0322d0");
    assert_eq!(first(1), "b25ea25ad27c11c061f947f86586245f98f5f7432953e9e24da8d992d4595699");
    let full = |i| veritas_hash::sha256_hex(&v.read_store(i, 0, v.volume_size).unwrap());
    assert_eq!(full(0), "d830fe9e2f75e66edfe0f9b0730c0ec8148233ed9c2ab5601195c293d593d9a9");
    assert_eq!(full(1), "d47ca0497f4aa3098a7d0b5407a6406a4f8d747e6207fdbc197e2224fb4838ae");
}

#[test]
fn ntfs_inside_shadow_copies() {
    let v = Arc::new(Vss::open(src("dfvfs/vss.raw")).unwrap());
    let live = Ntfs::open(src("dfvfs/vss.raw")).unwrap();
    assert!(live.lookup("/vss2").is_ok());
    for i in 0..2 {
        let fs = Ntfs::open(v.store_source(i).unwrap()).unwrap();
        assert_eq!(fs.read_file("/passwords.txt").unwrap().len(), 126);
        // vss2 was written after the second snapshot was taken, so no store has it.
        assert!(fs.lookup("/vss2").is_err(), "store {i}");
    }
    let s1 = Ntfs::open(v.store_source(1).unwrap()).unwrap();
    assert!(s1.lookup("/vss1").is_ok());
    let s0 = Ntfs::open(v.store_source(0).unwrap()).unwrap();
    assert!(s0.lookup("/vss1").is_err());
}

#[test]
fn not_a_vss_volume() {
    assert!(Vss::open(src("dfvfs/ntfs.raw")).is_err());
    assert!(!veritas_fs::vss::probe(src("dfvfs/ntfs.raw").as_ref()));
}
