mod common;
use common::*;
use veritas_fs::apfs::{fletcher64, Apfs};
use veritas_fs::error::FsError;
use veritas_fs::io::SubSource;

// Expected values from pyfsapfs 20261030 on dfvfs apfs.raw (identifiers, parent identifiers, sizes,
// modes, nanosecond times, added time, symlink target, extended attribute names).

#[test]
fn apfs_container_and_volume() {
    let fs = Apfs::open(src("dfvfs/apfs.raw")).unwrap();
    assert_eq!(fs.container.uuid, "d08a9fa0-d5a5-458b-813e-ebf9bf5d5338");
    assert_eq!(fs.volumes.len(), 1);
    let v = &fs.volumes[0];
    assert_eq!(v.name, "apfs_test");
    assert_eq!(v.uuid, "458ed10d-8ac3-4af1-8dfd-3954d151a3f3");
    assert!(!v.encrypted);
    assert_eq!(v.num_snapshots, 0);
    assert!(fs.snapshots(0).unwrap().is_empty());
}

#[test]
fn apfs_entries() {
    let fs = Apfs::open(src("dfvfs/apfs.raw")).unwrap();
    let w = fs.walk(0).unwrap();
    let got: Vec<(&str, u64, u64, u64)> = w.iter().map(|e| (e.path.as_str(), e.id, e.parent_id, e.size)).collect();
    assert_eq!(
        got,
        vec![
            ("/.fseventsd", 21, 2, 0),
            ("/.fseventsd/000000001714941a", 25, 21, 164),
            ("/.fseventsd/000000001714941b", 26, 21, 72),
            ("/.fseventsd/fseventsd-uuid", 22, 21, 36),
            ("/a_directory", 16, 2, 0),
            ("/a_directory/a_file", 17, 16, 53),
            ("/a_directory/a_resourcefork", 23, 16, 0),
            ("/a_directory/another_file", 19, 16, 22),
            ("/a_link", 20, 2, 0),
            ("/passwords.txt", 18, 2, 116),
        ]
    );
    let a = &w[5];
    assert_eq!((a.crtime, a.mtime, a.ctime, a.atime, a.added), (Some(1642144781197370938), Some(1642144781201997443), Some(1642144781211025598), Some(1642144781197370938), Some(1642144781197370938)));
    assert_eq!(a.mode, 0o100644);
    assert_eq!((a.uid, a.gid, a.nlink), (99, 99, 1));
    assert_eq!(a.xattrs, vec!["myxattr".to_string()]);
    assert_eq!(w[6].xattrs, vec!["com.apple.ResourceFork".to_string()]);
    assert_eq!(w[8].symlink_target.as_deref(), Some("a_directory/another_file"));
    assert_eq!(w[8].kind, "symlink");
    assert_eq!(fs.read_file(0, "/a_directory/a_file").unwrap(), A_FILE);
    assert_eq!(fs.read_file(0, "/passwords.txt").unwrap().len(), 116);
    assert_eq!(fs.lookup(0, "/a_directory/another_file").unwrap(), 19);
}

#[test]
fn apfs_encrypted_volume_is_reported() {
    let s = src("dfvfs/apfs_encrypted.dmg");
    let sub = SubSource::source(s.clone(), 40 * 512, 8112 * 512).unwrap();
    let fs = Apfs::open(sub).unwrap();
    assert_eq!(fs.volumes[0].name, "SingleVolume");
    assert!(fs.volumes[0].encrypted);
    assert!(matches!(fs.walk(0), Err(FsError::Unsupported(_))));
}

#[test]
fn apfs_checksum_detects_corruption() {
    let d = bytes("dfvfs/apfs.raw");
    let b0 = &d[..4096];
    assert_eq!(u64::from_le_bytes(b0[..8].try_into().unwrap()), fletcher64(b0));
    let mut c = b0.to_vec();
    c[100] ^= 1;
    assert_ne!(u64::from_le_bytes(c[..8].try_into().unwrap()), fletcher64(&c));
}
