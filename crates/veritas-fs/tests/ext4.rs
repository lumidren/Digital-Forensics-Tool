mod common;
use common::*;
use veritas_fs::ext4::Ext4;
use veritas_fs::image::{self, AnyFs};

// Expected values from pyfsext 20260821 (inode numbers, sizes, modes, nanosecond times, crtime,
// symlink target) on dfvfs ext4.raw / ext2.raw and plaso syslog_image.dd.

#[test]
fn ext4_listing_and_times() {
    let fs = Ext4::open(src("dfvfs/ext4.raw")).unwrap();
    assert_eq!(fs.sb.volume_name, "ext4_test");
    assert_eq!(fs.sb.inode_size, 256);
    assert_eq!(fs.sb.desc_size, 64);
    let w = fs.walk(false).unwrap();
    let got: Vec<(&str, u64, u64)> = w
        .iter()
        .map(|e| (e.path.as_str(), e.inode, e.size))
        .collect();
    assert_eq!(
        got,
        vec![
            ("/a_directory", 12, 1024),
            ("/a_directory/a_file", 13, 53),
            ("/a_directory/another_file", 15, 22),
            ("/a_link", 16, 24),
            ("/lost+found", 11, 12288),
            ("/passwords.txt", 14, 116)
        ]
    );
    let a = &w[1];
    assert_eq!(a.mode, 0o100664);
    assert_eq!((a.uid, a.gid, a.links), (1000, 1000, 1));
    assert_eq!(a.crtime, Some(1626962852841610817));
    assert_eq!(a.mtime, Some(1626962852841610817));
    assert_eq!(a.atime, Some(1626962852841610817));
    assert_eq!(a.ctime, Some(1626962852846610831));
    assert_eq!(w[0].crtime, Some(1626962852840610814));
    assert_eq!(w[0].mtime, Some(1626962852843610823));
    assert_eq!(
        w[3].symlink_target.as_deref(),
        Some("a_directory/another_file")
    );
    assert_eq!(w[4].crtime, Some(1626962852000000000));
    assert_eq!(fs.read_file("/a_directory/a_file").unwrap(), A_FILE);
    assert!(fs.read_file("/a_directory").is_err());
    assert!(w.iter().all(|e| e.allocated));
}

#[test]
fn ext4_extents_and_journal() {
    let fs = Ext4::open(src("dfvfs/ext4.raw")).unwrap();
    let i = fs.inode(13).unwrap();
    assert_ne!(i.flags & 0x80000, 0, "extent-mapped");
    let ex = fs.extents(&i).unwrap();
    assert_eq!(ex.len(), 1);
    assert_eq!(ex[0].length, 1);
    let j = fs.journal().unwrap();
    assert_eq!((j.block_size, j.max_len, j.version), (1024, 1024, 2));
    // jbd2 blocks (own parse of the journal inode; cross-checked with debugfs logdump layout).
    let kinds: Vec<&str> = j.blocks.iter().map(|b| b.type_name.as_str()).collect();
    assert_eq!(kinds, vec!["descriptor", "commit"]);
    assert_eq!(j.blocks[0].tags.len(), 10);
    assert_eq!(j.blocks[1].commit_time, Some(1626962852884610934));
}

#[test]
fn ext2_block_map_and_no_crtime() {
    let fs = Ext4::open(src("dfvfs/ext2.raw")).unwrap();
    let w = fs.walk(false).unwrap();
    assert_eq!(w.len(), 6);
    assert!(w.iter().all(|e| e.crtime.is_none()));
    let a = w.iter().find(|e| e.path == "/a_directory/a_file").unwrap();
    assert_eq!(
        (a.inode, a.size, a.mtime),
        (13, 53, Some(1626962852000000000))
    );
    assert_eq!(fs.read_file("/a_directory/a_file").unwrap(), A_FILE);
    assert!(fs.journal().is_err());
    assert_eq!(
        fs.read_file("/a_link").unwrap(),
        b"a_directory/another_file"
    );
}

#[test]
fn ext_deleted_inodes_via_bitmap() {
    let fs = Ext4::open(src("plaso/syslog_image.dd")).unwrap();
    let w = fs.walk(false).unwrap();
    let got: Vec<(&str, u64, u64)> = w
        .iter()
        .map(|e| (e.path.as_str(), e.inode, e.size))
        .collect();
    assert_eq!(
        got,
        vec![
            ("/logs", 13, 1024),
            ("/logs/hidden.zip", 11, 675),
            ("/logs/sys.tgz", 12, 730)
        ]
    );
    assert_eq!(w[1].uid, 151107);
    let del: Vec<u64> = fs.deleted_inodes().unwrap().iter().map(|i| i.ino).collect();
    assert_eq!(del, vec![14, 15, 16]);
    assert!(fs.deleted_inodes().unwrap().iter().all(|i| !i.allocated));
}

#[test]
fn ext_in_mbr_partitions() {
    let vols = image::volumes(src("dfvfs/mbr.raw")).unwrap();
    assert_eq!(vols.len(), 2);
    for v in &vols {
        let fs = AnyFs::open(v).unwrap();
        let names: Vec<String> = fs
            .entries(false)
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert!(
            names
                .iter()
                .any(|n| n.ends_with("lost+found") || n.contains("file")),
            "{names:?}"
        );
    }
}

#[test]
fn ext_malformed_superblock_is_error() {
    let mut d = bytes("dfvfs/ext4.raw");
    d[1024 + 0x28] = 0x7F; // inodes per group: breaks inodes_count invariant
    assert!(Ext4::open(veritas_fs::io::MemSource::source(d)).is_err());
}
