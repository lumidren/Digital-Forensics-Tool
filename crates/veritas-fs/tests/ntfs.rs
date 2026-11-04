mod common;
use common::*;
use veritas_fs::ntfs::record::{FileName, StdInfo};
use veritas_fs::ntfs::usn::{parse_usn_records, UsnRecord};
use veritas_fs::ntfs::{self, timestomp, FileEntry, Ntfs};

// Expected values below come from pyfsntfs 20260827 / pytsk3 4.15.0 on dfvfs ntfs.raw,
// dissect.ntfs 3.16 on plaso UsnJrnl.raw, and pyfsntfs `mft_metadata_file` on plaso MFT.

#[test]
fn ntfs_raw_entries() {
    let fs = Ntfs::open(src("dfvfs/ntfs.raw")).unwrap();
    assert_eq!(fs.boot.cluster_size, 4096);
    assert_eq!(fs.boot.mft_record_size, 1024);
    let all = fs.entries().unwrap();
    assert_eq!(all.len(), 69); // pyfsntfs number_of_file_entries
    let by = |n: u64| all.iter().find(|e| e.entry == n).unwrap();
    let a_file = by(65);
    assert_eq!(a_file.path.as_deref(), Some("/a_directory/a_file"));
    assert_eq!(a_file.size(), 53);
    assert!(a_file.in_use);
    let si = a_file.si.as_ref().unwrap();
    assert_eq!(
        (si.crtime, si.mtime, si.atime, si.ctime),
        (
            132117205799567496,
            132117205799581788,
            132117205799567496,
            132117205799581788
        )
    );
    let f = &a_file.file_names[0];
    assert_eq!(
        (f.parent_entry, f.namespace, f.crtime),
        (64, 0, 132117205799567496)
    );
    assert_eq!(by(66).path.as_deref(), Some("/passwords.txt"));
    assert_eq!(by(66).size(), 116);
    assert_eq!(by(68).size(), 56);
    assert_eq!(by(5).path.as_deref(), Some("/"));
    assert_eq!(by(25).path.as_deref(), Some("/$Extend/$ObjId"));
    assert_eq!(by(8).ads_names(), vec!["$Bad".to_string()]);
    assert_eq!(by(10).ads_names(), vec!["$Info".to_string()]);
    assert_eq!(by(9).ads_names(), vec!["$SDS".to_string()]);
    assert_eq!(by(0).size(), 70656);
    // Unallocated (deleted/free) records keep their $SI (pyfsntfs is_allocated == False).
    assert!(!by(16).in_use && by(16).si.is_some());
    assert_eq!(all.iter().filter(|e| !e.in_use).count(), 8 + 37);
}

#[test]
fn ntfs_read_by_path_and_entry() {
    let fs = Ntfs::open(src("dfvfs/ntfs.raw")).unwrap();
    assert_eq!(fs.read_file("/a_directory/a_file").unwrap(), A_FILE);
    assert_eq!(fs.read_file("/A_DIRECTORY/A_FILE").unwrap(), A_FILE); // case-insensitive lookup
    assert_eq!(fs.lookup("/a_directory/another_file").unwrap(), 67);
    assert_eq!(fs.read_entry_data(67, "").unwrap().len(), 22);
    assert_eq!(fs.read_entry_data(10, "$Info").unwrap().len(), 32);
    assert!(fs.read_file("/does/not/exist").is_err());
    // $UpCase is non-resident: first entries map 'a' -> 'A'.
    let up = fs.read_entry_data(10, "").unwrap();
    assert_eq!(up.len(), 131072);
    assert_eq!(u16::from_le_bytes([up[0x61 * 2], up[0x61 * 2 + 1]]), 0x41);
}

#[test]
fn ntfs_directory_index() {
    let fs = Ntfs::open(src("dfvfs/ntfs.raw")).unwrap();
    let root = fs.list_dir(5).unwrap();
    let names: Vec<&str> = root
        .iter()
        .filter(|e| !e.slack)
        .map(|e| e.file_name.name.as_str())
        .collect();
    for n in ["$MFT", "$Extend", "a_directory", "a_link", "passwords.txt"] {
        assert!(names.contains(&n), "{n}");
    }
    let sub = fs.list_dir(64).unwrap();
    let mut s: Vec<&str> = sub
        .iter()
        .filter(|e| !e.slack)
        .map(|e| e.file_name.name.as_str())
        .collect();
    s.sort();
    assert_eq!(s, vec!["a_file", "another_file"]);
}

#[test]
fn ntfs_index_slack_entry_is_recovered() {
    // Overwrite the live-entry count of /a_directory's $INDEX_ROOT so its second entry falls into
    // slack: the carver must still return it, flagged `slack`.
    let mut d = bytes("dfvfs/ntfs.raw");
    let rec = 4 * 4096 + 64 * 1024;
    let r = &d[rec..rec + 1024];
    let mut pos = u16::from_le_bytes([r[0x14], r[0x15]]) as usize;
    let mut ir = None;
    while pos + 8 < 1024 {
        let t = u32::from_le_bytes(r[pos..pos + 4].try_into().unwrap());
        let l = u32::from_le_bytes(r[pos + 4..pos + 8].try_into().unwrap()) as usize;
        if t == 0x90 {
            ir = Some(pos + u16::from_le_bytes([r[pos + 0x14], r[pos + 0x15]]) as usize);
            break;
        }
        pos += l;
    }
    let v = rec + ir.expect("$INDEX_ROOT");
    let first = u32::from_le_bytes(d[v + 0x10..v + 0x14].try_into().unwrap()) as usize;
    let e0 = v + 0x10 + first;
    let e0_len = u16::from_le_bytes([d[e0 + 8], d[e0 + 9]]) as usize;
    // Make the first entry the terminating one (flag LAST); keep its length so the next entry is slack.
    d[e0 + 12] |= 0x02;
    let used = (first + e0_len) as u32;
    d[v + 0x14..v + 0x18].copy_from_slice(&used.to_le_bytes());
    let fs = Ntfs::open(veritas_fs::io::MemSource::source(d)).unwrap();
    let list = fs.list_dir(64).unwrap();
    assert!(
        list.iter().any(
            |e| e.slack && (e.file_name.name == "another_file" || e.file_name.name == "a_file")
        ),
        "{list:?}"
    );
}

#[test]
fn ntfs_vss_raw_and_logfile() {
    let fs = Ntfs::open(src("dfvfs/vss.raw")).unwrap();
    assert_eq!(fs.boot.cluster_size, 512);
    assert_eq!(fs.lookup("/passwords.txt").unwrap(), 40); // pytsk3 inode
    assert_eq!(fs.read_file("/passwords.txt").unwrap().len(), 126);
    let lf = fs.logfile().unwrap();
    assert_eq!(lf.restart_areas.len(), 2);
    let ra = &lf.restart_areas[0];
    assert_eq!(
        (
            ra.current_lsn,
            ra.seq_number_bits,
            ra.log_page_size,
            ra.file_size
        ),
        (1590293, 45, 4096, 2097152)
    );
    assert_eq!(ra.clients[0].name, "NTFS");
    // Record-level parsing validated by the LSN -> file-offset mapping of each header.
    assert_eq!(lf.records.len(), 782);
    let r0 = &lf.records[0];
    assert_eq!(
        (r0.lsn, r0.redo_op_name.as_str(), r0.undo_op_name.as_str()),
        (1066028, "OpenNonresidentAttribute", "Noop")
    );
    assert!(lf
        .records
        .iter()
        .any(|r| r.redo_op_name == "InitializeFileRecordSegment" && r.mft_entry.is_some()));
    assert!(lf.records.windows(2).all(|w| w[0].lsn < w[1].lsn));
}

#[test]
fn usn_raw_extract_matches_dissect() {
    let d = bytes("plaso/UsnJrnl.raw");
    let recs = parse_usn_records(&d, 0);
    assert_eq!(recs.len(), 19);
    let r0 = &recs[0];
    assert_eq!(
        (
            r0.usn,
            r0.timestamp_raw,
            r0.reason,
            r0.file_entry,
            r0.file_sequence,
            r0.parent_entry
        ),
        (0, 130933917272031250, 0x100, 30, 1, 5)
    );
    assert_eq!(r0.name, "Nieuw - Tekstdocument.txt");
    assert_eq!(r0.timestamp, Some(1448918127203125000));
    assert_eq!(recs[3].name, "first.txt");
    assert_eq!(recs[3].reasons, vec!["RENAME_NEW_NAME".to_string()]);
    let last = recs.last().unwrap();
    assert_eq!(
        (last.offset, last.usn, last.reason, last.name.as_str()),
        (1664, 1664, 0x8008_0000, ".")
    );
}

#[test]
fn usn_v3_and_v4_records() {
    // Hand-built v3 record (128-bit references) followed by a v4 record, after zero padding.
    let mut v3 = vec![0u8; 0x50];
    v3[0..4].copy_from_slice(&0x50u32.to_le_bytes());
    v3[4..6].copy_from_slice(&3u16.to_le_bytes());
    v3[8..16].copy_from_slice(&((7u64 << 48) | 1234).to_le_bytes());
    v3[24..32].copy_from_slice(&((5u64 << 48) | 5).to_le_bytes());
    v3[40..48].copy_from_slice(&4096u64.to_le_bytes());
    v3[48..56].copy_from_slice(&130933917272031250u64.to_le_bytes());
    v3[56..60].copy_from_slice(&0x8000_0002u32.to_le_bytes());
    v3[72..74].copy_from_slice(&4u16.to_le_bytes());
    v3[74..76].copy_from_slice(&0x4Cu16.to_le_bytes());
    v3[0x4C..0x50].copy_from_slice(&[b'a', 0, b'b', 0]);
    let mut v4 = vec![0u8; 0x48];
    v4[0..4].copy_from_slice(&0x48u32.to_le_bytes());
    v4[4..6].copy_from_slice(&4u16.to_le_bytes());
    v4[8..16].copy_from_slice(&((7u64 << 48) | 1234).to_le_bytes());
    v4[40..48].copy_from_slice(&8192u64.to_le_bytes());
    v4[48..52].copy_from_slice(&0x1u32.to_le_bytes());
    let mut buf = vec![0u8; 64];
    buf.extend_from_slice(&v3);
    buf.extend_from_slice(&v4);
    let r = parse_usn_records(&buf, 1000);
    assert_eq!(r.len(), 2);
    assert_eq!(
        (
            r[0].major_version,
            r[0].file_entry,
            r[0].file_sequence,
            r[0].usn,
            r[0].name.as_str(),
            r[0].offset
        ),
        (3, 1234, 7, 4096, "ab", 1064)
    );
    assert_eq!(
        r[0].reasons,
        vec!["DATA_EXTEND".to_string(), "CLOSE".to_string()]
    );
    assert_eq!(
        (r[1].major_version, r[1].usn, r[1].reason, r[1].timestamp),
        (4, 8192, 1, None)
    );
}

#[test]
fn plaso_mft_extract() {
    let v = ntfs::parse_mft_file(&bytes("plaso/MFT")).unwrap();
    let by = |n: u64| v.iter().find(|e| e.entry == n).unwrap();
    assert_eq!(v.len(), 13068); // 13088 slots, 20 without a FILE header (pyfsntfs fails on those too)
    assert_eq!(by(27).path.as_deref(), Some("/pagefile.sys"));
    assert_eq!(by(27).size(), 100663296);
    assert_eq!(by(5).si.as_ref().unwrap().mtime, 128768122647268320);
    let sys_log = by(3498);
    assert_eq!(
        sys_log.path.as_deref(),
        Some("/WINDOWS/system32/config/system.LOG")
    );
    assert_eq!(sys_log.attribute_list.len(), 3);
    // Deleted record with an ADS (Zone.Identifier) survives via its attribute list.
    let z = by(12938);
    assert!(!z.in_use);
    assert_eq!(z.ads_names(), vec!["Zone.Identifier".to_string()]);
}

fn entry_with(si: StdInfo, fname: FileName) -> FileEntry {
    FileEntry {
        entry: 100,
        sequence: 1,
        in_use: true,
        si: Some(si),
        file_names: vec![fname],
        path: Some("/evil.exe".into()),
        ..Default::default()
    }
}

#[test]
fn timestomp_rules() {
    let fname = FileName {
        crtime: 132117205799567496,
        mtime: 132117205799567496,
        ctime: 132117205799567496,
        atime: 132117205799567496,
        namespace: 1,
        name: "evil.exe".into(),
        ..Default::default()
    };
    // Clean: SI == FN.
    let clean = entry_with(
        StdInfo {
            crtime: fname.crtime,
            mtime: fname.mtime,
            ctime: fname.ctime,
            atime: fname.atime,
            ..Default::default()
        },
        fname.clone(),
    );
    assert!(timestomp::detect(&[clean.clone()], &[]).is_empty());
    // Backdated SI with whole-second precision.
    let stomped = entry_with(
        StdInfo {
            crtime: 128000000000000000,
            mtime: 128000000000000000,
            ctime: fname.ctime,
            atime: fname.atime,
            ..Default::default()
        },
        fname.clone(),
    );
    let f = timestomp::detect(&[stomped], &[]);
    let rules: Vec<(&str, &str)> = f
        .iter()
        .map(|x| (x.rule.as_str(), x.field.as_str()))
        .collect();
    assert!(rules.contains(&("si_before_fn", "crtime")));
    assert!(rules.contains(&("si_before_fn", "mtime")));
    assert!(rules.contains(&("si_zero_subsecond", "crtime")));
    // USN shows a data change after the SI modification time.
    let usn = UsnRecord {
        offset: 0,
        major_version: 2,
        minor_version: 0,
        file_entry: 100,
        file_sequence: 1,
        parent_entry: 5,
        parent_sequence: 5,
        file_reference_128: None,
        usn: 1,
        timestamp_raw: fname.mtime + 600 * 10_000_000,
        timestamp: None,
        reason: 0x2,
        reasons: vec![],
        source_info: 0,
        security_id: 0,
        file_attributes: 0,
        name: "evil.exe".into(),
    };
    let f = timestomp::detect(&[clean], &[usn]);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].rule, "usn_after_si_mtime");
}

#[test]
fn timestomp_on_corpus_is_clean() {
    let fs = Ntfs::open(src("dfvfs/ntfs.raw")).unwrap();
    assert!(timestomp::detect(&fs.entries().unwrap(), &[]).is_empty());
}

#[test]
fn malformed_records_error_not_panic() {
    use veritas_fs::ntfs::record::MftRecord;
    assert!(MftRecord::parse(b"FILE", 0).is_err());
    assert!(MftRecord::parse(&[0u8; 1024], 0).is_err());
    let mut r = bytes("dfvfs/ntfs.raw")[4 * 4096 + 65 * 1024..4 * 4096 + 66 * 1024].to_vec();
    r[0x14] = 0xF0; // attribute offset beyond the record
    let rec = MftRecord::parse(&r, 65).unwrap();
    assert!(rec.attributes.is_empty() && rec.truncated);
}
