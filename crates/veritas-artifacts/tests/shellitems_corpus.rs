//! Shell item tests. Expected values from libfwsi-python (pyfwsi 20260522) applied to the LNK
//! link target ID lists (item class types, names, FAT modification times, 0xbeef0004 long name,
//! creation/access times and NTFS file references).
use proptest::prelude::*;
use std::path::PathBuf;
use veritas_artifacts::{lnk, shellitems};
use veritas_timeline::format_ns;

fn corpus(rel: &str) -> Option<Vec<u8>> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/plaso").join(rel);
    match std::fs::read(&p) {
        Ok(d) => Some(d),
        Err(_) if std::env::var("VERITAS_REQUIRE_CORPUS").is_err() => {
            eprintln!("skipping: corpus file {} missing (run testdata/fetch.py)", p.display());
            None
        }
        Err(e) => panic!("corpus file {} missing: {e}", p.display()),
    }
}

fn fmt(t: Option<i64>) -> String {
    t.map(format_ns).unwrap_or_default()
}

#[test]
fn nero_id_list_matches_pyfwsi() {
    let Some(d) = corpus("NeroInfoTool.lnk") else { return };
    let l = lnk::parse(&d).unwrap();
    let raw = hex::decode(&l.target_id_list_raw_hex).unwrap();
    let items = shellitems::parse_shell_item_list(&raw).unwrap();
    // pyfwsi class types: 0x1f, 0x2f, 0x31 x4, 0x32
    let types: Vec<&str> = items.iter().map(|i| i.item_type.as_str()).collect();
    assert_eq!(types, ["root_folder", "volume", "directory", "directory", "directory", "directory", "file"]);
    let sizes: Vec<usize> = items.iter().map(|i| i.raw_size).collect();
    assert_eq!(sizes, [20, 25, 148, 74, 80, 96, 98]);
    assert_eq!(items[0].class_id.as_deref(), Some("20d04fe0-3aea-1069-a2d8-08002b30309d"));
    assert_eq!(items[0].name, "My Computer");
    assert_eq!(items[1].name, "C:\\");
    let p = &items[2];
    assert_eq!(p.name, "PROGRA~2");
    assert_eq!(p.long_name.as_deref(), Some("Program Files (x86)"));
    assert_eq!(fmt(p.modification_ns), "2010-01-29T21:29:20.000000Z");
    assert_eq!(fmt(p.creation_ns), "2009-07-14T03:20:10.000000Z");
    assert_eq!(fmt(p.access_ns), "2010-01-29T21:29:20.000000Z");
    // file_reference 281474976710930 = entry 274, sequence 1
    assert_eq!(p.mft_entry, Some(274));
    assert_eq!(p.mft_sequence, Some(1));
    let eb = &p.extension_blocks[0];
    assert_eq!(eb.signature, 0xbeef0004);
    assert_eq!(eb.fields["localized_name"], "@shell32.dll,-21817");
    assert_eq!(eb.fields["file_reference"], 281474976710930u64);
    let refs: Vec<Option<u64>> = items[2..].iter().map(|i| i.mft_entry).collect();
    // pyfwsi file references 281474976710930, 281474976790987, 281474976790988,
    // 562949953502657 and 281474976792005 (low 48 bits = MFT entry).
    assert_eq!(refs, [Some(274), Some(80331), Some(80332), Some(81345), Some(81349)]);
    assert_eq!(items[5].mft_sequence, Some(2));
    assert_eq!(items[6].name, "InfoTool.exe");
    assert_eq!(fmt(items[6].modification_ns), "2009-06-05T20:13:20.000000Z");
    assert_eq!(shellitems::shell_item_path(&items), r"My Computer\C:\Program Files (x86)\Nero\Nero 9\Nero InfoTool\InfoTool.exe");
}

#[test]
fn unpaired_surrogate_id_list() {
    let Some(d) = corpus("unpaired_surrogate.lnk") else { return };
    let l = lnk::parse(&d).unwrap();
    let items = &l.target_id_list;
    assert_eq!(items.len(), 4);
    assert_eq!(items[3].name, "UNICOD~1.EXE");
    assert_eq!(items[3].long_name.as_deref(), Some("unicode_U+0000d800_\u{fffd}.exe"));
    // pyfwsi file_reference 17732923533157946
    assert_eq!(items[3].mft_entry, Some(17732923533157946u64 & 0xffff_ffff_ffff));
    assert_eq!(items[3].mft_sequence, Some((17732923533157946u64 >> 48) as u16));
}

#[test]
fn hex_input_and_terminator() {
    // root folder (My Computer) followed by the 0x0000 terminator
    let hex = "14001f50e04fd020ea3a6910a2d808002b30309d 0000";
    let b = shellitems::parse_hex_input(hex).unwrap();
    let items = shellitems::parse_shell_item_list(&b).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].name, "My Computer");
    assert!(shellitems::known_folder_name("B4BFCC3A-DB2C-424C-B029-7FE99A87C641").is_some());
    assert!(shellitems::KNOWN_FOLDERS.len() >= 40);
    // too-small item size is an error, not a panic
    assert!(shellitems::parse_shell_item_list(&[2, 0, 0x1f]).is_err());
}

#[test]
fn determinism() {
    let Some(d) = corpus("NeroInfoTool.lnk") else { return };
    let l = lnk::parse(&d).unwrap();
    let raw = hex::decode(&l.target_id_list_raw_hex).unwrap();
    let a = serde_json::to_string(&shellitems::parse_shell_item_list(&raw).unwrap()).unwrap();
    let b = serde_json::to_string(&shellitems::parse_shell_item_list(&raw).unwrap()).unwrap();
    assert_eq!(a, b);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]
    #[test]
    fn random_lists_never_panic(d in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = shellitems::parse_shell_item_list(&d);
    }

    #[test]
    fn typed_items_never_panic(class in any::<u8>(), body in proptest::collection::vec(any::<u8>(), 0..300)) {
        let mut d = vec![0u8, 0, class];
        d.extend_from_slice(&body);
        let n = d.len() as u16;
        d[0..2].copy_from_slice(&n.to_le_bytes());
        let _ = shellitems::parse_shell_item(&d);
        let _ = shellitems::parse_extension_blocks(&d, 3);
    }

    #[test]
    fn mutated_nero_list_never_panics(muts in proptest::collection::vec((0usize..543, any::<u8>()), 1..16)) {
        if let Some(d) = corpus("NeroInfoTool.lnk") {
            let l = lnk::parse(&d).unwrap();
            let mut raw = hex::decode(&l.target_id_list_raw_hex).unwrap();
            let n = raw.len();
            for (o, b) in muts { raw[o % n] = b; }
            let _ = shellitems::parse_shell_item_list(&raw);
        }
    }
}
