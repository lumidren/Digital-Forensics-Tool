//! LNK corpus tests. Expected values were produced by liblnk-python (pylnk 20260525):
//! get_file_{creation,modification,access}_time_as_integer, file_size, data_flags, local_path,
//! description, relative_path, working_directory, command_line_arguments, icon_location,
//! environment_variables_location, drive_type, drive_serial_number, volume_label,
//! machine_identifier and the droid identifiers.
use proptest::prelude::*;
use std::path::PathBuf;
use veritas_artifacts::lnk;

fn corpus(rel: &str) -> Option<Vec<u8>> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/corpus/plaso")
        .join(rel);
    match std::fs::read(&p) {
        Ok(d) => Some(d),
        Err(_) if std::env::var("VERITAS_REQUIRE_CORPUS").is_err() => {
            eprintln!(
                "skipping: corpus file {} missing (run testdata/fetch.py)",
                p.display()
            );
            None
        }
        Err(e) => panic!("corpus file {} missing: {e}", p.display()),
    }
}

#[test]
fn nero_info_tool() {
    let Some(d) = corpus("NeroInfoTool.lnk") else {
        return;
    };
    let l = lnk::parse(&d).unwrap();
    assert_eq!(l.creation_filetime, 128887064000000000);
    assert_eq!(l.modification_filetime, 128887064000000000);
    assert_eq!(l.access_filetime, 129092742113321569);
    assert_eq!(l.file_size, 4635160);
    assert_eq!(l.link_flags, 16639);
    assert_eq!(l.file_attribute_flags, 32);
    assert_eq!(
        l.local_path().as_deref(),
        Some(r"C:\Program Files (x86)\Nero\Nero 9\Nero InfoTool\InfoTool.exe")
    );
    assert_eq!(l.network_path(), None);
    assert!(l
        .description
        .as_deref()
        .unwrap()
        .starts_with("Nero InfoTool provides you with information"));
    assert_eq!(
        l.relative_path.as_deref(),
        Some(r"..\..\..\..\..\..\..\..\Program Files (x86)\Nero\Nero 9\Nero InfoTool\InfoTool.exe")
    );
    assert_eq!(
        l.working_directory.as_deref(),
        Some(r"C:\Program Files (x86)\Nero\Nero 9\Nero InfoTool")
    );
    assert_eq!(
        l.command_line_arguments.as_deref(),
        Some("-ScParameter=30002  ")
    );
    assert_eq!(
        l.icon_location.as_deref(),
        Some(r"C:\Program Files (x86)\Nero\Nero 9\Nero InfoTool\InfoTool.exe")
    );
    let li = l.link_info.as_ref().unwrap();
    assert_eq!(li.drive_type, Some(3));
    assert_eq!(li.drive_serial_number, Some(1894578739));
    assert_eq!(li.volume_label.as_deref(), Some("OS"));
    let t = l.tracker.as_ref().unwrap();
    assert_eq!(t.machine_identifier, "win-3qmdjgkf3g9");
    assert_eq!(
        t.droid_volume_identifier,
        "c989f572-4deb-4c64-b0d1-dc4959bbff28"
    );
    assert_eq!(
        t.droid_file_identifier,
        "958705b5-0d19-11df-9fe4-705ab616a5f3"
    );
    assert_eq!(
        t.birth_droid_file_identifier,
        "958705b5-0d19-11df-9fe4-705ab616a5f3"
    );
    assert_eq!(t.droid_mac_address.as_deref(), Some("70:5a:b6:16:a5:f3"));
    // 2010-01-29T21:02:17.8401717Z from the version 1 UUID timestamp
    assert_eq!(t.droid_file_time_ns, Some(1264798937840171700));
    assert_eq!(
        l.known_folder_id.as_deref(),
        Some("7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e")
    );
    assert_eq!(l.special_folder_id, Some(42));
    assert_eq!(
        l.icon_environment_location.as_deref(),
        Some(r"%ProgramFiles%\Nero\Nero 9\Nero InfoTool\InfoTool.exe")
    );
    // property store: System.SID-like VT_LPWSTR value
    assert_eq!(l.property_store.len(), 1);
    assert_eq!(l.property_store[0].vtype, 0x1f);
    assert_eq!(
        l.property_store[0].value,
        "S-1-5-21-1649921694-3861100353-2334684395-500"
    );
    assert_eq!(l.target_id_list.len(), 7);
    assert_eq!(l.size, d.len());
}

#[test]
fn example_lnk_no_link_info() {
    let Some(d) = corpus("example.lnk") else {
        return;
    };
    let l = lnk::parse(&d).unwrap();
    assert_eq!(l.creation_filetime, 128920013428491310);
    assert_eq!(l.modification_filetime, 128920091582200000);
    assert_eq!(l.access_filetime, 128920013428491310);
    assert_eq!(l.file_size, 544768);
    assert_eq!(l.link_flags, 33555420);
    assert!(l.link_info.is_none());
    assert_eq!(l.local_path(), None);
    assert_eq!(
        l.description.as_deref(),
        Some(r"@%windir%\system32\migwiz\wet.dll,-590")
    );
    assert_eq!(l.relative_path.as_deref(), Some(r".\migwiz\migwiz.exe"));
    assert_eq!(
        l.working_directory.as_deref(),
        Some(r"%windir%\system32\migwiz")
    );
    assert_eq!(l.command_line_arguments, None);
    assert_eq!(
        l.environment_variables_location.as_deref(),
        Some(r"%windir%\system32\migwiz\migwiz.exe")
    );
    let t = l.tracker.as_ref().unwrap();
    assert_eq!(t.machine_identifier, "win-tj9qcsjkags");
    assert_eq!(
        t.droid_volume_identifier,
        "494ccbda-98e8-45c8-b8ca-f64d464366c7"
    );
    assert_eq!(
        t.droid_file_identifier,
        "846ee3bb-7039-11de-9d20-001d09fa5a1c"
    );
}

#[test]
fn unpaired_surrogate_does_not_fail() {
    let Some(d) = corpus("unpaired_surrogate.lnk") else {
        return;
    };
    let l = lnk::parse(&d).unwrap();
    // pylnk returns the lone surrogate U+D800; Rust strings substitute U+FFFD.
    assert_eq!(
        l.local_path().as_deref(),
        Some("C:\\test\\unicode_U+0000d800_\u{fffd}.exe")
    );
    assert_eq!(l.file_size, 11264);
    assert_eq!(
        l.link_info.as_ref().unwrap().drive_serial_number,
        Some(748933550)
    );
    assert_eq!(l.tracker.as_ref().unwrap().machine_identifier, "test");
    assert_eq!(l.creation_filetime, 133334352807971076);
}

#[test]
fn events_and_determinism() {
    let Some(d) = corpus("NeroInfoTool.lnk") else {
        return;
    };
    let l = lnk::parse(&d).unwrap();
    let ev = lnk::events(&l, "sha", "NeroInfoTool.lnk", 0);
    let link: Vec<_> = ev
        .iter()
        .filter(|e| e.data_type == "windows:lnk:link")
        .collect();
    assert_eq!(link.len(), 3);
    assert_eq!(link[0].timestamp_desc, "Creation Time");
    assert_eq!(
        link[0].attrs["droid_file_identifier"],
        "958705b5-0d19-11df-9fe4-705ab616a5f3"
    );
    assert_eq!(
        link[0].attrs["birth_droid_file_identifier"],
        "958705b5-0d19-11df-9fe4-705ab616a5f3"
    );
    assert_eq!(link[0].attrs["machine_identifier"], "win-3qmdjgkf3g9");
    assert_eq!(
        ev.iter()
            .filter(|e| e.data_type == "windows:distributed_link_tracking:creation")
            .count(),
        1
    );
    let again = lnk::events(&lnk::parse(&d).unwrap(), "sha", "NeroInfoTool.lnk", 0);
    assert_eq!(
        serde_json::to_string(&ev).unwrap(),
        serde_json::to_string(&again).unwrap()
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]
    #[test]
    fn lnk_mutations_never_panic(muts in proptest::collection::vec((0usize..4096, any::<u8>()), 1..32), cut in 0usize..4096) {
        for f in ["NeroInfoTool.lnk", "example.lnk", "unpaired_surrogate.lnk"] {
            if let Some(mut d) = corpus(f) {
                let n = d.len();
                for (o, b) in &muts { d[o % n] = *b; }
                if let Ok(l) = lnk::parse(&d) { let _ = lnk::events(&l, "", "", 0); }
                let _ = lnk::parse(&d[..cut % n]);
            }
        }
    }

    #[test]
    fn property_store_random_never_panics(d in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = lnk::parse_property_store(&d);
    }
}
