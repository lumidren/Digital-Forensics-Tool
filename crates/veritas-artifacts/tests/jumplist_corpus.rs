//! Jump list / OLECF corpus tests. Stream enumeration expectations come from libolecf-python
//! (pyolecf 20260526) root item sub items; embedded LNK local paths from pylnk 20260525 on each
//! stream; DestList entry counts and the first entry are checked against the stream bytes
//! read through pyolecf (DestList header: version, number of entries).
use proptest::prelude::*;
use std::path::PathBuf;
use veritas_artifacts::{jumplist, olecf};

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
fn automatic_destinations_win7() {
    let Some(d) = corpus("automaticDestinations-ms/1b4dd67f29cb1962.automaticDestinations-ms")
    else {
        return;
    };
    let ole = olecf::Olecf::parse(&d).unwrap();
    let mut names: Vec<String> = ole
        .root_children()
        .into_iter()
        .map(|i| ole.entries[i].name.clone())
        .collect();
    names.sort();
    // pyolecf: ['1', 'DestList', '2', '3', '4', '5', '6', '7']
    assert_eq!(names, ["1", "2", "3", "4", "5", "6", "7", "DestList"]);
    let a = jumplist::parse_automatic(&d).unwrap();
    let dl = a.dest_list.as_ref().unwrap();
    assert_eq!(dl.version, 1);
    assert_eq!(dl.number_of_entries, 7);
    assert_eq!(dl.entries.len(), 7);
    let e = &dl.entries[0];
    assert_eq!(e.entry_number, 7);
    assert_eq!(e.hostname, "student-pc1");
    assert_eq!(e.path, r"C:\Users\bperry\Downloads");
    assert_eq!(e.last_modification_filetime, 130853359640343008);
    assert_eq!(e.pin_status, -1);
    assert_eq!(
        e.droid_file_identifier.as_deref(),
        Some("9b1ce584-4a4c-11e5-b5c9-080027ac3d7f")
    );
    assert_eq!(a.streams.len(), 7);
    let sizes: Vec<usize> = a.streams.iter().map(|s| s.size).collect();
    assert_eq!(sizes, [416, 415, 412, 413, 1573, 4803, 542]);
    assert_eq!(
        a.streams[0].lnk.as_ref().unwrap().local_path().as_deref(),
        Some(r"C:\Users\bperry\AppData\Roaming\Microsoft\Windows\Libraries\Documents.library-ms")
    );
    assert_eq!(
        a.streams[0].lnk.as_ref().unwrap().modification_filetime,
        130849722317294695
    );
    let ev = jumplist::automatic_events(&a, "sha", "x");
    assert_eq!(
        ev.iter()
            .filter(|e| e.data_type == "windows:jump_list:automatic_destination")
            .count(),
        7
    );
    assert!(ev.iter().any(|e| e.data_type == "windows:lnk:link"));
}

#[test]
fn automatic_destinations_win10() {
    let Some(d) = corpus("automaticDestinations-ms/9d1f905ce5044aee.automaticDestinations-ms")
    else {
        return;
    };
    let a = jumplist::parse_automatic(&d).unwrap();
    let dl = a.dest_list.as_ref().unwrap();
    assert_eq!(dl.version, 3);
    assert_eq!(dl.entries.len(), 2);
    assert_eq!(
        dl.entries[0].path,
        "http://support.microsoft.com/kb/3124263"
    );
    assert_eq!(dl.entries[0].access_count, Some(1));
    assert_eq!(dl.entries[1].entry_number, 1);
    let sizes: Vec<usize> = a.streams.iter().map(|s| s.size).collect();
    assert_eq!(sizes, [465, 337]);
    // pylnk: no local path in either stream
    assert!(a
        .streams
        .iter()
        .all(|s| s.lnk.as_ref().unwrap().local_path().is_none()));
}

#[test]
fn custom_destinations() {
    let Some(d) = corpus("customDestinations-ms/368d807282ccde9d.customDestinations-ms") else {
        return;
    };
    let c = jumplist::parse_custom(&d).unwrap();
    assert_eq!(c.categories, ["My Category 1", "My Category 2"]);
    assert_eq!(c.entries.len(), 3);
    assert_eq!(c.entries[0].category.as_deref(), Some("My Category 1"));
    assert_eq!(c.entries[2].category.as_deref(), Some("My Category 2"));
    assert_eq!(c.entries[0].lnk.local_path().as_deref(), Some(r"C:\test"));
    let Some(d) = corpus("customDestinations-ms/5afe4de1b92fc382.customDestinations-ms") else {
        return;
    };
    let c = jumplist::parse_custom(&d).unwrap();
    assert_eq!(c.entries.len(), 9);
    assert!(c
        .entries
        .iter()
        .all(|e| e.lnk.local_path().as_deref() == Some(r"C:\Windows\System32\GettingStarted.exe")));
    let ev = jumplist::custom_events(&c, "sha", "x");
    assert!(ev.iter().all(|e| e.data_type != "windows:lnk:link"));
    assert!(ev
        .iter()
        .any(|e| e.data_type == "windows:jump_list:custom_destination"));
}

#[test]
fn olecf_document_summary() {
    let Some(d) = corpus("Document.doc") else {
        return;
    };
    let o = olecf::Olecf::parse(&d).unwrap();
    let names: Vec<String> = o.walk().into_iter().map(|(p, _)| p).collect();
    assert!(names.iter().any(|n| n == "/WordDocument"));
    let si = o.summary_information();
    assert!(si.keys().any(|k| k.starts_with("summary.")), "{si:?}");
}

#[test]
fn determinism() {
    let Some(d) = corpus("automaticDestinations-ms/1b4dd67f29cb1962.automaticDestinations-ms")
    else {
        return;
    };
    let a = serde_json::to_string(&jumplist::automatic_events(
        &jumplist::parse_automatic(&d).unwrap(),
        "s",
        "p",
    ))
    .unwrap();
    let b = serde_json::to_string(&jumplist::automatic_events(
        &jumplist::parse_automatic(&d).unwrap(),
        "s",
        "p",
    ))
    .unwrap();
    assert_eq!(a, b);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]
    #[test]
    fn olecf_mutations_never_panic(muts in proptest::collection::vec((0usize..1_000_000, any::<u8>()), 1..32), cut in 0usize..1_000_000) {
        for f in ["automaticDestinations-ms/1b4dd67f29cb1962.automaticDestinations-ms", "automaticDestinations-ms/9d1f905ce5044aee.automaticDestinations-ms"] {
            if let Some(mut d) = corpus(f) {
                let n = d.len();
                for (o, b) in &muts { d[o % n] = *b; }
                if let Ok(a) = jumplist::parse_automatic(&d) { let _ = jumplist::automatic_events(&a, "", ""); }
                if let Ok(o) = olecf::Olecf::parse(&d) { let _ = o.walk(); let _ = o.summary_information(); }
                let _ = jumplist::parse_automatic(&d[..cut % n]);
            }
        }
    }

    #[test]
    fn custom_mutations_never_panic(muts in proptest::collection::vec((0usize..1_000_000, any::<u8>()), 1..32), cut in 0usize..1_000_000) {
        if let Some(mut d) = corpus("customDestinations-ms/368d807282ccde9d.customDestinations-ms") {
            let n = d.len();
            for (o, b) in &muts { d[o % n] = *b; }
            let _ = jumplist::parse_custom(&d);
            let _ = jumplist::parse_custom(&d[..cut % n]);
        }
    }

    #[test]
    fn destlist_random_never_panics(d in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = jumplist::parse_dest_list(&d);
    }
}
