//! EVTX / EVT corpus tests. Expected values come from libevtx-python (pyevtx 20260705) and
//! libevt-python (pyevt 20260705) run over the same files; the expected XML of the first three
//! records of each file is pyevtx's `record.xml_string`, stored in `tests/fixtures/`.
use proptest::prelude::*;
use std::path::PathBuf;
use veritas_artifacts::evtx;

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

fn fixture(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(p).unwrap().replace("\r\n", "\n")
}

#[test]
fn system_evtx_matches_pyevtx() {
    let Some(d) = corpus("evtx/System.evtx") else {
        return;
    };
    let f = evtx::parse(&d).unwrap();
    // pyevtx: number_of_records == 5009, number_of_recovered_records == 0
    assert_eq!(f.records.len(), 5009);
    assert!(f.header.checksum_ok);
    assert_eq!(f.header.number_of_chunks, 27);
    assert!(f
        .chunks
        .iter()
        .all(|c| c.header_crc_ok && c.data_crc_ok && c.errors.is_empty()));
    let r = &f.records[0];
    assert_eq!(r.identifier, 1);
    assert_eq!(r.written_filetime, 129_347_853_596_264_271);
    assert_eq!(r.event_id, Some(7036));
    assert_eq!(r.qualifiers, Some(16384));
    assert_eq!(r.level, Some(4));
    assert_eq!(r.provider_name.as_deref(), Some("Service Control Manager"));
    assert_eq!(
        r.provider_guid.as_deref(),
        Some("{555908d1-a6d7-4695-8e1e-26931d2012f4}")
    );
    assert_eq!(r.source_name(), Some("Service Control Manager"));
    assert_eq!(r.computer.as_deref(), Some("37L4247F27-26"));
    assert_eq!(r.channel.as_deref(), Some("System"));
    assert_eq!(r.process_id, Some(492));
    assert_eq!(r.thread_id, Some(1188));
    assert_eq!(r.keywords.as_deref(), Some("0x8080000000000000"));
    assert_eq!(
        r.time_created.as_deref(),
        Some("2010-11-21T03:55:59.626427100Z")
    );
    assert_eq!(
        r.strings,
        vec![
            "Windows Event Log",
            "stopped",
            "6500760065006E0074006C006F0067002F0031000000"
        ]
    );
    assert_eq!(
        r.event_data,
        vec![
            ("param1".to_string(), "Windows Event Log".to_string()),
            ("param2".to_string(), "stopped".to_string())
        ]
    );
    for i in 0..3 {
        assert_eq!(
            f.records[i].xml,
            fixture(&format!("evtx_System_record{}.xml", i + 1)),
            "record {}",
            i + 1
        );
    }
    // Record 2 is a classic-provider event with unnamed Data elements.
    assert_eq!(
        f.records[1].event_data_unnamed,
        vec!["37L4247F27-26", "WIN-NBRJP24VCHB"]
    );
    // UserData record (pyevtx record 18): Microsoft-Windows-UserPnp 20010
    let r18 = &f.records[17];
    assert_eq!(r18.event_id, Some(20010));
    assert_eq!(r18.user_sid.as_deref(), Some("S-1-5-18"));
    assert!(r18
        .user_data
        .as_ref()
        .unwrap()
        .get("INFO_PNP_STATE")
        .is_some());
    // Event ids of the first 10 records per pyevtx.
    let ids: Vec<u32> = f
        .records
        .iter()
        .take(10)
        .map(|r| r.event_id.unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![7036, 6011, 6009, 6005, 51047, 50037, 7036, 7036, 7036, 7036]
    );
}

#[test]
fn system2_evtx_crc_and_records() {
    let Some(d) = corpus("evtx/System2.evtx") else {
        return;
    };
    let f = evtx::parse(&d).unwrap();
    // pyevtx reports 194 records: libevtx skips chunk 2, whose event-records CRC32 mismatches.
    let valid: Vec<_> = f
        .records
        .iter()
        .filter(|r| r.header_crc_ok && r.data_crc_ok)
        .collect();
    assert_eq!(valid.len(), 194);
    assert_eq!(f.chunks.len(), 3);
    assert!(!f.chunks[2].data_crc_ok);
    assert_eq!(valid[0].event_id, Some(4608));
    assert_eq!(
        valid[0].provider_guid.as_deref(),
        Some("{54849625-5478-4994-A5BA-3E3B0328C30D}")
    );
    assert_eq!(valid[0].written_filetime, 130_834_731_770_781_250);
    for i in 0..3 {
        assert_eq!(
            f.records[i].xml,
            fixture(&format!("evtx_System2_record{}.xml", i + 1)),
            "record {}",
            i + 1
        );
    }
    // 4624 logon: analytics fields promoted to top-level attrs.
    let logon = f.records.iter().find(|r| r.event_id == Some(4624)).unwrap();
    let evs = evtx::record_event(logon, "sha", "System2.evtx");
    let a = &evs[0].attrs;
    assert_eq!(a["known_name"], "logon_success");
    assert_eq!(a["known_category"], "logon");
    assert!(a.contains_key("logon_type"));
    assert!(a.contains_key("target_user_name"));
}

#[test]
fn events_shape_and_determinism() {
    let Some(d) = corpus("evtx/System.evtx") else {
        return;
    };
    let f = evtx::parse(&d).unwrap();
    let ev = evtx::events(&f, "abc", "System.evtx");
    assert_eq!(ev.len(), 5009);
    let e = &ev[0];
    assert_eq!(e.data_type, "windows:evtx:record");
    assert_eq!(e.timestamp_desc, "Content Modification Time");
    assert!(e.message.starts_with("[7036 / 0x1b7c] Source Name: Service Control Manager Strings: ['Windows Event Log', 'stopped'"));
    assert_eq!(e.attrs["event_identifier"], 7036);
    assert_eq!(e.attrs["known_category"], "service");
    let a = serde_json::to_string(&ev).unwrap();
    let b = serde_json::to_string(&evtx::events(
        &evtx::parse(&d).unwrap(),
        "abc",
        "System.evtx",
    ))
    .unwrap();
    assert_eq!(a, b);
    // 7045 service install promotes service_name / image_path.
    let svc = ev
        .iter()
        .find(|e| e.attrs["event_identifier"] == 7045)
        .unwrap();
    assert_eq!(
        svc.attrs["service_name"],
        "Intel(R) PRO/1000 NDIS 6 Adapter Driver"
    );
    assert_eq!(svc.attrs["image_path"], "system32\\DRIVERS\\E1G6032E.sys");
}

#[test]
fn legacy_evt_matches_pyevt() {
    let Some(d) = corpus("SysEvent.Evt") else {
        return;
    };
    let recs = evtx::parse_evt(&d).unwrap();
    // pyevt: number_of_records 6063 (record numbers 1392..=7454), number_of_recovered_records 438.
    let live: Vec<_> = recs.iter().filter(|r| !r.recovered).collect();
    assert_eq!(live.len(), 6063);
    assert_eq!(live.first().unwrap().record_number, 1392);
    assert_eq!(live.last().unwrap().record_number, 7454);
    assert_eq!(live[0].event_identifier, 2147524609);
    assert_eq!(live[0].source_name, "LSASRV");
    let recovered = recs.iter().filter(|r| r.recovered).count();
    assert!((430..=438).contains(&recovered), "{recovered}");
    let ev = evtx::evt_events(&recs[..2], "x", "SysEvent.Evt");
    assert_eq!(ev.len(), 4);
    assert_eq!(ev[0].data_type, "windows:evt:record");
}

#[test]
fn template_nesting_and_garbage_do_not_panic() {
    // A chunk whose single record is a template instance pointing at itself.
    let mut d = vec![0u8; 4096 + 65536];
    d[..8].copy_from_slice(b"ElfFile\0");
    let c = 4096;
    d[c..c + 8].copy_from_slice(b"ElfChnk\0");
    d[c + 48..c + 52].copy_from_slice(&(65536u32).to_le_bytes());
    let r = c + 512;
    d[r..r + 4].copy_from_slice(&0x2a2au32.to_le_bytes());
    d[r + 4..r + 8].copy_from_slice(&200u32.to_le_bytes());
    // Template definition at chunk offset 2048 whose body instantiates itself.
    let x = 2048usize;
    d[c + x + 20..c + x + 24].copy_from_slice(&18u32.to_le_bytes());
    let body = c + x + 24;
    d[body] = 0x0c;
    d[body + 6..body + 10].copy_from_slice(&(x as u32).to_le_bytes());
    // record: fragment header + template instance referencing the definition, 0 values, EOF
    let b = r + 24;
    d[b..b + 4].copy_from_slice(&[0x0f, 1, 1, 0]);
    d[b + 4] = 0x0c;
    d[b + 10..b + 14].copy_from_slice(&(x as u32).to_le_bytes());
    let f = evtx::parse(&d).unwrap();
    assert_eq!(f.records.len(), 1);
    assert!(
        f.chunks[0].errors.iter().any(|e| e.contains("nesting")),
        "{:?}",
        f.chunks[0].errors
    );
}

fn first_chunk() -> Option<Vec<u8>> {
    corpus("evtx/System.evtx").map(|d| d[..4096 + 65536].to_vec())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]
    #[test]
    fn evtx_mutations_never_panic(muts in proptest::collection::vec((0usize..69632, any::<u8>()), 1..64), cut in 0usize..69632) {
        if let Some(mut d) = first_chunk() {
            for (o, b) in muts { d[o] = b; }
            let _ = evtx::parse(&d);
            let _ = evtx::parse(&d[..cut]);
        }
    }

    #[test]
    fn evt_mutations_never_panic(muts in proptest::collection::vec((0usize..65536, any::<u8>()), 1..64), cut in 0usize..65536) {
        if let Some(d) = corpus("SysEvent.Evt") {
            let mut d = d[..65536].to_vec();
            for (o, b) in muts { d[o] = b; }
            let _ = evtx::parse_evt(&d);
            let _ = evtx::parse_evt(&d[..cut]);
        }
    }

    #[test]
    fn evtx_random_bytes_never_panic(d in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let mut x = b"ElfFile\0".to_vec();
        x.extend_from_slice(&d);
        let _ = evtx::parse(&x);
    }
}
