//! REGF parser against the public Plaso corpus.
//!
//! Expected numbers were produced once with libregf-python (`pyregf` 20260526) walking every
//! key (`key.sub_keys`, `key.values`, `get_last_written_time_as_integer`) and are hard-coded
//! here; the full per-key comparison lives in `python/tests/parity/test_regf.py`.
//! Tests skip (with a message) when the corpus has not been fetched (`testdata/fetch.py`).
use std::path::PathBuf;
use veritas_artifacts::regf::{Hive, ValueData, ValueType};

fn load(name: &str) -> Option<Vec<u8>> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/corpus/plaso")
        .join(name);
    match std::fs::read(&p) {
        Ok(b) => Some(b),
        Err(_) => {
            eprintln!("corpus file {} missing; skipping", p.display());
            None
        }
    }
}

fn counts(h: &Hive) -> (usize, usize) {
    let mut keys = 0;
    let mut values = 0;
    h.walk(|_, _, k| {
        keys += 1;
        values += k.values().len();
    })
    .unwrap();
    (keys, values)
}

// (file, root key name, keys, values) per pyregf.
const EXPECTED: &[(&str, &str, usize, usize)] = &[
    ("NTUSER.DAT", "$$$PROTO.HIV", 1127, 5602),
    (
        "NTUSER-WIN7.DAT",
        "CMI-CreateHive{D43B12B8-09B5-40DB-B4F6-F6DFEB78DAEC}",
        2288,
        5470,
    ),
    (
        "NTUSER-RunTests.DAT",
        "CMI-CreateHive{D43B12B8-09B5-40DB-B4F6-F6DFEB78DAEC}",
        893,
        1306,
    ),
    (
        "NTUSER-CCLEANER.DAT",
        "CMI-CreateHive{D43B12B8-09B5-40DB-B4F6-F6DFEB78DAEC}",
        1203,
        2373,
    ),
    (
        "SYSTEM",
        "CMI-CreateHive{F10156BE-0E87-4EFB-969E-5DA29D131144}",
        30756,
        73455,
    ),
    (
        "regf/NTUSER.DAT",
        "CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}",
        1597,
        2310,
    ),
    (
        "regf/UsrClass.dat",
        "S-1-5-21-226059406-2984137831-1201299043-1107_Classes",
        7505,
        19987,
    ),
    ("regf/100_sub_keys.hiv", "TestKey", 101, 100),
    (
        "winreg/Amcache.hve",
        "{11517B7C-E79D-4e20-961B-75A811715ADD}",
        2105,
        17539,
    ),
    (
        "winreg/win10-Amcache.hve",
        "{11517B7C-E79D-4e20-961B-75A811715ADD}",
        207,
        4188,
    ),
];

#[test]
fn regf_corpus_key_and_value_counts_match_pyregf() {
    for (name, root, keys, values) in EXPECTED {
        let Some(b) = load(name) else { continue };
        let h = Hive::parse(&b).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(h.base_block().checksum_ok(), "{name} checksum");
        assert_eq!(h.root().unwrap().name, *root, "{name} root");
        assert_eq!(counts(&h), (*keys, *values), "{name} counts");
    }
}

#[test]
fn regf_corpus_software_counts_match_pyregf() {
    let Some(b) = load("SOFTWARE") else { return };
    let h = Hive::parse(&b).unwrap();
    assert_eq!(counts(&h), (117_488, 193_870));
}

#[test]
fn regf_corpus_corrupt_subkey_list_is_tolerated() {
    // pyregf aborts on sub key 8 of the root (cell offset 0xbe00004480); we skip it and keep
    // the readable keys.
    let Some(b) = load("regf/corrupt_sub_key_list.hiv") else {
        return;
    };
    let h = Hive::parse(&b).unwrap();
    let root = h.root().unwrap();
    assert!(root.try_subkeys().is_err());
    let (keys, _) = counts(&h);
    assert!(keys >= 9, "readable keys: {keys}");
}

#[test]
fn regf_corpus_system_values() {
    let Some(b) = load("SYSTEM") else { return };
    let h = Hive::parse(&b).unwrap();
    let bb = h.base_block();
    assert_eq!((bb.major_version, bb.minor_version), (1, 5));
    assert_eq!(bb.primary_sequence, bb.secondary_sequence);
    let sel = h.key("Select").unwrap();
    assert_eq!(sel.value_u32("Current"), Some(1));
    assert_eq!(sel.value_u32("LastKnownGood"), Some(2));
    assert_eq!(sel.last_written_raw, 128_920_207_954_100_473);
    let cn = h
        .key("controlset001\\CONTROL\\ComputerName\\ComputerName")
        .unwrap();
    assert_eq!(
        cn.value_string("ComputerName").as_deref(),
        Some("WKS-WIN732BITA")
    );
    // Default value: name "" and REG_SZ "mnmsrvc".
    let def = cn.value("").unwrap();
    assert_eq!(def.data, ValueData::String("mnmsrvc".into()));
    let tcpip = h.key("ControlSet001\\Services\\Tcpip").unwrap();
    assert_eq!(tcpip.last_written_raw, 129_780_136_266_875_000);
    assert_eq!(
        tcpip.value_string("ImagePath").as_deref(),
        Some("System32\\drivers\\tcpip.sys")
    );
    assert_eq!(tcpip.value("ImagePath").unwrap().kind, ValueType::ExpandSz);
    assert_eq!(tcpip.value_u32("Start"), Some(0));
    let sm = h.key("ControlSet001\\Control\\Session Manager").unwrap();
    assert_eq!(
        sm.value_multi("BootExecute").unwrap(),
        vec!["autocheck autochk *".to_string()]
    );
    let w = h.key("ControlSet001\\Control\\Windows").unwrap();
    assert_eq!(w.value_u64("ShutdownTime"), Some(129_779_783_208_392_499));
    assert_eq!(
        h.key("ControlSet001\\Services").unwrap().subkeys().len(),
        467
    );
    // AppCompatCache is a 56256-byte REG_BINARY, above the 16344-byte big-data threshold.
    let acc = h
        .key("ControlSet001\\Control\\Session Manager\\AppCompatCache")
        .unwrap()
        .value("AppCompatCache")
        .unwrap();
    assert_eq!(acc.raw.len(), 56_256);
    assert!(acc.data_error.is_none());
}

#[test]
fn regf_corpus_software_values() {
    let Some(b) = load("SOFTWARE") else { return };
    let h = Hive::parse(&b).unwrap();
    let cv = h.key("Microsoft\\Windows NT\\CurrentVersion").unwrap();
    assert_eq!(
        cv.value_string("ProductName").as_deref(),
        Some("Windows 7 Ultimate")
    );
    assert_eq!(cv.value_string("CurrentVersion").as_deref(), Some("6.1"));
    assert_eq!(cv.value_string("CurrentBuild").as_deref(), Some("7601"));
    assert_eq!(
        cv.value_string("RegisteredOwner").as_deref(),
        Some("Windows User")
    );
    assert_eq!(cv.value_u32("InstallDate"), Some(0x4cda_c847));
    assert_eq!(cv.last_written_raw, 129_761_825_615_625_000);
    let dpid = cv.value("DigitalProductId4").unwrap();
    assert_eq!(dpid.raw.len(), 1272);
    assert_eq!(
        h.key("Microsoft\\Windows\\CurrentVersion\\Run")
            .unwrap()
            .values()
            .len(),
        7
    );
}

#[test]
fn regf_corpus_amcache_win10_values() {
    let Some(b) = load("winreg/win10-Amcache.hve") else {
        return;
    };
    let h = Hive::parse(&b).unwrap();
    let k = h
        .key("Root\\InventoryApplicationFile\\7z.exe|afe683e0fa522625")
        .unwrap();
    assert_eq!(
        k.value_string("LowerCaseLongPath").as_deref(),
        Some("c:\\program files\\7-zip\\7z.exe")
    );
    assert_eq!(
        k.value_string("FileId").as_deref(),
        Some("00006c7ea8bbd435163ae3945cbef30ef6b9872a4591")
    );
    assert_eq!(k.value("Size").unwrap().data, ValueData::Qword(0x72800));
}

#[test]
fn regf_corpus_deleted_recovery_runs_and_is_deterministic() {
    let Some(b) = load("NTUSER.DAT") else { return };
    let h = Hive::parse(&b).unwrap();
    let a = h.recover_deleted();
    let b2 = h.recover_deleted();
    assert_eq!(a, b2);
    // Every recovered key is unreachable from the root.
    let mut live = std::collections::BTreeSet::new();
    h.walk(|_, _, k| {
        live.insert(k.offset);
    })
    .unwrap();
    assert!(a.keys.iter().all(|k| !live.contains(&k.offset)));
    eprintln!(
        "NTUSER.DAT: {} deleted keys, {} deleted values",
        a.keys.len(),
        a.values.len()
    );
}

#[test]
fn regf_corpus_walk_order_is_deterministic() {
    let Some(b) = load("NTUSER.DAT") else { return };
    let h = Hive::parse(&b).unwrap();
    let a: Vec<String> = h.keys().into_iter().map(|(p, _)| p).collect();
    let b2: Vec<String> = h.keys().into_iter().map(|(p, _)| p).collect();
    assert_eq!(a, b2);
    assert_eq!(a[0], "");
    assert_eq!(a.len(), 1127);
}
