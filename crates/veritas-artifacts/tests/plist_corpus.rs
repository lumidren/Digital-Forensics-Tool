//! Plist corpus tests. `tests/fixtures/plist/*.json` were produced with Python's `plistlib`
//! (CPython 3.12) on the same files: dates as microseconds since the epoch, bytes as hex,
//! UIDs as integers, reals as `repr()` strings. Our output must be value-equal.
use proptest::prelude::*;
use serde_json::{Map, Value};
use std::path::PathBuf;
use veritas_artifacts::plist::{self, PlistValue};

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

/// Normalize our JSON into the fixture convention.
fn norm(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            if let Some(ns) = m.get("__date_ns__") {
                // plistlib rounds to microseconds (round-half-even on the float seconds)
                let ns = ns.as_i64().unwrap();
                return serde_json::json!({"__date_us__": (ns as f64 / 1000.0).round() as i64});
            }
            if let Some(r) = m.get("__real__") {
                return serde_json::json!({"__real__": r.as_str().unwrap().parse::<f64>().unwrap()});
            }
            if let Some(s) = m.get("__set__") {
                return norm(s);
            }
            let mut out = Map::new();
            for (k, x) in m {
                out.insert(k.clone(), norm(x));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
        other => other.clone(),
    }
}

fn norm_fixture(v: &Value) -> Value {
    match v {
        Value::Object(m) if m.contains_key("__real__") => {
            serde_json::json!({"__real__": m["__real__"].as_str().unwrap().parse::<f64>().unwrap()})
        }
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| (k.clone(), norm_fixture(x)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(norm_fixture).collect()),
        other => other.clone(),
    }
}

const FILES: &[&str] = &[
    "plist/InstallHistory.plist",
    "plist/NSKeyedArchiver.plist",
    "plist/com.apple.SoftwareUpdate.plist",
    "plist/com.apple.TimeMachine.plist",
    "plist/com.apple.airport.preferences.plist",
    "plist/com.apple.bluetooth.plist",
    "plist/com.apple.loginitems.plist",
    "plist/launchd.minimal.plist",
    "ios/com.apple.MobileBackup.plist",
    "ios/com.apple.wifi.known-networks.plist",
];

#[test]
fn values_equal_plistlib() {
    for f in FILES {
        let Some(d) = corpus(f) else { return };
        let p = plist::parse(&d).unwrap_or_else(|e| panic!("{f}: {e}"));
        let fx = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/plist")
            .join(format!("{}.json", f.replace('/', "__")));
        let expected: Value = serde_json::from_str(&std::fs::read_to_string(fx).unwrap()).unwrap();
        assert_eq!(norm(&p.to_json()), norm_fixture(&expected), "{f}");
    }
}

#[test]
fn ns_keyed_archiver_unarchive() {
    let Some(d) = corpus("plist/NSKeyedArchiver.plist") else {
        return;
    };
    let p = plist::parse(&d).unwrap();
    let u = plist::unarchive(&p).unwrap();
    assert_eq!(
        u.get("MyString").and_then(|v| v.as_str()),
        Some("Some string")
    );
    assert_eq!(u.get("MyInteger"), Some(&PlistValue::Int(98)));
    assert_eq!(u.get("MyBool"), Some(&PlistValue::Bool(true)));
    assert_eq!(
        u.get("MyDate").and_then(|v| v.date_ns()),
        Some(1_707_759_649_000_000_000)
    );
    assert_eq!(u.get("MyData"), Some(&PlistValue::Data(b"DATA\n".to_vec())));
    let ev = plist::events(&p, "s", "NSKeyedArchiver.plist");
    assert!(ev
        .iter()
        .any(|e| e.data_type == "plist:key" && e.attrs["key"] == "MyDate"));
}

#[test]
fn well_known_events() {
    let cases: &[(&str, &str, usize)] = &[
        (
            "plist/InstallHistory.plist",
            "macos:install_history:entry",
            7,
        ),
        (
            "plist/com.apple.SoftwareUpdate.plist",
            "macos:software_update:entry",
            2,
        ),
        (
            "plist/com.apple.TimeMachine.plist",
            "macos:time_machine:backup",
            13,
        ),
        (
            "plist/com.apple.airport.preferences.plist",
            "macos:airport:entry",
            4,
        ),
        (
            "plist/com.apple.bluetooth.plist",
            "macos:bluetooth:entry",
            12,
        ),
        (
            "plist/com.apple.loginitems.plist",
            "macos:login_items:entry",
            1,
        ),
    ];
    for (f, dt, n) in cases {
        let Some(d) = corpus(f) else { return };
        let p = plist::parse(&d).unwrap();
        let ev = plist::events(&p, "s", f);
        assert_eq!(ev.iter().filter(|e| e.data_type == *dt).count(), *n, "{f}");
        // every date value is also present as a generic plist:key event
        let generic = ev.iter().filter(|e| e.data_type == "plist:key").count();
        let mut dates = 0;
        count_dates(&p, &mut dates);
        assert_eq!(generic, dates, "{f}");
    }
    let Some(d) = corpus("plist/InstallHistory.plist") else {
        return;
    };
    let ev = plist::events(&plist::parse(&d).unwrap(), "s", "InstallHistory.plist");
    let first = ev
        .iter()
        .find(|e| e.data_type == "macos:install_history:entry")
        .unwrap();
    assert_eq!(first.attrs["display_name"], "OS X");
    assert_eq!(first.attrs["display_version"], "10.9 (13A603)");
    assert_eq!(first.attrs["process_name"], "OS X Installer");
    assert_eq!(first.timestamp, Some(1_384_225_175_000_000_000)); // 2013-11-12T02:59:35Z
}

fn count_dates(v: &PlistValue, n: &mut usize) {
    match v {
        PlistValue::Date(_) => *n += 1,
        PlistValue::Array(a) | PlistValue::Set(a) => a.iter().for_each(|x| count_dates(x, n)),
        PlistValue::Dict(kv) => kv.iter().for_each(|(_, x)| count_dates(x, n)),
        _ => {}
    }
}

#[test]
fn to_json_sorted_and_deterministic() {
    let Some(d) = corpus("plist/com.apple.bluetooth.plist") else {
        return;
    };
    let a = plist::parse(&d).unwrap().to_json().to_string();
    let b = plist::parse(&d).unwrap().to_json().to_string();
    assert_eq!(a, b);
    let p = plist::parse_xml(
        b"<plist><dict><key>b</key><integer>1</integer><key>a</key><real>0.5</real></dict></plist>",
    )
    .unwrap();
    assert_eq!(p.to_json().to_string(), r#"{"a":{"__real__":"0.5"},"b":1}"#);
}

#[test]
fn cyclic_binary_plist_is_rejected() {
    // bplist00 with one array object that contains itself.
    let mut d = b"bplist00".to_vec();
    d.extend_from_slice(&[0xa1, 0x00]); // array of 1 ref -> object 0
    let table = d.len();
    d.push(8); // offset of object 0
    let mut trailer = vec![0u8; 6];
    trailer.push(1); // offset int size
    trailer.push(1); // ref size
    trailer.extend_from_slice(&1u64.to_be_bytes());
    trailer.extend_from_slice(&0u64.to_be_bytes());
    trailer.extend_from_slice(&(table as u64).to_be_bytes());
    d.extend_from_slice(&trailer);
    assert!(plist::parse(&d).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]
    #[test]
    fn binary_mutations_never_panic(muts in proptest::collection::vec((0usize..1_000_000, any::<u8>()), 1..16), cut in 0usize..1_000_000) {
        for f in ["plist/com.apple.bluetooth.plist", "plist/NSKeyedArchiver.plist"] {
            if let Some(mut d) = corpus(f) {
                let n = d.len();
                for (o, b) in &muts { d[o % n] = *b; }
                if let Ok(p) = plist::parse(&d) { let _ = plist::events(&p, "", f); let _ = p.to_json(); }
                let _ = plist::parse(&d[..cut % n]);
            }
        }
    }

    #[test]
    fn xml_mutations_never_panic(muts in proptest::collection::vec((0usize..1_000_000, any::<u8>()), 1..16)) {
        if let Some(mut d) = corpus("plist/com.apple.airport.preferences.plist") {
            let n = d.len();
            for (o, b) in &muts { d[o % n] = *b; }
            if let Ok(p) = plist::parse(&d) { let _ = plist::events(&p, "", "com.apple.airport.preferences.plist"); }
        }
    }

    #[test]
    fn random_bplist_never_panics(body in proptest::collection::vec(any::<u8>(), 32..512)) {
        let mut d = b"bplist00".to_vec();
        d.extend_from_slice(&body);
        let _ = plist::parse(&d);
    }
}
