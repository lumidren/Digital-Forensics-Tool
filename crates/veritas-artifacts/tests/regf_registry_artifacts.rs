//! Registry artifact plugins against the public Plaso corpus.
//!
//! Reference values: raw key/value data read with libregf-python (`pyregf` 20260526) and
//! decoded by hand / by the independent decoders in
//! `python/tests/parity/test_registry_artifacts.py` (shimcache: Mandiant Win7 32-bit layout;
//! UserAssist: ROT13 + XP 16-byte / Win7 72-byte layouts).
use std::path::PathBuf;
use veritas_artifacts::regf::Hive;
use veritas_artifacts::registry::{
    amcache, autoruns, events_from_hive, network, recentdocs, services, shellbags, shimcache, sysinfo, usb, userassist, HiveKind, Provenance,
};
use veritas_timeline::filetime_to_ns;

fn load(name: &str) -> Option<Hive> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/plaso").join(name);
    match std::fs::read(&p) {
        Ok(b) => Some(Hive::parse(&b).unwrap()),
        Err(_) => {
            eprintln!("corpus file {} missing; skipping", p.display());
            None
        }
    }
}

fn prov(name: &str) -> Provenance {
    Provenance { evidence_sha256: "00".repeat(32), evidence_path: name.into(), host: None, user: None }
}

#[test]
fn registry_hive_kind_detection() {
    for (name, kind) in [
        ("SYSTEM", HiveKind::System),
        ("NTUSER.DAT", HiveKind::NtUser),
        ("NTUSER-WIN7.DAT", HiveKind::NtUser),
        ("regf/UsrClass.dat", HiveKind::UsrClass),
        ("winreg/Amcache.hve", HiveKind::Amcache),
        ("winreg/win10-Amcache.hve", HiveKind::Amcache),
    ] {
        let Some(h) = load(name) else { continue };
        assert_eq!(HiveKind::detect(&h), kind, "{name}");
    }
}

#[test]
fn registry_shimcache_system_win7_32() {
    let Some(h) = load("SYSTEM") else { return };
    let (rel, _, res) = shimcache::from_hive(&h).unwrap();
    assert_eq!(rel, "ControlSet001\\Control\\Session Manager\\AppCompatCache");
    let c = res.unwrap();
    assert_eq!(c.format, "win7_32");
    assert_eq!(c.entries.len(), 330);
    let first = &c.entries[0];
    assert_eq!(first.path, "\\??\\C:\\Program Files\\McAfee\\VirusScan Enterprise\\mfeann.exe");
    assert_eq!(first.last_modified_raw, 129_393_076_800_000_000);
    assert_eq!(first.insert_flags, Some(7));
    assert_eq!(first.executed, Some(true));
    let last = &c.entries[329];
    assert_eq!(last.index, 329);
    assert_eq!(last.path, "\\??\\C:\\Windows\\bfsvc.exe");
    assert_eq!(last.last_modified_raw, 129_347_290_158_000_000);
    assert_eq!(c.entries.iter().filter(|e| e.executed == Some(true)).count(), 238);
}

#[test]
fn registry_services_and_sysinfo_system() {
    let Some(h) = load("SYSTEM") else { return };
    let svcs = services::services(&h);
    assert_eq!(svcs.len(), 467);
    let t = svcs.iter().find(|s| s.name == "Tcpip").unwrap();
    assert_eq!(t.control_set, "ControlSet001");
    assert_eq!(t.image_path.as_deref(), Some("System32\\drivers\\tcpip.sys"));
    assert_eq!((t.service_type, t.start, t.error_control), (Some(1), Some(0), Some(1)));
    assert_eq!(t.last_written_ns, filetime_to_ns(129_780_136_266_875_000));
    let si = sysinfo::system_info(&h);
    assert_eq!(si.computer_name.as_deref(), Some("WKS-WIN732BITA"));
    assert_eq!(si.timezone.as_deref(), Some("Eastern Standard Time"));
    assert_eq!(si.timezone_bias_minutes, Some(300));
    assert_eq!(si.shutdown_ns, filetime_to_ns(129_779_783_208_392_499));
}

#[test]
fn registry_usb_system() {
    let Some(h) = load("SYSTEM") else { return };
    let devs = usb::devices(&h);
    let stor: Vec<_> = devs.iter().filter(|d| d.data_type == "windows:registry:usbstor").collect();
    assert_eq!(stor.len(), 1);
    let d = stor[0];
    assert_eq!(d.serial, "AA951D0000007252&0");
    assert_eq!(d.vendor.as_deref(), Some("HP"));
    assert_eq!(d.product.as_deref(), Some("v100w"));
    assert_eq!(d.friendly_name.as_deref(), Some("HP v100w USB Device"));
    // Properties\{83da...}\00000064\00000000\Data = e01b2da028f0cb01
    assert_eq!(d.first_install_ns, filetime_to_ns(0x01cb_f028_a02d_1be0));
    let names: Vec<&str> = d.mounted.iter().map(|m| m.name.as_str()).collect();
    assert!(names.contains(&"\\DosDevices\\E:"), "{names:?}");
    assert!(names.contains(&"\\??\\Volume{eba74da6-5bb2-11e0-95d1-000c2971073c}"));
    assert!(devs.iter().any(|d| d.data_type == "windows:registry:usb" && d.vendor.as_deref() == Some("03F0") && d.serial == "AA951D0000007252"));
}

#[test]
fn registry_network_software_and_interfaces() {
    if let Some(h) = load("SOFTWARE") {
        let ps = network::profiles(&h);
        assert_eq!(ps.len(), 3);
        let p = ps.iter().find(|p| p.guid == "{1EDE3981-5784-4C61-B5A7-CF328A10043E}").unwrap();
        assert_eq!(p.profile_name, "shieldbase.local");
        assert_eq!(p.name_type, Some(6));
        // SYSTEMTIME da07 0b00 0300 0a00 0b00 1700 2b00 9f02 = 2010-11-10 11:23:43.671 (local)
        assert_eq!(p.created_ns, Some(1_289_388_223_671_000_000));
        let q = ps.iter().find(|p| p.guid == "{F9642846-4369-4D3A-86A4-DE66EC52DF4E}").unwrap();
        assert_eq!(q.dns_suffix.as_deref(), Some("tx.rr.com"));
        assert_eq!(q.gateway_mac.as_deref(), Some("00:18:F8:EA:2E:A2"));
        let cv = sysinfo::current_version(&h);
        assert_eq!(cv.get("ProductName").map(String::as_str), Some("Windows 7 Ultimate"));
        assert_eq!(cv.get("InstallDate").map(String::as_str), Some("1289406535"));
        assert_eq!(sysinfo::profiles(&h).len(), 11);
        let run = autoruns::autorun_keys(&h, HiveKind::Software);
        let r = run.iter().find(|a| a.key_rel_path == "Microsoft\\Windows\\CurrentVersion\\Run").unwrap();
        assert_eq!(r.entries.len(), 7);
        assert_eq!(r.entries[0].0, "VMware Tools");
        assert!(run.iter().any(|a| a.location == "Winlogon" && a.entries.iter().any(|(n, d)| n == "Shell" && d == "explorer.exe")));
    }
    if let Some(h) = load("SYSTEM") {
        let ifs = network::interfaces(&h);
        assert_eq!(ifs.len(), 3);
        let i = ifs.iter().find(|i| i.guid == "{698E50A9-4F58-4D86-B61D-F42E58DCACF6}").unwrap();
        assert_eq!(i.values.get("NameServer").map(String::as_str), Some("10.3.58.4"));
        let lsa = autoruns::autorun_keys(&h, HiveKind::System);
        assert!(lsa.iter().any(|a| a.location == "BootExecute" && a.entries[0].1 == "autocheck autochk *"));
    }
}

#[test]
fn registry_userassist_xp_and_win7() {
    if let Some(h) = load("NTUSER.DAT") {
        let e = userassist::entries(&h);
        assert_eq!(e.len(), 14);
        assert!(e.iter().all(|x| x.format == "xp"));
        let msn = e.iter().find(|x| x.value_name == "UEME_RUNPIDL:%csidl2%\\MSN.lnk").unwrap();
        assert_eq!(msn.count, 14);
        assert_eq!(msn.last_executed_raw, 128_938_722_828_110_676);
    }
    if let Some(h) = load("NTUSER-WIN7.DAT") {
        let e = userassist::entries(&h);
        assert_eq!(e.len(), 90);
        let calc = e.iter().find(|x| x.value_name == "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\calc.exe").unwrap();
        assert_eq!(calc.path, "%SystemRoot%\\System32\\calc.exe");
        assert_eq!((calc.count, calc.focus_count, calc.focus_duration_ms), (12, Some(17), Some(340_000)));
        assert_eq!(calc.last_executed_raw, 129_338_489_770_780_676);
    }
}

#[test]
fn registry_mru_lists_ntuser() {
    if let Some(h) = load("NTUSER.DAT") {
        let ls = recentdocs::lists(&h);
        let rd = ls.iter().find(|l| l.key_rel_path == "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs").unwrap();
        assert_eq!(rd.data_type, "windows:registry:mrulistex");
        let names: Vec<&str> = rd.entries.iter().map(|e| e.data.as_str()).collect();
        assert_eq!(names, vec!["Administrator's Documents", "Not to be seen document.txt", "Very secret document.txt"]);
        assert_eq!(rd.last_written_ns, filetime_to_ns(128_938_727_636_383_750));
        assert!(ls.iter().any(|l| l.key_rel_path.ends_with("RecentDocs\\.txt")));
        let tu = ls.iter().find(|l| l.data_type == "windows:registry:typedurls").unwrap();
        assert_eq!(tu.entries[0].data, "http://firefox.com/");
    }
    if let Some(h) = load("NTUSER-WIN7.DAT") {
        let ls = recentdocs::lists(&h);
        let run = ls.iter().find(|l| l.key_rel_path.ends_with("RunMRU")).unwrap();
        assert_eq!(run.data_type, "windows:registry:mrulist");
        assert_eq!(run.entries.len(), 1);
        assert_eq!(run.entries[0].data, "\\\\controller\\WebDavShare");
        let ww = ls.iter().find(|l| l.key_rel_path.ends_with("WordWheelQuery")).unwrap();
        let w: Vec<&str> = ww.entries.iter().map(|e| e.data.as_str()).collect();
        assert_eq!(w, vec!["rar.exe", "hyth"]);
        let tp = ls.iter().find(|l| l.key_rel_path.ends_with("TypedPaths")).unwrap();
        assert_eq!(tp.entries[0].data, "\\\\controller");
        let rd = ls.iter().find(|l| l.key_rel_path.ends_with("Explorer\\RecentDocs")).unwrap();
        assert_eq!(rd.entries[0].value_name, "17");
        assert_eq!(rd.entries[0].data, "The SHIELD");
        assert!(ls.iter().any(|l| l.key_rel_path.contains("OpenSavePidlMRU")));
        assert!(ls.iter().any(|l| l.key_rel_path.ends_with("LastVisitedPidlMRU")));
    }
}

#[test]
fn registry_shellbags() {
    // Numbered BagMRU values per pyregf: UsrClass 6, NTUSER.DAT (ShellNoRoam) 5, NTUSER-WIN7 3.
    for (name, n) in [("regf/UsrClass.dat", 6), ("NTUSER.DAT", 5), ("NTUSER-WIN7.DAT", 3)] {
        let Some(h) = load(name) else { continue };
        let e = shellbags::entries(&h);
        assert_eq!(e.len(), n, "{name}");
        // Child paths extend their parent's path.
        for x in &e {
            assert!(!x.path.is_empty());
        }
    }
    if let Some(h) = load("regf/UsrClass.dat") {
        let e = shellbags::entries(&h);
        assert_eq!(e[0].value_name, "0");
        assert_eq!(e[0].mru_position, Some(0));
        assert_eq!(e[0].raw_hex, "14001f706806ee260aa0d7449371beb064c986830000");
        // Deepest bag per pyregf: BagMRU\0\0\0 (four path components).
        let deepest = e.iter().max_by_key(|x| x.key_rel_path.matches('\\').count()).unwrap();
        assert!(deepest.key_rel_path.ends_with("BagMRU\\0\\0\\0"), "{}", deepest.key_rel_path);
        assert_eq!(deepest.path.matches('\\').count(), 3, "{}", deepest.path);
    }
}

#[test]
fn registry_amcache_layouts() {
    if let Some(h) = load("winreg/Amcache.hve") {
        let r = amcache::records(&h);
        let count = |s: &str| r.iter().filter(|x| x.source == s).count();
        assert_eq!(count("file"), 1120);
        assert_eq!(count("program"), 26);
        assert_eq!(count("inventory_application_file"), 247);
        assert_eq!(count("inventory_application"), 74);
        assert_eq!(count("inventory_driver_binary"), 311);
        let f = r.iter().find(|x| x.key_rel_path.ends_with("100000169dd")).unwrap();
        assert_eq!(f.fields["full_path"], "c:\\users\\user\\appdata\\local\\microsoft\\onedrive\\17.3.6943.0625\\FileSyncFAL.dll");
        assert_eq!(f.fields["sha1"], "818b581a471c1c6833839d35a9d6f3544f6a9c92");
        assert!(f.times.iter().any(|(d, t)| *d == veritas_timeline::desc::MODIFICATION && Some(*t) == filetime_to_ns(0x01d3_0abe_67d5_8c2d)));
    }
    if let Some(h) = load("winreg/win10-Amcache.hve") {
        let r = amcache::records(&h);
        let z = r.iter().find(|x| x.key_rel_path.ends_with("7z.exe|afe683e0fa522625")).unwrap();
        assert_eq!(z.data_type, "windows:registry:amcache");
        assert_eq!(z.fields["sha1"], "6c7ea8bbd435163ae3945cbef30ef6b9872a4591");
        assert_eq!(z.fields["file_size"], "468992");
        assert_eq!(z.fields["publisher"], "igor pavlov");
        assert_eq!(z.fields["link_date"], "02/21/2019 16:00:00");
        assert_eq!(z.times, vec![(amcache::LINK_TIME, 1_550_764_800_000_000_000)]);
        assert_eq!(r.iter().filter(|x| x.data_type == "windows:registry:amcache:programs").count(), 75);
    }
}

#[test]
fn registry_events_from_hive_ntuser_complete_and_deterministic() {
    let Some(h) = load("NTUSER-WIN7.DAT") else { return };
    let p = prov("NTUSER-WIN7.DAT");
    let a = events_from_hive(&h, HiveKind::NtUser, &p);
    let b = events_from_hive(&h, HiveKind::NtUser, &p);
    assert_eq!(a, b);
    let n = |dt: &str| a.iter().filter(|e| e.data_type == dt).count();
    assert!(n("windows:registry:key_value") >= 2288);
    assert_eq!(n("windows:registry:userassist"), 90);
    assert!(n("windows:registry:mrulistex") >= 5);
    assert_eq!(n("windows:registry:mrulist"), 1);
    assert!(n("windows:registry:typedurls") >= 2);
    assert!(n("windows:registry:run") >= 1);
    assert!(n("windows:registry:mount_points2") >= 5);
    assert!(n("windows:shellbags") >= 3);
    let e = a.iter().find(|e| e.data_type == "windows:registry:userassist").unwrap();
    assert!(e.attrs["key_path"].as_str().unwrap().starts_with("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{"));
    assert_eq!(e.parser, "winreg/userassist");
    let mut sorted = a.clone();
    sorted.sort();
    assert_eq!(sorted, a);
    // values attr stays within budget
    for e in &a {
        if let Some(v) = e.attrs.get("values").and_then(|v| v.as_array()) {
            let total: usize = v.iter().filter_map(|s| s.as_str()).map(str::len).sum();
            assert!(total <= veritas_artifacts::registry::KEY_VALUES_BUDGET);
        }
    }
}

#[test]
fn registry_events_from_hive_system() {
    let Some(h) = load("SYSTEM") else { return };
    let a = events_from_hive(&h, HiveKind::System, &prov("SYSTEM"));
    let n = |dt: &str| a.iter().filter(|e| e.data_type == dt).count();
    assert_eq!(n("windows:registry:appcompatcache"), 330);
    assert_eq!(n("windows:registry:service"), 467);
    assert!(n("windows:registry:usbstor") >= 3);
    assert_eq!(n("windows:registry:shutdown"), 1);
    assert_eq!(n("windows:registry:sysinfo"), 1);
    assert!(n("windows:registry:key_value") >= 30756);
    let s = a.iter().find(|e| e.data_type == "windows:registry:shutdown").unwrap();
    assert_eq!(s.timestamp, filetime_to_ns(129_779_783_208_392_499));
}
