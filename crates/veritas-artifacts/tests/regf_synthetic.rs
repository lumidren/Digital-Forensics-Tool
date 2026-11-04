//! REGF features that the public corpus does not exercise, on hives built in-test:
//! big data (`db`), resident data, nested `ri` lists, cycles, depth cap, deleted-cell recovery,
//! new-format transaction-log replay and BAM.
use veritas_artifacts::regf::{
    base_block_checksum, marvin32, Hive, ValueData, ValueType, MARVIN32_REGISTRY_SEED,
};
use veritas_artifacts::registry::{bam, events_from_hive, HiveKind, Provenance};

const FT: u64 = 132_000_000_000_000_000; // 2019-04-12

/// Minimal hive writer: cells are appended to one growing hive-bin region.
struct B {
    region: Vec<u8>, // starts at hive-bins offset 0 (the hbin header is written in finish)
}

impl B {
    fn new() -> Self {
        B {
            region: vec![0u8; 32],
        }
    }
    fn alloc(&mut self, data: &[u8]) -> u32 {
        let off = self.region.len() as u32;
        let size = (data.len() + 4).div_ceil(8) * 8;
        self.region.extend((-(size as i32)).to_le_bytes());
        self.region.extend(data);
        self.region.resize(off as usize + size, 0);
        off
    }
    fn free(&mut self, off: u32) {
        let o = off as usize;
        let s = i32::from_le_bytes(self.region[o..o + 4].try_into().unwrap());
        self.region[o..o + 4].copy_from_slice(&s.abs().to_le_bytes());
    }
    fn patch_u32(&mut self, cell: u32, at: usize, v: u32) {
        let o = cell as usize + 4 + at;
        self.region[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn nk(&mut self, name: &str, nsub: u32, sublist: u32, nval: u32, vallist: u32) -> u32 {
        let mut d = vec![0u8; 76];
        d[0..2].copy_from_slice(b"nk");
        d[2..4].copy_from_slice(&0x20u16.to_le_bytes());
        d[4..12].copy_from_slice(&FT.to_le_bytes());
        d[20..24].copy_from_slice(&nsub.to_le_bytes());
        d[28..32].copy_from_slice(&sublist.to_le_bytes());
        d[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        d[36..40].copy_from_slice(&nval.to_le_bytes());
        d[40..44].copy_from_slice(&vallist.to_le_bytes());
        d[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
        d[48..52].copy_from_slice(&u32::MAX.to_le_bytes());
        d[72..74].copy_from_slice(&(name.len() as u16).to_le_bytes());
        d.extend(name.as_bytes());
        self.alloc(&d)
    }
    fn vk(&mut self, name: &str, kind: u32, data: &[u8]) -> u32 {
        let (size_field, data_off) = if data.len() <= 4 {
            let mut b = [0u8; 4];
            b[..data.len()].copy_from_slice(data);
            (0x8000_0000 | data.len() as u32, u32::from_le_bytes(b))
        } else if data.len() > 16344 {
            let mut segs = Vec::new();
            for chunk in data.chunks(16344) {
                segs.push(self.alloc(chunk));
            }
            let list: Vec<u8> = segs.iter().flat_map(|s| s.to_le_bytes()).collect();
            let lo = self.alloc(&list);
            let mut db = b"db".to_vec();
            db.extend((segs.len() as u16).to_le_bytes());
            db.extend(lo.to_le_bytes());
            (data.len() as u32, self.alloc(&db))
        } else {
            (data.len() as u32, self.alloc(data))
        };
        let mut d = vec![0u8; 20];
        d[0..2].copy_from_slice(b"vk");
        d[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
        d[4..8].copy_from_slice(&size_field.to_le_bytes());
        d[8..12].copy_from_slice(&data_off.to_le_bytes());
        d[12..16].copy_from_slice(&kind.to_le_bytes());
        d[16..18].copy_from_slice(&1u16.to_le_bytes());
        d.extend(name.as_bytes());
        self.alloc(&d)
    }
    fn list(&mut self, sig: &[u8; 2], offs: &[u32]) -> u32 {
        let mut d = sig.to_vec();
        d.extend((offs.len() as u16).to_le_bytes());
        for o in offs {
            d.extend(o.to_le_bytes());
            if sig == b"lf" || sig == b"lh" {
                d.extend(0u32.to_le_bytes());
            }
        }
        self.alloc(&d)
    }
    fn vlist(&mut self, offs: &[u32]) -> u32 {
        let d: Vec<u8> = offs.iter().flat_map(|o| o.to_le_bytes()).collect();
        self.alloc(&d)
    }
    fn finish(mut self, root: u32) -> Vec<u8> {
        let used = self.region.len();
        let size = (used + 8).div_ceil(4096) * 4096;
        let free = size - used;
        self.region.extend((free as i32).to_le_bytes());
        self.region.resize(size, 0);
        self.region[0..4].copy_from_slice(b"hbin");
        self.region[8..12].copy_from_slice(&(size as u32).to_le_bytes());
        let mut base = vec![0u8; 4096];
        base[0..4].copy_from_slice(b"regf");
        base[4..8].copy_from_slice(&4u32.to_le_bytes());
        base[8..12].copy_from_slice(&4u32.to_le_bytes());
        base[12..20].copy_from_slice(&FT.to_le_bytes());
        base[20..24].copy_from_slice(&1u32.to_le_bytes());
        base[24..28].copy_from_slice(&5u32.to_le_bytes());
        base[32..36].copy_from_slice(&1u32.to_le_bytes());
        base[36..40].copy_from_slice(&root.to_le_bytes());
        base[40..44].copy_from_slice(&(size as u32).to_le_bytes());
        base[44..48].copy_from_slice(&1u32.to_le_bytes());
        let ck = base_block_checksum(&base).unwrap();
        base[508..512].copy_from_slice(&ck.to_le_bytes());
        base.extend(self.region);
        base
    }
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

struct Built {
    bytes: Vec<u8>,
    big: Vec<u8>,
    a_offset: u32,
}

fn build_main() -> Built {
    let mut b = B::new();
    let big: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    let v1 = b.vk("Str", 1, &utf16z("hello"));
    let v2 = b.vk("Dw", 4, &0x1122_3344u32.to_le_bytes());
    let v3 = b.vk("Big", 3, &big);
    let v4 = b.vk("Q", 11, &7u64.to_le_bytes());
    let mut multi = utf16z("one");
    multi.extend(utf16z("two"));
    multi.extend([0, 0]);
    let v5 = b.vk("Multi", 7, &multi);
    let v6 = b.vk("", 1, &utf16z("default!"));
    let vl = b.vlist(&[v1, v2, v3, v4, v5, v6]);
    let a = b.nk("A", 0, u32::MAX, 6, vl);
    let c1 = b.nk("C1", 0, u32::MAX, 0, u32::MAX);
    let c2 = b.nk("C2", 0, u32::MAX, 0, u32::MAX);
    let c3 = b.nk("C3", 0, u32::MAX, 0, u32::MAX);
    let li1 = b.list(b"li", &[c1, c2]);
    let li2 = b.list(b"lh", &[c3]);
    let ri = b.list(b"ri", &[li1, li2]);
    let bk = b.nk("B", 3, ri, 0, u32::MAX);
    // Deleted key "Gone" with one value, and a deleted value under A.
    let gv = b.vk("GoneVal", 1, &utf16z("bye"));
    let gvl = b.vlist(&[gv]);
    let gone = b.nk("Gone", 0, u32::MAX, 1, gvl);
    let old = b.vk("OldVal", 4, &5u32.to_le_bytes());
    let rl = b.list(b"lf", &[a, bk]);
    let root = b.nk("ROOT", 2, rl, 0, u32::MAX);
    b.patch_u32(gone, 16, root);
    for c in [gone, gvl, gv, old] {
        b.free(c);
    }
    Built {
        bytes: b.finish(root),
        big,
        a_offset: a,
    }
}

#[test]
fn regf_synthetic_values_big_data_and_ri_lists() {
    let built = build_main();
    let h = Hive::parse(&built.bytes).unwrap();
    assert!(h.base_block().checksum_ok());
    let a = h.key("a").unwrap();
    assert_eq!(a.offset, built.a_offset);
    assert_eq!(
        a.value("Str").unwrap().data,
        ValueData::String("hello".into())
    );
    let dw = a.value("dw").unwrap();
    assert!(dw.resident);
    assert_eq!(dw.data, ValueData::Dword(0x1122_3344));
    let big = a.value("Big").unwrap();
    assert_eq!(big.kind, ValueType::Binary);
    assert_eq!(big.raw, built.big);
    assert!(big.data_error.is_none());
    assert_eq!(a.value("Q").unwrap().data, ValueData::Qword(7));
    assert_eq!(
        a.value("Multi").unwrap().data,
        ValueData::MultiString(vec!["one".into(), "two".into()])
    );
    assert_eq!(
        a.value("").unwrap().as_string().as_deref(),
        Some("default!")
    );
    let names: Vec<String> = h
        .key("B")
        .unwrap()
        .subkeys()
        .into_iter()
        .map(|k| k.name)
        .collect();
    assert_eq!(names, vec!["C1", "C2", "C3"]);
    let paths: Vec<String> = h.keys().into_iter().map(|(p, _)| p).collect();
    assert_eq!(paths, vec!["", "A", "B", "B\\C1", "B\\C2", "B\\C3"]);
    assert!(h.key("ROOT\\B\\C3").is_some());
}

#[test]
fn regf_synthetic_deleted_recovery() {
    let h = Hive::parse(&build_main().bytes).unwrap();
    let d = h.recover_deleted();
    let gone = d
        .keys
        .iter()
        .find(|k| k.name == "Gone")
        .expect("deleted key");
    assert_eq!(gone.parent_path.as_deref(), Some(""));
    assert!(!gone.allocated);
    assert_eq!(gone.values.len(), 1);
    assert_eq!(gone.values[0].as_string().as_deref(), Some("bye"));
    let old = d
        .values
        .iter()
        .find(|v| v.value.name == "OldVal")
        .expect("deleted value");
    assert_eq!(old.value.data, ValueData::Dword(5));
    let gv = d.values.iter().find(|v| v.value.name == "GoneVal").unwrap();
    assert_eq!(gv.owner_key_offset, Some(gone.offset));
    // Generic events include the deleted key.
    let ev = events_from_hive(&h, HiveKind::Other, &Provenance::default());
    assert!(ev
        .iter()
        .any(|e| e.attrs.get("deleted") == Some(&serde_json::json!(true))
            && e.message.contains("Gone")));
}

#[test]
fn regf_synthetic_cycles_and_depth_limit() {
    // Root whose subkey list contains itself and a chain deeper than the depth cap.
    let mut b = B::new();
    let mut child = b.nk("leaf", 0, u32::MAX, 0, u32::MAX);
    for i in 0..600 {
        let l = b.list(b"li", &[child]);
        child = b.nk(&format!("k{i}"), 1, l, 0, u32::MAX);
    }
    let rl = b.list(b"li", &[child, 0]);
    let root = b.nk("R", 2, rl, 0, u32::MAX);
    // Patch the second entry to point to the root itself.
    let o = rl as usize + 4 + 4 + 4;
    b.region[o..o + 4].copy_from_slice(&root.to_le_bytes());
    let h = Hive::parse(&b.finish(root)).unwrap();
    let mut max_depth = 0;
    let n = h.walk(|_, d, _| max_depth = max_depth.max(d)).unwrap();
    assert_eq!(max_depth, 512);
    assert_eq!(n, 513);
    // ri list pointing to itself is rejected, not followed forever.
    let mut b = B::new();
    let ri = b.list(b"ri", &[0]);
    b.patch_u32(ri, 4, ri);
    let root = b.nk("R", 1, ri, 0, u32::MAX);
    let h = Hive::parse(&b.finish(root)).unwrap();
    assert!(h.root().unwrap().try_subkeys().is_err());
    assert!(h.root().unwrap().subkeys().is_empty());
}

/// Build a new-format log holding one HvLE entry with the given dirty pages.
fn build_log(base: &[u8], seq: u32, hbins_size: u32, pages: &[(u32, &[u8])]) -> Vec<u8> {
    let mut log = base[..512].to_vec();
    log[28..32].copy_from_slice(&6u32.to_le_bytes());
    let ck = base_block_checksum(&log).unwrap();
    log[508..512].copy_from_slice(&ck.to_le_bytes());
    let mut e = vec![0u8; 40];
    for (off, data) in pages {
        e.extend(off.to_le_bytes());
        e.extend((data.len() as u32).to_le_bytes());
    }
    for (_, data) in pages {
        e.extend(*data);
    }
    let size = e.len().div_ceil(512) * 512;
    e.resize(size, 0);
    e[0..4].copy_from_slice(b"HvLE");
    e[4..8].copy_from_slice(&(size as u32).to_le_bytes());
    e[12..16].copy_from_slice(&seq.to_le_bytes());
    e[16..20].copy_from_slice(&hbins_size.to_le_bytes());
    e[20..24].copy_from_slice(&(pages.len() as u32).to_le_bytes());
    let h1 = marvin32(&e[40..], MARVIN32_REGISTRY_SEED);
    e[24..32].copy_from_slice(&h1.to_le_bytes());
    let h2 = marvin32(&e[..32], MARVIN32_REGISTRY_SEED);
    e[32..40].copy_from_slice(&h2.to_le_bytes());
    log.extend(e);
    log
}

#[test]
fn regf_synthetic_transaction_log_replay() {
    let built = build_main();
    let clean = built.bytes.clone();
    // The "new" state: key A renamed to Z (same length) — the page that holds A's nk.
    let mut newer = clean.clone();
    let name_at = 4096 + built.a_offset as usize + 4 + 76;
    assert_eq!(newer[name_at], b'A');
    newer[name_at] = b'Z';
    let page_off = ((name_at - 4096) / 4096) * 4096;
    let page = newer[4096 + page_off..4096 + page_off + 4096].to_vec();
    let hbins = u32::from_le_bytes(clean[40..44].try_into().unwrap());
    // Dirty primary: sequence 5 != 4.
    let mut primary = clean.clone();
    primary[4..8].copy_from_slice(&5u32.to_le_bytes());
    let ck = base_block_checksum(&primary).unwrap();
    primary[508..512].copy_from_slice(&ck.to_le_bytes());
    let log = build_log(&primary, 4, hbins, &[(page_off as u32, &page)]);

    let plain = Hive::parse(&primary).unwrap();
    assert!(plain.key("A").is_some());
    assert!(plain.warnings.iter().any(|w| w.contains("dirty")));

    let h = Hive::parse_with_logs(&primary, &[&log]).unwrap();
    let rec = h.recovery.clone().unwrap();
    assert!(rec.was_dirty);
    assert_eq!(rec.applied_entries, 1);
    assert_eq!(rec.dirty_pages, 1);
    assert_eq!(rec.last_sequence, Some(4));
    assert!(h.key("Z").is_some());
    assert!(h.key("A").is_none());
    assert!(!h.base_block().is_dirty());

    // A corrupted entry hash stops replay.
    let mut bad = log.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0xFF;
    let h = Hive::parse_with_logs(&primary, &[&bad]).unwrap();
    assert_eq!(h.recovery.as_ref().unwrap().applied_entries, 0);
    assert!(h.key("A").is_some());

    // Old-format logs are reported as unsupported.
    let mut old = log.clone();
    old[28..32].copy_from_slice(&1u32.to_le_bytes());
    let ck = base_block_checksum(&old).unwrap();
    old[508..512].copy_from_slice(&ck.to_le_bytes());
    let h = Hive::parse_with_logs(&primary, &[&old]).unwrap();
    assert!(h
        .recovery
        .unwrap()
        .notes
        .iter()
        .any(|n| n.contains("not supported")));

    // Clean primary: logs are ignored.
    let h = Hive::parse_with_logs(&clean, &[&log]).unwrap();
    assert_eq!(h.recovery.as_ref().unwrap().applied_entries, 0);
    assert!(h.key("A").is_some());
}

#[test]
fn registry_bam_synthetic() {
    let mut b = B::new();
    let mut data = 0x01d5_0000_0000_0000u64.to_le_bytes().to_vec();
    data.extend([0u8; 16]);
    let v1 = b.vk(
        "\\Device\\HarddiskVolume2\\Windows\\System32\\notepad.exe",
        3,
        &data,
    );
    let v2 = b.vk("Version", 4, &1u32.to_le_bytes());
    let vl = b.vlist(&[v1, v2]);
    let sid = b.nk("S-1-5-21-1-2-3-1001", 0, u32::MAX, 2, vl);
    let l = b.list(b"lf", &[sid]);
    let us = b.nk("UserSettings", 1, l, 0, u32::MAX);
    let l = b.list(b"lf", &[us]);
    let st = b.nk("State", 1, l, 0, u32::MAX);
    let l = b.list(b"lf", &[st]);
    let bamk = b.nk("bam", 1, l, 0, u32::MAX);
    let l = b.list(b"lf", &[bamk]);
    let svcs = b.nk("Services", 1, l, 0, u32::MAX);
    let l = b.list(b"lf", &[svcs]);
    let cs = b.nk("ControlSet001", 1, l, 0, u32::MAX);
    let cur = b.vk("Current", 4, &1u32.to_le_bytes());
    let vl = b.vlist(&[cur]);
    let sel = b.nk("Select", 0, u32::MAX, 1, vl);
    let l = b.list(b"lf", &[cs, sel]);
    let root = b.nk("ROOT", 2, l, 0, u32::MAX);
    let h = Hive::parse(&b.finish(root)).unwrap();
    assert_eq!(HiveKind::detect(&h), HiveKind::System);
    let e = bam::entries(&h);
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].sid, "S-1-5-21-1-2-3-1001");
    assert_eq!(
        e[0].last_executed_ns,
        veritas_timeline::filetime_to_ns(0x01d5_0000_0000_0000)
    );
    let ev = events_from_hive(&h, HiveKind::System, &Provenance::default());
    let x = ev
        .iter()
        .find(|e| e.data_type == "windows:registry:bam")
        .unwrap();
    assert_eq!(x.attrs["key_path"], "HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Services\\bam\\State\\UserSettings\\S-1-5-21-1-2-3-1001");
}
