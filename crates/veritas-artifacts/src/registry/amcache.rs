//! Amcache.hve (`windows:registry:amcache`, `windows:registry:amcache:programs`).
//!
//! Old layout (Windows 7 with KB2952664 / Windows 8.x / early 10):
//! - `Root\File\{volume GUID}\{file reference}` with hex-named values: `0` product name,
//!   `1` company, `5` file version, `6` size, `c` description, `f` link time (Unix),
//!   `11` last modified, `12` created, `15` full path, `17` last modified (store),
//!   `100` program id, `101` SHA-1 (with 4 leading zeros).
//! - `Root\Programs\{program id}`: `0` name, `1` version, `2` publisher, `a` install time
//!   (Unix seconds), `b` uninstall time.
//!
//! New layout (Windows 10 1709+): `Root\InventoryApplicationFile`, `InventoryApplication`,
//! `InventoryDriverBinary`, `InventoryApplicationShortcut`. The key last-written time is the
//! primary event time; LinkDate / InstallDate / DriverTimeStamp produce additional events.
use super::{join, Ctx};
use crate::regf::{Hive, Key};
use chrono::{NaiveDateTime, TimeZone, Utc};
use std::collections::BTreeMap;
use veritas_timeline::{desc, filetime_to_ns, unix_secs_to_ns, Event};

pub const LINK_TIME: &str = "Link Time";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmcacheRecord {
    pub data_type: &'static str,
    /// `file`, `program`, `inventory_application_file`, `inventory_application`,
    /// `inventory_driver_binary`, `inventory_application_shortcut`.
    pub source: &'static str,
    pub key_rel_path: String,
    pub key_offset: u32,
    pub last_written_ns: Option<i64>,
    pub fields: BTreeMap<String, String>,
    /// Additional (timestamp_desc, ns) pairs.
    pub times: Vec<(&'static str, i64)>,
}

/// Parse `MM/DD/YYYY HH:MM:SS` (UTC) as written by the inventory providers.
pub fn parse_amcache_date(s: &str) -> Option<i64> {
    let dt = NaiveDateTime::parse_from_str(s.trim(), "%m/%d/%Y %H:%M:%S").ok()?;
    Utc.from_utc_datetime(&dt).timestamp_nanos_opt()
}

/// FileId / `101` values are `0000` + SHA-1.
pub fn strip_sha1(s: &str) -> String {
    if s.len() == 44 && s.starts_with("0000") {
        s[4..].to_lowercase()
    } else {
        s.to_lowercase()
    }
}

fn str_fields(k: &Key<'_>, map: &[(&str, &str)]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (vname, field) in map {
        if let Some(v) = k.value(vname) {
            let s = match v.kind {
                crate::regf::ValueType::Qword | crate::regf::ValueType::Dword => v.as_u64().map(|n| n.to_string()).unwrap_or_default(),
                _ => v.as_string().unwrap_or_default(),
            };
            if !s.is_empty() {
                out.insert(field.to_string(), s);
            }
        }
    }
    out
}

fn record(data_type: &'static str, source: &'static str, rel: String, k: &Key<'_>, fields: BTreeMap<String, String>) -> AmcacheRecord {
    AmcacheRecord { data_type, source, key_rel_path: rel, key_offset: k.offset, last_written_ns: k.last_written_ns, fields, times: vec![] }
}

pub fn records(hive: &Hive) -> Vec<AmcacheRecord> {
    let mut out = Vec::new();
    // Old layout: files.
    if let Some(files) = hive.key("Root\\File") {
        for vol in files.subkeys() {
            for f in vol.subkeys() {
                let mut fields = str_fields(&f, &[("15", "full_path"), ("0", "product_name"), ("1", "company_name"), ("5", "file_version"), ("c", "file_description"), ("100", "program_id"), ("6", "file_size")]);
                if let Some(h) = f.value_string("101") {
                    fields.insert("sha1".into(), strip_sha1(&h));
                }
                fields.insert("volume_guid".into(), vol.name.clone());
                fields.insert("file_reference".into(), f.name.clone());
                let rel = join(&join("Root\\File", &vol.name), &f.name);
                let mut r = record("windows:registry:amcache", "file", rel, &f, fields);
                for (vn, d) in [("17", desc::MODIFICATION), ("11", desc::METADATA_MODIFICATION), ("12", desc::CREATION)] {
                    if let Some(t) = f.value_u64(vn).and_then(filetime_to_ns) {
                        r.times.push((d, t));
                    }
                }
                if let Some(t) = f.value_u32("f").filter(|&t| t != 0).and_then(|t| unix_secs_to_ns(t as i64)) {
                    r.times.push((LINK_TIME, t));
                }
                out.push(r);
            }
        }
    }
    // Old layout: programs.
    if let Some(progs) = hive.key("Root\\Programs") {
        for p in progs.subkeys() {
            let fields = str_fields(&p, &[("0", "name"), ("1", "version"), ("2", "publisher"), ("6", "entry_type"), ("f", "product_code")]);
            let mut r = record("windows:registry:amcache:programs", "program", join("Root\\Programs", &p.name), &p, fields);
            if let Some(t) = p.value_u64("a").filter(|&t| t != 0).and_then(|t| unix_secs_to_ns(t as i64)) {
                r.times.push((desc::INSTALLATION, t));
            }
            if let Some(t) = p.value_u64("b").filter(|&t| t != 0).and_then(|t| unix_secs_to_ns(t as i64)) {
                r.times.push(("Uninstall Time", t));
            }
            out.push(r);
        }
    }
    // New layout.
    if let Some(k) = hive.key("Root\\InventoryApplicationFile") {
        for f in k.subkeys() {
            let mut fields = str_fields(
                &f,
                &[
                    ("LowerCaseLongPath", "full_path"),
                    ("Name", "name"),
                    ("ProductName", "product_name"),
                    ("ProductVersion", "product_version"),
                    ("Publisher", "publisher"),
                    ("Size", "file_size"),
                    ("BinFileVersion", "bin_file_version"),
                    ("BinaryType", "binary_type"),
                    ("ProgramId", "program_id"),
                    ("LinkDate", "link_date"),
                    ("Version", "version"),
                ],
            );
            if let Some(h) = f.value_string("FileId") {
                fields.insert("sha1".into(), strip_sha1(&h));
            }
            if let Some(s) = fields.get("file_size").cloned() {
                if let Some(hex) = s.strip_prefix("0x") {
                    if let Ok(n) = u64::from_str_radix(hex, 16) {
                        fields.insert("file_size".into(), n.to_string());
                    }
                }
            }
            let mut r = record("windows:registry:amcache", "inventory_application_file", join("Root\\InventoryApplicationFile", &f.name), &f, fields);
            if let Some(t) = r.fields.get("link_date").and_then(|s| parse_amcache_date(s)) {
                r.times.push((LINK_TIME, t));
            }
            out.push(r);
        }
    }
    if let Some(k) = hive.key("Root\\InventoryApplication") {
        for a in k.subkeys() {
            let fields = str_fields(
                &a,
                &[("Name", "name"), ("Version", "version"), ("Publisher", "publisher"), ("InstallDate", "install_date"), ("RootDirPath", "root_dir_path"), ("Source", "source"), ("ProgramId", "program_id"), ("UninstallString", "uninstall_string"), ("PackageFullName", "package_full_name")],
            );
            let mut r = record("windows:registry:amcache:programs", "inventory_application", join("Root\\InventoryApplication", &a.name), &a, fields);
            if let Some(t) = r.fields.get("install_date").and_then(|s| parse_amcache_date(s)) {
                r.times.push((desc::INSTALLATION, t));
            }
            out.push(r);
        }
    }
    if let Some(k) = hive.key("Root\\InventoryDriverBinary") {
        for d in k.subkeys() {
            let fields = str_fields(
                &d,
                &[("DriverName", "driver_name"), ("Product", "product_name"), ("ProductVersion", "product_version"), ("DriverCompany", "publisher"), ("DriverVersion", "version"), ("Service", "service"), ("Inf", "inf"), ("DriverId", "driver_id"), ("ImageSize", "image_size")],
            );
            let mut fields = fields;
            fields.insert("full_path".into(), d.name.clone());
            let mut r = record("windows:registry:amcache", "inventory_driver_binary", join("Root\\InventoryDriverBinary", &d.name), &d, fields);
            if let Some(t) = d.value_u32("DriverTimeStamp").filter(|&t| t != 0).and_then(|t| unix_secs_to_ns(t as i64)) {
                r.times.push((LINK_TIME, t));
            }
            out.push(r);
        }
    }
    if let Some(k) = hive.key("Root\\InventoryApplicationShortcut") {
        for s in k.subkeys() {
            let mut fields = str_fields(&s, &[("ShortcutPath", "shortcut_path"), ("ShortcutTargetPath", "target_path"), ("ShortcutAumid", "aumid"), ("ShortcutProgramId", "program_id")]);
            if !fields.contains_key("shortcut_path") {
                fields.insert("shortcut_path".into(), s.name.clone());
            }
            out.push(record("windows:registry:amcache", "inventory_application_shortcut", join("Root\\InventoryApplicationShortcut", &s.name), &s, fields));
        }
    }
    out
}

pub fn events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    let mut out = Vec::new();
    for r in records(hive) {
        let label = r.fields.get("full_path").or(r.fields.get("name")).or(r.fields.get("shortcut_path")).cloned().unwrap_or_else(|| r.key_rel_path.clone());
        let mk = |d: &str, ts: Option<i64>| {
            let mut e = ctx.event("amcache", r.data_type, d, ts, format!("[{}] {}", r.source, label), &r.key_rel_path, r.key_offset).attr("source", r.source);
            for (k, v) in &r.fields {
                e = e.attr(k, v.clone());
            }
            e
        };
        out.push(mk(desc::WRITTEN, r.last_written_ns));
        for (d, t) in &r.times {
            out.push(mk(d, Some(*t)));
        }
    }
    out
}
