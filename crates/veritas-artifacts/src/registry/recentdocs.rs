//! MRU lists in NTUSER.DAT.
//!
//! - `windows:registry:mrulistex`: `Explorer\RecentDocs` (and per-extension subkeys),
//!   `ComDlg32\OpenSavePidlMRU\*`, `ComDlg32\LastVisitedPidlMRU`, `ComDlg32\CIDSizeMRU`,
//!   `Explorer\WordWheelQuery`.
//! - `windows:registry:mrulist`: `Explorer\RunMRU`, `ComDlg32\OpenSaveMRU\*` (XP),
//!   `ComDlg32\LastVisitedMRU` (XP).
//! - `windows:registry:typedurls`: `Internet Explorer\TypedURLs`, `Explorer\TypedPaths`.
//!
//! One event per key, timestamped with the key's last-written time (which is the time the
//! entry at MRU position 0 was recorded), entries listed in MRU order. Plaso convention.
use super::{join, parse_mrulist, parse_mrulistex, split_utf16z, Ctx};
use crate::regf::{Hive, Key, Value};
use serde_json::json;
use veritas_timeline::{desc, Event};

const EXPLORER: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryFormat {
    /// UTF-16 string (NUL terminated) possibly followed by a shell item; string only.
    Utf16,
    /// Shell item list.
    ShellItemList,
    /// UTF-16 program name, NUL, then a shell item list.
    Utf16ThenShellItemList,
    /// UTF-16 program name, NUL, UTF-16 path (XP LastVisitedMRU).
    Utf16Pair,
    /// REG_SZ value (RunMRU strips the trailing `\1`).
    String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MruEntry {
    pub index: usize,
    pub value_name: String,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MruList {
    pub data_type: &'static str,
    pub key_rel_path: String,
    pub key_offset: u32,
    pub last_written_ns: Option<i64>,
    pub entries: Vec<MruEntry>,
}

fn shell_path(raw: &[u8]) -> String {
    match crate::shellitems::parse_shell_item_list(raw) {
        Ok(items) => super::join_shell_path(&items.iter().map(|i| i.long_name.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| i.name.clone())).collect::<Vec<_>>()),
        Err(_) => format!("<shell item list: {} bytes>", raw.len()),
    }
}

fn decode(v: &Value, f: EntryFormat) -> String {
    match f {
        EntryFormat::Utf16 => split_utf16z(&v.raw).0,
        EntryFormat::ShellItemList => shell_path(&v.raw),
        EntryFormat::Utf16ThenShellItemList => {
            let (name, rest) = split_utf16z(&v.raw);
            format!("{name} {}", shell_path(rest)).trim_end().to_string()
        }
        EntryFormat::Utf16Pair => {
            let (a, rest) = split_utf16z(&v.raw);
            let (b, _) = split_utf16z(rest);
            if b.is_empty() { a } else { format!("{a} {b}") }
        }
        EntryFormat::String => {
            let s = v.as_string().unwrap_or_default();
            s.strip_suffix("\\1").map(str::to_string).unwrap_or(s)
        }
    }
}

/// Decode an MRUListEx key.
pub fn mrulistex(key: &Key<'_>, rel: &str, f: EntryFormat) -> Option<MruList> {
    let values = key.values();
    let order = parse_mrulistex(&values.iter().find(|v| v.name.eq_ignore_ascii_case("MRUListEx"))?.raw);
    let mut entries = Vec::new();
    for (i, n) in order.iter().enumerate() {
        let name = n.to_string();
        let data = match values.iter().find(|v| v.name == name) {
            Some(v) => decode(v, f),
            None => "<missing value>".to_string(),
        };
        entries.push(MruEntry { index: i, value_name: name, data });
    }
    Some(MruList { data_type: "windows:registry:mrulistex", key_rel_path: rel.into(), key_offset: key.offset, last_written_ns: key.last_written_ns, entries })
}

/// Decode an MRUList key.
pub fn mrulist(key: &Key<'_>, rel: &str, f: EntryFormat) -> Option<MruList> {
    let values = key.values();
    let order = parse_mrulist(&values.iter().find(|v| v.name.eq_ignore_ascii_case("MRUList"))?.as_string()?);
    let mut entries = Vec::new();
    for (i, n) in order.iter().enumerate() {
        let data = match values.iter().find(|v| &v.name == n) {
            Some(v) => decode(v, f),
            None => "<missing value>".to_string(),
        };
        entries.push(MruEntry { index: i, value_name: n.clone(), data });
    }
    Some(MruList { data_type: "windows:registry:mrulist", key_rel_path: rel.into(), key_offset: key.offset, last_written_ns: key.last_written_ns, entries })
}

/// TypedURLs / TypedPaths: `url1`, `url2`, ... in numeric order.
pub fn typed(key: &Key<'_>, rel: &str) -> MruList {
    let mut vals: Vec<(u32, Value)> = key
        .values()
        .into_iter()
        .filter_map(|v| v.name.to_ascii_lowercase().strip_prefix("url").and_then(|n| n.parse::<u32>().ok()).map(|n| (n, v)))
        .collect();
    vals.sort_by_key(|(n, _)| *n);
    let entries = vals.into_iter().enumerate().map(|(i, (_, v))| MruEntry { index: i, data: v.as_string().unwrap_or_default(), value_name: v.name }).collect();
    MruList { data_type: "windows:registry:typedurls", key_rel_path: rel.into(), key_offset: key.offset, last_written_ns: key.last_written_ns, entries }
}

pub fn lists(hive: &Hive) -> Vec<MruList> {
    let mut out = Vec::new();
    let ex = |rel: String, f: EntryFormat, out: &mut Vec<MruList>| {
        if let Some(k) = hive.key(&rel) {
            out.extend(mrulistex(&k, &rel, f));
            for s in k.subkeys() {
                out.extend(mrulistex(&s, &join(&rel, &s.name), f));
            }
        }
    };
    ex(format!("{EXPLORER}\\RecentDocs"), EntryFormat::Utf16, &mut out);
    ex(format!("{EXPLORER}\\ComDlg32\\OpenSavePidlMRU"), EntryFormat::ShellItemList, &mut out);
    ex(format!("{EXPLORER}\\ComDlg32\\LastVisitedPidlMRU"), EntryFormat::Utf16ThenShellItemList, &mut out);
    ex(format!("{EXPLORER}\\ComDlg32\\LastVisitedPidlMRULegacy"), EntryFormat::Utf16ThenShellItemList, &mut out);
    ex(format!("{EXPLORER}\\ComDlg32\\CIDSizeMRU"), EntryFormat::Utf16, &mut out);
    ex(format!("{EXPLORER}\\WordWheelQuery"), EntryFormat::Utf16, &mut out);
    let l = |rel: String, f: EntryFormat, sub: bool, out: &mut Vec<MruList>| {
        if let Some(k) = hive.key(&rel) {
            out.extend(mrulist(&k, &rel, f));
            if sub {
                for s in k.subkeys() {
                    out.extend(mrulist(&s, &join(&rel, &s.name), f));
                }
            }
        }
    };
    l(format!("{EXPLORER}\\RunMRU"), EntryFormat::String, false, &mut out);
    l(format!("{EXPLORER}\\ComDlg32\\OpenSaveMRU"), EntryFormat::String, true, &mut out);
    l(format!("{EXPLORER}\\ComDlg32\\LastVisitedMRU"), EntryFormat::Utf16Pair, false, &mut out);
    for rel in ["Software\\Microsoft\\Internet Explorer\\TypedURLs".to_string(), format!("{EXPLORER}\\TypedPaths")] {
        if let Some(k) = hive.key(&rel) {
            out.push(typed(&k, &rel));
        }
    }
    out
}

pub fn events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    lists(hive)
        .into_iter()
        .filter(|l| !l.entries.is_empty())
        .map(|l| {
            let parts: Vec<String> = l.entries.iter().map(|e| format!("Index: {} [MRU Value {}]: {}", e.index + 1, e.value_name, e.data)).collect();
            let msg = format!("[{}] {}", ctx.full_path(&l.key_rel_path), parts.join(" "));
            let entries: Vec<serde_json::Value> = l.entries.iter().map(|e| json!({"index": e.index, "value_name": e.value_name, "data": e.data})).collect();
            let parser = match l.data_type {
                "windows:registry:typedurls" => "typedurls",
                "windows:registry:mrulist" => "mrulist",
                _ => "mrulistex",
            };
            ctx.event(parser, l.data_type, desc::WRITTEN, l.last_written_ns, msg, &l.key_rel_path, l.key_offset).attr("entries", serde_json::Value::Array(entries))
        })
        .collect()
}
