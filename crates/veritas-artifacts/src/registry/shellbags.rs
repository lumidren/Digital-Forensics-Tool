//! ShellBags (`windows:shellbags`).
//!
//! Roots:
//! - NTUSER: `Software\Microsoft\Windows\Shell\BagMRU`, `Software\Microsoft\Windows\ShellNoRoam\BagMRU`
//! - UsrClass: `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` (and the Wow6432Node twin)
//!
//! Each BagMRU key holds numbered values (one shell item each) ordered by `MRUListEx`, and a
//! subkey per value with the same number for the next path level. The walk reconstructs the
//! full folder path by joining decoded shell-item names. Shell items are decoded by
//! [`crate::shellitems::parse_shell_item_list`].
//!
//! One event per BagMRU entry: timestamp = last-written time of the entry's own subkey
//! (the entry with MRU position 0 also matches the parent key's last-written time). Shell item
//! timestamps (creation / modification / access) become additional events.
use super::{join, parse_mrulistex, Ctx};
use crate::regf::{Hive, Key};
use serde_json::json;
use veritas_timeline::{desc, Event};

pub const BAGMRU_ROOTS: &[&str] = &[
    "Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
    "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
];

/// Maximum number of BagMRU entries walked per hive.
pub const MAX_ENTRIES: usize = 200_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellBagEntry {
    /// Root-relative path of the BagMRU key holding the value.
    pub key_rel_path: String,
    pub key_offset: u32,
    pub value_name: String,
    pub mru_position: Option<usize>,
    /// Reconstructed folder path (names joined by `\`).
    pub path: String,
    pub item_name: String,
    pub item_types: Vec<String>,
    pub node_slot: Option<u32>,
    /// Last-written time of the entry's subkey (falls back to the BagMRU key).
    pub last_written_ns: Option<i64>,
    pub creation_ns: Option<i64>,
    pub modification_ns: Option<i64>,
    pub access_ns: Option<i64>,
    pub mft_entry: Option<u64>,
    pub raw_hex: String,
    pub decode_error: Option<String>,
}

fn decode(raw: &[u8]) -> (String, Vec<String>, Option<i64>, Option<i64>, Option<i64>, Option<u64>, Option<String>) {
    match crate::shellitems::parse_shell_item_list(raw) {
        Ok(items) => {
            let names: Vec<String> = items.iter().map(|i| i.long_name.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| i.name.clone())).filter(|n| !n.is_empty()).collect();
            let types: Vec<String> = items.iter().map(|i| i.item_type.clone()).collect();
            let last = items.last();
            (
                super::join_shell_path(&names),
                types,
                last.and_then(|i| i.creation_ns),
                last.and_then(|i| i.modification_ns),
                last.and_then(|i| i.access_ns),
                last.and_then(|i| i.mft_entry),
                None,
            )
        }
        Err(e) => (String::new(), vec![], None, None, None, None, Some(e.to_string())),
    }
}

fn walk(key: &Key<'_>, rel: &str, prefix: &str, depth: usize, out: &mut Vec<ShellBagEntry>) {
    if depth > crate::regf::MAX_KEY_DEPTH || out.len() >= MAX_ENTRIES {
        return;
    }
    let values = key.values();
    let mru: Vec<u32> = values.iter().find(|v| v.name.eq_ignore_ascii_case("MRUListEx")).map(|v| parse_mrulistex(&v.raw)).unwrap_or_default();
    let mut numbered: Vec<(u32, &crate::regf::Value)> = values.iter().filter_map(|v| v.name.parse::<u32>().ok().map(|n| (n, v))).collect();
    numbered.sort_by_key(|(n, _)| *n);
    // Order: MRUListEx order first, then any numbered value missing from the list.
    let mut order: Vec<u32> = Vec::new();
    for n in &mru {
        if numbered.iter().any(|(m, _)| m == n) && !order.contains(n) {
            order.push(*n);
        }
    }
    for (n, _) in &numbered {
        if !order.contains(n) {
            order.push(*n);
        }
    }
    let subkeys = key.subkeys();
    for n in order {
        if out.len() >= MAX_ENTRIES {
            return;
        }
        let Some((_, v)) = numbered.iter().find(|(m, _)| *m == n) else { continue };
        let (name, types, c, m, a, mft, err) = decode(&v.raw);
        let item_name = if name.is_empty() { format!("<unknown shell item {}>", n) } else { name };
        let path = super::join_shell_path(&[prefix, item_name.as_str()]);
        let child = subkeys.iter().find(|s| s.name == n.to_string());
        let node_slot = child.and_then(|c| c.value_u32("NodeSlot"));
        out.push(ShellBagEntry {
            key_rel_path: rel.to_string(),
            key_offset: key.offset,
            value_name: v.name.clone(),
            mru_position: mru.iter().position(|x| *x == n),
            path: path.clone(),
            item_name,
            item_types: types,
            node_slot,
            last_written_ns: child.and_then(|c| c.last_written_ns).or(key.last_written_ns),
            creation_ns: c,
            modification_ns: m,
            access_ns: a,
            mft_entry: mft,
            raw_hex: hex::encode(&v.raw),
            decode_error: err,
        });
        if let Some(ch) = child {
            walk(ch, &join(rel, &ch.name), &path, depth + 1, out);
        }
    }
}

pub fn entries(hive: &Hive) -> Vec<ShellBagEntry> {
    let mut out = Vec::new();
    for root in BAGMRU_ROOTS {
        if let Some(k) = hive.key(root) {
            walk(&k, root, "", 0, &mut out);
        }
    }
    out
}

pub fn events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    let mut out = Vec::new();
    for e in entries(hive) {
        let base = |d: &str, ts: Option<i64>| {
            let mut ev = ctx
                .event("shellbags", "windows:shellbags", d, ts, format!("Shell bag: {} [{}\\{}]", e.path, ctx.full_path(&e.key_rel_path), e.value_name), &e.key_rel_path, e.key_offset)
                .attr("path", e.path.clone())
                .attr("value_name", e.value_name.clone())
                .attr("item_types", json!(e.item_types))
                .attr("raw_item_hex", e.raw_hex.clone());
            if let Some(p) = e.mru_position {
                ev = ev.attr("mru_position", p as u64);
            }
            if let Some(s) = e.node_slot {
                ev = ev.attr("node_slot", s);
            }
            if let Some(m) = e.mft_entry {
                ev = ev.attr("mft_entry", m);
            }
            if let Some(err) = &e.decode_error {
                ev = ev.attr("decode_error", err.clone());
            }
            ev
        };
        out.push(base(desc::WRITTEN, e.last_written_ns));
        if e.creation_ns.is_some() {
            out.push(base(desc::CREATION, e.creation_ns));
        }
        if e.modification_ns.is_some() {
            out.push(base(desc::MODIFICATION, e.modification_ns));
        }
        if e.access_ns.is_some() {
            out.push(base(desc::ACCESS, e.access_ns));
        }
    }
    out
}
