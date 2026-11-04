//! Registry-derived timeline artifacts.
//!
//! [`events_from_hive`] dispatches every plugin that applies to a hive kind and adds one
//! generic `windows:registry:key_value` event per key (Plaso's default registry event), so the
//! timeline holds every key's last-written time even where no specific plugin applies.
//! Data type names follow Plaso where Plaso has one.
use crate::regf::{Hive, Key, Value};
use serde_json::{json, Value as Json};
use veritas_timeline::{desc, Event};

pub mod amcache;
pub mod autoruns;
pub mod bam;
pub mod network;
pub mod recentdocs;
pub mod services;
pub mod shellbags;
pub mod shimcache;
pub mod sysinfo;
pub mod usb;
pub mod userassist;

/// Total byte budget for `attrs.values` on generic key events.
pub const KEY_VALUES_BUDGET: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HiveKind {
    System,
    Software,
    Sam,
    Security,
    NtUser,
    UsrClass,
    Amcache,
    Other,
}

impl HiveKind {
    /// Guess the kind from a file name (`SYSTEM`, `NTUSER.DAT`, `UsrClass.dat`, `Amcache.hve`).
    pub fn from_file_name(name: &str) -> Option<HiveKind> {
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name).to_ascii_lowercase();
        let k = match base.as_str() {
            "system" => HiveKind::System,
            "software" => HiveKind::Software,
            "sam" => HiveKind::Sam,
            "security" => HiveKind::Security,
            "usrclass.dat" => HiveKind::UsrClass,
            "amcache.hve" => HiveKind::Amcache,
            b if b.starts_with("ntuser") && b.ends_with(".dat") => HiveKind::NtUser,
            b if b.ends_with("amcache.hve") => HiveKind::Amcache,
            _ => return None,
        };
        Some(k)
    }

    /// Guess the kind from the hive's content.
    pub fn detect(hive: &Hive) -> HiveKind {
        let has = |p: &str| hive.key(p).is_some();
        if has("Select") && (has("ControlSet001") || has("ControlSet002")) {
            HiveKind::System
        } else if has("Microsoft\\Windows NT\\CurrentVersion") {
            HiveKind::Software
        } else if has("Root\\InventoryApplicationFile") || has("Root\\File") || has("Root\\Programs") {
            HiveKind::Amcache
        } else if has("SAM\\Domains") {
            HiveKind::Sam
        } else if has("Policy\\Secrets") || has("Policy\\PolAdtEv") {
            HiveKind::Security
        } else if has("Local Settings\\Software\\Microsoft\\Windows\\Shell") || (has("CLSID") && !has("Software")) {
            HiveKind::UsrClass
        } else if has("Software\\Microsoft") && (has("Control Panel") || has("Environment") || has("Console")) {
            HiveKind::NtUser
        } else {
            HiveKind::Other
        }
    }

    /// Mount point used to build full key paths in events.
    pub fn mount_point(&self) -> &'static str {
        match self {
            HiveKind::System => "HKEY_LOCAL_MACHINE\\System",
            HiveKind::Software => "HKEY_LOCAL_MACHINE\\Software",
            HiveKind::Sam => "HKEY_LOCAL_MACHINE\\SAM",
            HiveKind::Security => "HKEY_LOCAL_MACHINE\\Security",
            HiveKind::NtUser => "HKEY_CURRENT_USER",
            HiveKind::UsrClass => "HKEY_CURRENT_USER\\Software\\Classes",
            HiveKind::Amcache => "",
            HiveKind::Other => "",
        }
    }
}

/// Where the hive came from; copied into every event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Provenance {
    pub evidence_sha256: String,
    pub evidence_path: String,
    pub host: Option<String>,
    pub user: Option<String>,
}

/// Shared event-building context for plugins.
pub struct Ctx<'a> {
    pub prov: &'a Provenance,
    pub kind: HiveKind,
}

impl Ctx<'_> {
    /// Full key path for a root-relative path.
    pub fn full_path(&self, rel: &str) -> String {
        let mp = self.kind.mount_point();
        match (mp.is_empty(), rel.is_empty()) {
            (true, _) => rel.to_string(),
            (false, true) => mp.to_string(),
            (false, false) => format!("{mp}\\{rel}"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn event(&self, parser: &str, data_type: &str, ts_desc: &str, ts: Option<i64>, message: String, rel_key_path: &str, offset: u32) -> Event {
        let mut e = Event::new(data_type, ts_desc, message)
            .with_time(ts)
            .provenance(&self.prov.evidence_sha256, &self.prov.evidence_path, offset as i64, &format!("winreg/{parser}"), crate::PARSER_VERSION)
            .attr("key_path", self.full_path(rel_key_path));
        e.source_short = "REG".into();
        e.source_long = "Registry Key".into();
        e.host = self.prov.host.clone();
        e.user = self.prov.user.clone();
        e
    }
}

/// `MRUListEx`: little-endian u32 indexes terminated by 0xFFFFFFFF.
pub fn parse_mrulistex(raw: &[u8]) -> Vec<u32> {
    raw.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).take_while(|&v| v != 0xFFFF_FFFF).take(65536).collect()
}

/// `MRUList`: UTF-16 string of value-name letters.
pub fn parse_mrulist(s: &str) -> Vec<String> {
    s.chars().filter(|c| !c.is_control()).map(|c| c.to_string()).collect()
}

/// Split UTF-16LE bytes at the first NUL code unit: (string, bytes after the terminator).
pub fn split_utf16z(raw: &[u8]) -> (String, &[u8]) {
    let mut i = 0;
    while i + 1 < raw.len() {
        if raw[i] == 0 && raw[i + 1] == 0 {
            return (crate::util::utf16le(&raw[..i], false), &raw[i + 2..]);
        }
        i += 2;
    }
    (crate::util::utf16le(raw, false), &[])
}

/// Resolve `CurrentControlSet` via `Select\Current`, falling back to the first control set.
pub fn current_control_set(hive: &Hive) -> Option<String> {
    if let Some(cur) = hive.key("Select").and_then(|k| k.value_u32("Current")) {
        let name = format!("ControlSet{cur:03}");
        if hive.key(&name).is_some() {
            return Some(name);
        }
    }
    (1..=9).map(|i| format!("ControlSet{i:03}")).find(|n| hive.key(n).is_some())
}

/// Join a path with a child name.
pub fn join(a: &str, b: &str) -> String {
    if a.is_empty() {
        b.to_string()
    } else {
        format!("{a}\\{b}")
    }
}

/// Join shell-item names into a path without doubling separators (volume names end in `\`).
pub fn join_shell_path<S: AsRef<str>>(parts: &[S]) -> String {
    let mut out = String::new();
    for p in parts {
        let p = p.as_ref();
        if p.is_empty() {
            continue;
        }
        if !out.is_empty() && !out.ends_with('\\') {
            out.push('\\');
        }
        out.push_str(p);
    }
    out
}

/// Plaso-style one-line rendering of a value: `name: [TYPE] data`.
pub fn render_value(v: &Value) -> String {
    let name = if v.name.is_empty() { "(default)" } else { v.name.as_str() };
    let mut s = v.display_string();
    if s.chars().count() > 512 {
        s = s.chars().take(512).collect::<String>() + "...";
    }
    format!("{name}: [{}] {s}", v.kind.name())
}

/// One `windows:registry:key_value` event for a key.
pub fn key_value_event(ctx: &Ctx<'_>, rel: &str, k: &Key<'_>, deleted: bool) -> Event {
    let mut vals: Vec<String> = k.values().iter().map(render_value).collect();
    vals.sort();
    let mut budget = KEY_VALUES_BUDGET;
    let mut kept: Vec<Json> = Vec::new();
    let mut truncated = false;
    for v in vals {
        if v.len() > budget {
            truncated = true;
            break;
        }
        budget -= v.len();
        kept.push(Json::String(v));
    }
    let msg = if kept.is_empty() {
        format!("[{}] (no values)", ctx.full_path(rel))
    } else {
        let joined: Vec<&str> = kept.iter().filter_map(|j| j.as_str()).take(8).collect();
        format!("[{}] {}{}", ctx.full_path(rel), joined.join(" "), if kept.len() > 8 { " ..." } else { "" })
    };
    let mut e = ctx
        .event("winreg_default", "windows:registry:key_value", desc::WRITTEN, k.last_written_ns, msg, rel, k.offset)
        .attr("values", Json::Array(kept))
        .attr("number_of_values", k.value_count)
        .attr("number_of_subkeys", k.subkey_count);
    if truncated {
        e = e.attr("values_truncated", true);
    }
    if let Some(c) = &k.class_name {
        e = e.attr("class_name", c.clone());
    }
    if deleted {
        e = e.attr("deleted", true);
    }
    e
}

/// Generic per-key events for every reachable key plus recovered deleted keys.
pub fn generic_events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    let mut out = Vec::new();
    let _ = hive.walk(|p, _, k| out.push(key_value_event(ctx, p, k, false)));
    for d in hive.deleted_keys() {
        let rel = match &d.parent_path {
            Some(pp) => join(pp, &d.name),
            None => format!("<orphan:{:#x}>\\{}", d.parent_offset, d.name),
        };
        let mut vals: Vec<String> = d.values.iter().map(render_value).collect();
        vals.sort();
        vals.truncate(64);
        let e = ctx
            .event("winreg_default", "windows:registry:key_value", desc::WRITTEN, d.last_written_ns, format!("[{}] (deleted key)", ctx.full_path(&rel)), &rel, d.offset)
            .attr("values", json!(vals))
            .attr("deleted", true)
            .attr("cell_allocated", d.allocated);
        out.push(e);
    }
    out
}

/// All events for a hive: specific plugins for its kind plus generic key events.
pub fn events_from_hive(hive: &Hive, hive_kind: HiveKind, provenance: &Provenance) -> Vec<Event> {
    let ctx = Ctx { prov: provenance, kind: hive_kind };
    let mut out = Vec::new();
    match hive_kind {
        HiveKind::System => {
            out.extend(services::events(hive, &ctx));
            out.extend(shimcache::events(hive, &ctx));
            out.extend(usb::system_events(hive, &ctx));
            out.extend(bam::events(hive, &ctx));
            out.extend(network::interface_events(hive, &ctx));
            out.extend(sysinfo::system_events(hive, &ctx));
            out.extend(autoruns::events(hive, &ctx));
        }
        HiveKind::Software => {
            out.extend(sysinfo::software_events(hive, &ctx));
            out.extend(network::profile_events(hive, &ctx));
            out.extend(autoruns::events(hive, &ctx));
            out.extend(usb::software_events(hive, &ctx));
        }
        HiveKind::NtUser => {
            out.extend(userassist::events(hive, &ctx));
            out.extend(shellbags::events(hive, &ctx));
            out.extend(recentdocs::events(hive, &ctx));
            out.extend(autoruns::events(hive, &ctx));
            out.extend(usb::ntuser_events(hive, &ctx));
        }
        HiveKind::UsrClass => out.extend(shellbags::events(hive, &ctx)),
        HiveKind::Amcache => out.extend(amcache::events(hive, &ctx)),
        HiveKind::Sam | HiveKind::Security | HiveKind::Other => {}
    }
    out.extend(generic_events(hive, &ctx));
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_mrulistex_and_split() {
        assert_eq!(parse_mrulistex(&hex::decode("0100000000000000ffffffff02000000").unwrap()), vec![1, 0]);
        let raw = hex::decode("680069000000aabb").unwrap();
        let (s, rest) = split_utf16z(&raw);
        assert_eq!(s, "hi");
        assert_eq!(rest, &[0xaa, 0xbb]);
        assert_eq!(HiveKind::from_file_name("C:\\x\\NTUSER.DAT"), Some(HiveKind::NtUser));
        assert_eq!(HiveKind::from_file_name("UsrClass.dat"), Some(HiveKind::UsrClass));
        assert_eq!(join_shell_path(&["My Computer", "C:\\", "Users"]), "My Computer\\C:\\Users");
    }
}
