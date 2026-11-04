//! Windows jump lists: AutomaticDestinations (OLECF with LNK streams and a DestList stream)
//! and CustomDestinations (concatenated LNK blobs grouped in categories).
use crate::error::{ParseError, Result};
use crate::lnk::{self, LnkFile, LNK_CLSID};
use crate::olecf::Olecf;
use crate::shellitems::{decode_ansi, guid_string};
use crate::util::{need, u16_at, u32_at, u64_at, utf16le};
use serde::Serialize;
use serde_json::json;
use veritas_timeline::{desc, filetime_to_ns, Event};

const MAX_DESTLIST_ENTRIES: usize = 100_000;
const MAX_CUSTOM_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Serialize)]
pub struct DestListEntry {
    pub offset: usize,
    pub entry_number: u32,
    pub hostname: String,
    pub path: String,
    pub last_modification_ns: Option<i64>,
    pub last_modification_filetime: u64,
    pub pin_status: i32,
    pub access_count: Option<u32>,
    pub droid_volume_identifier: Option<String>,
    pub droid_file_identifier: Option<String>,
    pub birth_droid_volume_identifier: Option<String>,
    pub birth_droid_file_identifier: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DestList {
    pub version: u32,
    pub number_of_entries: u32,
    pub number_of_pinned_entries: u32,
    pub last_entry_number: u32,
    pub last_revision_number: u64,
    pub entries: Vec<DestListEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutoStream {
    pub name: String,
    pub size: usize,
    pub lnk: Option<LnkFile>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutomaticDestinations {
    pub dest_list: Option<DestList>,
    pub streams: Vec<AutoStream>,
}

fn nonzero_guid(b: &[u8]) -> Option<String> {
    guid_string(b).filter(|g| g != "00000000-0000-0000-0000-000000000000")
}

pub fn parse_dest_list(d: &[u8]) -> Result<DestList> {
    let version = u32_at(d, 0)?;
    let n = u32_at(d, 4)?;
    let mut dl = DestList {
        version,
        number_of_entries: n,
        number_of_pinned_entries: u32_at(d, 8)?,
        last_entry_number: u32_at(d, 16)?,
        last_revision_number: u64_at(d, 24)?,
        entries: Vec::new(),
    };
    let mut off = 32usize;
    let v1 = version < 2;
    while dl.entries.len() < (n as usize).min(MAX_DESTLIST_ENTRIES) && off < d.len() {
        let path_off = if v1 { 112 } else { 128 };
        let plen = u16_at(d, off + path_off)? as usize;
        let path = utf16le(need(d, off + path_off + 2, plen * 2)?, false);
        let ft = u64_at(d, off + 100)?;
        let e = DestListEntry {
            offset: off,
            entry_number: u32_at(d, off + 88)?,
            hostname: decode_ansi(&need(d, off + 72, 16)?.iter().copied().take_while(|&b| b != 0).collect::<Vec<_>>()),
            path,
            last_modification_ns: filetime_to_ns(ft),
            last_modification_filetime: ft,
            pin_status: u32_at(d, off + 108)? as i32,
            access_count: if v1 { None } else { Some(u32_at(d, off + 116)?) },
            droid_volume_identifier: nonzero_guid(need(d, off + 8, 16)?),
            droid_file_identifier: nonzero_guid(need(d, off + 24, 16)?),
            birth_droid_volume_identifier: nonzero_guid(need(d, off + 40, 16)?),
            birth_droid_file_identifier: nonzero_guid(need(d, off + 56, 16)?),
        };
        off += path_off + 2 + plen * 2 + if v1 { 0 } else { 4 };
        dl.entries.push(e);
    }
    Ok(dl)
}

pub fn parse_automatic(data: &[u8]) -> Result<AutomaticDestinations> {
    let ole = Olecf::parse(data)?;
    let mut out = AutomaticDestinations { dest_list: None, streams: Vec::new() };
    let mut kids = ole.root_children();
    kids.sort_by(|a, b| {
        let (na, nb) = (&ole.entries[*a].name, &ole.entries[*b].name);
        let ka = u64::from_str_radix(na, 16).ok();
        let kb = u64::from_str_radix(nb, 16).ok();
        (ka.is_none(), ka, na).cmp(&(kb.is_none(), kb, nb))
    });
    for i in kids {
        let e = &ole.entries[i];
        if !e.is_stream() {
            continue;
        }
        let bytes = match ole.read_stream(i) {
            Ok(b) => b,
            Err(err) => {
                out.streams.push(AutoStream { name: e.name.clone(), size: e.size as usize, lnk: None, error: Some(err.to_string()) });
                continue;
            }
        };
        if e.name.eq_ignore_ascii_case("DestList") {
            out.dest_list = parse_dest_list(&bytes).ok();
            continue;
        }
        let (lnk, error) = match lnk::parse(&bytes) {
            Ok(l) => (Some(l), None),
            Err(err) => (None, Some(err.to_string())),
        };
        out.streams.push(AutoStream { name: e.name.clone(), size: bytes.len(), lnk, error });
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize)]
pub struct CustomEntry {
    pub offset: usize,
    pub category: Option<String>,
    pub lnk: LnkFile,
}

#[derive(Debug, Clone, Serialize)]
pub struct CustomDestinations {
    pub version: u32,
    pub categories: Vec<String>,
    pub entries: Vec<CustomEntry>,
}

pub fn parse_custom(data: &[u8]) -> Result<CustomDestinations> {
    let version = u32_at(data, 0)?;
    if version != 2 {
        return Err(ParseError::Unsupported(format!("customDestinations version {version}")));
    }
    // Locate category names (type 0 = custom category with a UTF-16 name) best-effort, and
    // embedded links by the LNK class identifier followed by a shell link header.
    let mut pat = Vec::with_capacity(36);
    pat.extend_from_slice(&LNK_CLSID);
    pat.extend_from_slice(&[0x4c, 0, 0, 0]);
    pat.extend_from_slice(&LNK_CLSID);
    let mut categories: Vec<(usize, String)> = Vec::new();
    let mut entries = Vec::new();
    let mut off = 12usize;
    // Category header walk.
    let mut pos = 12usize;
    while pos + 4 <= data.len() && categories.len() < 1024 {
        let Ok(t) = u32_at(data, pos) else { break };
        if t == 0 {
            let Ok(n) = u16_at(data, pos + 4) else { break };
            let Ok(name) = need(data, pos + 6, n as usize * 2) else { break };
            categories.push((pos, utf16le(name, false)));
        }
        // jump to the next footer to find the next category header
        match find(data, &0xbabf_fbabu32.to_le_bytes(), pos + 4) {
            Some(f) => pos = f + 4,
            None => break,
        }
    }
    while let Some(p) = find(data, &pat, off) {
        if entries.len() >= MAX_CUSTOM_ENTRIES {
            break;
        }
        let start = p + 16;
        match lnk::parse(&data[start..]) {
            Ok(l) => {
                let cat = categories.iter().rev().find(|(cpos, _)| *cpos < p).map(|(_, n)| n.clone());
                let adv = l.size.max(76);
                entries.push(CustomEntry { offset: start, category: cat, lnk: l });
                off = start + adv;
            }
            Err(_) => off = p + 16,
        }
    }
    Ok(CustomDestinations { version, categories: categories.into_iter().map(|(_, n)| n).collect(), entries })
}

fn find(h: &[u8], n: &[u8], from: usize) -> Option<usize> {
    if n.is_empty() || from >= h.len() || h.len() - from < n.len() {
        return None;
    }
    h[from..].windows(n.len()).position(|w| w == n).map(|p| p + from)
}

pub fn automatic_events(a: &AutomaticDestinations, sha: &str, path: &str) -> Vec<Event> {
    let mut out = Vec::new();
    for s in &a.streams {
        if let Some(l) = &s.lnk {
            for mut e in lnk::events(l, sha, path, 0) {
                e.attrs.insert("jump_list_stream".into(), json!(s.name));
                e.offset = i64::from_str_radix(&s.name, 16).unwrap_or(0);
                e.parser = "jumplist".into();
                out.push(e);
            }
        }
    }
    if let Some(dl) = &a.dest_list {
        for en in &dl.entries {
            let msg = format!(
                "Entry: {} Pin status: {} Hostname: {} Path: {} Droid volume identifier: {} Droid file identifier: {}",
                en.entry_number,
                if en.pin_status == -1 { "Unpinned".to_string() } else { format!("Pinned ({})", en.pin_status) },
                en.hostname,
                en.path,
                en.droid_volume_identifier.clone().unwrap_or_default(),
                en.droid_file_identifier.clone().unwrap_or_default()
            );
            let mut e = Event::new("windows:jump_list:automatic_destination", desc::MODIFICATION, msg)
                .with_time(en.last_modification_ns)
                .attr("entry_number", en.entry_number)
                .attr("hostname", en.hostname.clone())
                .attr("path", en.path.clone())
                .attr("pin_status", en.pin_status)
                .attr("dest_list_version", dl.version)
                .attr("droid_volume_identifier", json!(en.droid_volume_identifier))
                .attr("droid_file_identifier", json!(en.droid_file_identifier))
                .attr("birth_droid_volume_identifier", json!(en.birth_droid_volume_identifier))
                .attr("birth_droid_file_identifier", json!(en.birth_droid_file_identifier));
            if let Some(c) = en.access_count {
                e = e.attr("access_count", c);
            }
            e.source_short = "LNK".into();
            e.source_long = "Jump List DestList".into();
            out.push(e.provenance(sha, path, en.offset as i64, "jumplist", crate::PARSER_VERSION));
        }
    }
    out
}

pub fn custom_events(c: &CustomDestinations, sha: &str, path: &str) -> Vec<Event> {
    let mut out = Vec::new();
    for en in &c.entries {
        for mut e in lnk::events(&en.lnk, sha, path, en.offset as i64) {
            if e.data_type == "windows:lnk:link" {
                e.data_type = "windows:jump_list:custom_destination".into();
            }
            e.attrs.insert("jump_list_category".into(), json!(en.category));
            e.parser = "jumplist".into();
            e.source_long = "Jump List CustomDestinations".into();
            out.push(e);
        }
    }
    out
}
