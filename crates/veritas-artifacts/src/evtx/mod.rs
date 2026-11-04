//! Windows XML event log (.evtx, MS-EVEN6) and legacy event log (.evt) parsers.
pub mod binxml;
pub mod known_ids;

use crate::error::{ParseError, Result};
use crate::util::{need, u16_at, u32_at, u64_at, utf16le};
use binxml::{Chunk, XElem, XNode};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use veritas_timeline::{desc, filetime_to_ns, format_ns, unix_secs_to_ns, Event};

const CHUNK_SIZE: usize = 65536;
const MAX_CHUNKS: usize = 1 << 20;

// ---------------------------------------------------------------- CRC32 (IEEE)

const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}
static CRC_TABLE: [u32; 256] = crc_table();

pub fn crc32(parts: &[&[u8]]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for p in parts {
        for &b in *p {
            c = CRC_TABLE[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
        }
    }
    !c
}

// ---------------------------------------------------------------- structures

#[derive(Debug, Clone, Serialize)]
pub struct FileHeader {
    pub first_chunk_number: u64,
    pub last_chunk_number: u64,
    pub next_record_identifier: u64,
    pub major_version: u16,
    pub minor_version: u16,
    pub number_of_chunks: u16,
    pub flags: u32,
    pub checksum_ok: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChunkInfo {
    pub index: usize,
    pub offset: usize,
    pub first_record_id: u64,
    pub last_record_id: u64,
    pub header_crc_ok: bool,
    pub data_crc_ok: bool,
    pub records: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Record {
    pub identifier: u64,
    pub written_filetime: u64,
    pub written_ns: Option<i64>,
    pub offset: usize,
    pub chunk_index: usize,
    pub header_crc_ok: bool,
    pub data_crc_ok: bool,
    pub xml: String,
    pub provider_name: Option<String>,
    pub provider_guid: Option<String>,
    pub event_source_name: Option<String>,
    pub event_id: Option<u32>,
    pub qualifiers: Option<u32>,
    pub version: Option<u32>,
    pub level: Option<u32>,
    pub task: Option<u32>,
    pub opcode: Option<u32>,
    pub keywords: Option<String>,
    pub time_created: Option<String>,
    pub time_created_ns: Option<i64>,
    pub record_id: Option<u64>,
    pub activity_id: Option<String>,
    pub related_activity_id: Option<String>,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    pub channel: Option<String>,
    pub computer: Option<String>,
    pub user_sid: Option<String>,
    /// Named `<Data Name=..>` values in document order (name -> value).
    pub event_data: Vec<(String, String)>,
    /// Unnamed `<Data>` values.
    pub event_data_unnamed: Vec<String>,
    /// `<Binary>` content under EventData (hex).
    pub binary: Option<String>,
    /// UserData as a nested JSON object.
    pub user_data: Option<Value>,
    /// libevtx-style string list (EventData/UserData leaf values in order).
    pub strings: Vec<String>,
}

impl Record {
    pub fn source_name(&self) -> Option<&str> {
        self.event_source_name.as_deref().or(self.provider_name.as_deref())
    }
    pub fn event_data_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        for (k, v) in &self.event_data {
            m.insert(k.clone(), json!(v));
        }
        m
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EvtxFile {
    pub header: FileHeader,
    pub chunks: Vec<ChunkInfo>,
    pub records: Vec<Record>,
}

// ---------------------------------------------------------------- parsing

pub fn parse(data: &[u8]) -> Result<EvtxFile> {
    let sig = need(data, 0, 8)?;
    if sig != b"ElfFile\0" {
        return Err(ParseError::BadSignature { offset: 0, expected: "ElfFile".into(), found: hex::encode(sig) });
    }
    need(data, 0, 128)?;
    let header = FileHeader {
        first_chunk_number: u64_at(data, 8)?,
        last_chunk_number: u64_at(data, 16)?,
        next_record_identifier: u64_at(data, 24)?,
        minor_version: u16_at(data, 36)?,
        major_version: u16_at(data, 38)?,
        number_of_chunks: u16_at(data, 42)?,
        flags: u32_at(data, 120)?,
        checksum_ok: crc32(&[&data[..120]]) == u32_at(data, 124)?,
    };
    // Chunks start after the 4096-byte header block regardless of the declared header size.
    let hdr_block = 4096usize;
    let mut chunks = Vec::new();
    let mut records = Vec::new();
    let mut idx = 0usize;
    let mut off = hdr_block;
    while off + 512 <= data.len() && idx < MAX_CHUNKS {
        let end = (off + CHUNK_SIZE).min(data.len());
        let c = &data[off..end];
        if &c[..8] == b"ElfChnk\0" {
            let (ci, mut recs) = parse_chunk(c, idx, off);
            chunks.push(ci);
            records.append(&mut recs);
        }
        idx += 1;
        off += CHUNK_SIZE;
    }
    Ok(EvtxFile { header, chunks, records })
}

fn parse_chunk(c: &[u8], index: usize, file_off: usize) -> (ChunkInfo, Vec<Record>) {
    let mut ci = ChunkInfo {
        index,
        offset: file_off,
        first_record_id: u64_at(c, 24).unwrap_or(0),
        last_record_id: u64_at(c, 32).unwrap_or(0),
        header_crc_ok: false,
        data_crc_ok: false,
        records: 0,
        errors: Vec::new(),
    };
    let free = u32_at(c, 48).unwrap_or(0) as usize;
    if c.len() >= 512 {
        ci.header_crc_ok = crc32(&[&c[..120], &c[128..512]]) == u32_at(c, 124).unwrap_or(0);
        if free >= 512 && free <= c.len() {
            ci.data_crc_ok = crc32(&[&c[512..free]]) == u32_at(c, 52).unwrap_or(0);
        }
    }
    let chunk = Chunk::new(c);
    let mut out = Vec::new();
    let mut p = 512usize;
    let limit = if free >= 512 && free <= c.len() { free } else { c.len() };
    while p + 24 <= limit {
        if u32_at(c, p).ok() != Some(0x0000_2a2a) {
            break;
        }
        let size = u32_at(c, p + 4).unwrap_or(0) as usize;
        if size < 28 || p + size > c.len() {
            ci.errors.push(format!("record at chunk offset {p}: bad size {size}"));
            break;
        }
        let mut r = Record {
            identifier: u64_at(c, p + 8).unwrap_or(0),
            written_filetime: u64_at(c, p + 16).unwrap_or(0),
            offset: file_off + p,
            chunk_index: index,
            header_crc_ok: ci.header_crc_ok,
            data_crc_ok: ci.data_crc_ok,
            ..Default::default()
        };
        r.written_ns = filetime_to_ns(r.written_filetime);
        chunk.reset_budget();
        match render_record(&chunk, p + 24, p + size - 4) {
            Ok(nodes) => {
                r.xml = binxml::render(&nodes);
                extract(&nodes, &mut r);
            }
            Err(e) => ci.errors.push(format!("record {}: {e}", r.identifier)),
        }
        out.push(r);
        p += size;
    }
    ci.records = out.len();
    (ci, out)
}

fn render_record(chunk: &Chunk, start: usize, end: usize) -> Result<Vec<XNode>> {
    let (nodes, _) = chunk.parse_fragment(start, end, 0)?;
    chunk.resolve(&nodes, &[], 0)
}

fn parse_num<T: std::str::FromStr>(s: &str) -> Option<T> {
    s.trim().parse().ok()
}

fn first_elem(nodes: &[XNode]) -> Option<&XElem> {
    nodes.iter().find_map(|n| match n {
        XNode::Elem(e) => Some(e),
        _ => None,
    })
}

fn elem_to_json(e: &XElem, depth: usize) -> Value {
    if depth > 64 {
        return Value::Null;
    }
    if !e.has_elem_children() {
        if e.attrs.is_empty() {
            return json!(e.text());
        }
        let mut m = Map::new();
        for (k, v) in &e.attrs {
            m.insert(format!("@{k}"), json!(v));
        }
        let t = e.text();
        if !t.is_empty() {
            m.insert("#text".into(), json!(t));
        }
        return Value::Object(m);
    }
    let mut m = Map::new();
    for (k, v) in &e.attrs {
        m.insert(format!("@{k}"), json!(v));
    }
    for c in e.elems() {
        let v = elem_to_json(c, depth + 1);
        match m.get_mut(&c.name) {
            Some(Value::Array(a)) => a.push(v),
            Some(prev) => {
                let p = prev.take();
                *prev = Value::Array(vec![p, v]);
            }
            None => {
                m.insert(c.name.clone(), v);
            }
        }
    }
    Value::Object(m)
}

fn leaf_texts(e: &XElem, out: &mut Vec<String>, depth: usize) {
    if depth > 64 {
        return;
    }
    if !e.has_elem_children() {
        // Attribute-only empty elements carry no string (libevtx).
        if !(e.text().is_empty() && !e.attrs.is_empty()) {
            out.push(e.text());
        }
        return;
    }
    for c in e.elems() {
        leaf_texts(c, out, depth + 1);
    }
}

fn parse_systemtime_attr(s: &str) -> Option<i64> {
    // 2010-11-21T03:55:59.626427100Z
    let (main, frac) = s.trim_end_matches('Z').split_once('.').unwrap_or((s.trim_end_matches('Z'), "0"));
    let dt = chrono::NaiveDateTime::parse_from_str(main, "%Y-%m-%dT%H:%M:%S").ok()?;
    let mut f = frac.to_string();
    f.truncate(9);
    while f.len() < 9 {
        f.push('0');
    }
    let ns: i64 = f.parse().ok()?;
    dt.and_utc().timestamp_nanos_opt()?.checked_add(ns)
}

fn extract(nodes: &[XNode], r: &mut Record) {
    let Some(ev) = first_elem(nodes) else { return };
    if let Some(sys) = ev.child("System") {
        if let Some(p) = sys.child("Provider") {
            r.provider_name = p.attr("Name").map(String::from);
            r.provider_guid = p.attr("Guid").map(String::from);
            r.event_source_name = p.attr("EventSourceName").map(String::from);
        }
        if let Some(e) = sys.child("EventID") {
            r.event_id = parse_num(&e.text());
            r.qualifiers = e.attr("Qualifiers").and_then(parse_num);
        }
        r.version = sys.child("Version").and_then(|e| parse_num(&e.text()));
        r.level = sys.child("Level").and_then(|e| parse_num(&e.text()));
        r.task = sys.child("Task").and_then(|e| parse_num(&e.text()));
        r.opcode = sys.child("Opcode").and_then(|e| parse_num(&e.text()));
        r.keywords = sys.child("Keywords").map(|e| e.text());
        if let Some(t) = sys.child("TimeCreated").and_then(|e| e.attr("SystemTime")) {
            r.time_created = Some(t.to_string());
            r.time_created_ns = parse_systemtime_attr(t);
        }
        r.record_id = sys.child("EventRecordID").and_then(|e| parse_num(&e.text()));
        if let Some(c) = sys.child("Correlation") {
            r.activity_id = c.attr("ActivityID").map(String::from);
            r.related_activity_id = c.attr("RelatedActivityID").map(String::from);
        }
        if let Some(x) = sys.child("Execution") {
            r.process_id = x.attr("ProcessID").and_then(parse_num);
            r.thread_id = x.attr("ThreadID").and_then(parse_num);
        }
        r.channel = sys.child("Channel").map(|e| e.text());
        r.computer = sys.child("Computer").map(|e| e.text());
        r.user_sid = sys.child("Security").and_then(|e| e.attr("UserID")).map(String::from);
    }
    if let Some(ed) = ev.child("EventData") {
        for d in ed.elems() {
            let v = if d.has_elem_children() { elem_to_json(d, 0).to_string() } else { d.text() };
            if d.name == "Data" {
                match d.attr("Name") {
                    Some(n) => r.event_data.push((n.to_string(), v.clone())),
                    None => r.event_data_unnamed.push(v.clone()),
                }
            } else if d.name == "Binary" {
                r.binary = Some(v.clone());
            } else {
                r.event_data.push((d.name.clone(), v.clone()));
            }
            r.strings.push(v);
        }
    }
    if let Some(ud) = ev.child("UserData") {
        let mut m = Map::new();
        for c in ud.elems() {
            m.insert(c.name.clone(), elem_to_json(c, 0));
            leaf_texts(c, &mut r.strings, 0);
        }
        r.user_data = Some(Value::Object(m));
    }
}

// ---------------------------------------------------------------- events

/// EventData keys copied to normalized top-level attributes for the analytics layer.
const PROMOTE: &[(&str, &str)] = &[
    ("NewProcessName", "process_name"),
    ("Image", "process_name"),
    ("ProcessName", "process_name"),
    ("CommandLine", "command_line"),
    ("ProcessCommandLine", "command_line"),
    ("ParentProcessName", "parent_process_name"),
    ("ParentImage", "parent_process_name"),
    ("ParentCommandLine", "parent_command_line"),
    ("TargetUserName", "target_user_name"),
    ("TargetDomainName", "target_domain_name"),
    ("TargetUserSid", "target_user_sid"),
    ("SubjectUserName", "subject_user_name"),
    ("SubjectDomainName", "subject_domain_name"),
    ("LogonType", "logon_type"),
    ("LogonProcessName", "logon_process_name"),
    ("AuthenticationPackageName", "authentication_package"),
    ("WorkstationName", "workstation_name"),
    ("IpAddress", "ip_address"),
    ("SourceAddress", "ip_address"),
    ("SourceIp", "ip_address"),
    ("Address", "ip_address"),
    ("IpPort", "ip_port"),
    ("SourcePort", "ip_port"),
    ("DestinationIp", "destination_ip"),
    ("DestinationPort", "destination_port"),
    ("TargetServerName", "target_server_name"),
    ("ServiceName", "service_name"),
    ("ImagePath", "image_path"),
    ("ServiceFileName", "image_path"),
    ("ServiceType", "service_type"),
    ("StartType", "start_type"),
    ("AccountName", "service_account"),
    ("TaskName", "task_name"),
    ("TaskContent", "task_content"),
    ("ScriptBlockText", "script_block_text"),
    ("Path", "script_path"),
    ("ShareName", "share_name"),
    ("RelativeTargetName", "share_relative_target"),
    ("Hashes", "hashes"),
    ("User", "user_name"),
    ("QueryName", "dns_query"),
    ("TargetFilename", "target_filename"),
    ("ThreatName", "threat_name"),
    ("Threat Name", "threat_name"),
];

fn flatten_user_data(v: &Value, out: &mut Vec<(String, String)>, depth: usize) {
    if depth > 16 {
        return;
    }
    if let Value::Object(m) = v {
        for (k, x) in m {
            match x {
                Value::String(s) => out.push((k.clone(), s.clone())),
                Value::Object(_) => flatten_user_data(x, out, depth + 1),
                _ => {}
            }
        }
    }
}

pub fn record_event(r: &Record, sha: &str, path: &str) -> Vec<Event> {
    let eid = r.event_id.unwrap_or(0);
    let src = r.source_name().unwrap_or("").to_string();
    let strings_repr = format!("[{}]", r.strings.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(", "));
    let msg = format!(
        "[{eid} / 0x{eid:04x}] Source Name: {src} Strings: {strings_repr} Computer Name: {} Record Number: {} Event Level: {}",
        r.computer.clone().unwrap_or_default(),
        r.identifier,
        r.level.map(|l| l.to_string()).unwrap_or_default()
    );
    let known = known_ids::lookup(eid, r.provider_name.as_deref().unwrap_or(""), r.channel.as_deref().unwrap_or(""));
    let mut ed = Map::new();
    for (k, v) in &r.event_data {
        ed.insert(k.clone(), json!(v));
    }
    let mut base = Event::new("windows:evtx:record", desc::WRITTEN, msg.clone())
        .with_time(r.written_ns)
        .attr("xml_string", r.xml.clone())
        .attr("event_identifier", eid)
        .attr("event_identifier_qualifiers", json!(r.qualifiers))
        .attr("event_level", json!(r.level))
        .attr("event_version", json!(r.version))
        .attr("task", json!(r.task))
        .attr("opcode", json!(r.opcode))
        .attr("keywords", json!(r.keywords))
        .attr("source_name", src.clone())
        .attr("provider_identifier", json!(r.provider_guid))
        .attr("channel", json!(r.channel))
        .attr("computer_name", json!(r.computer))
        .attr("record_number", r.identifier)
        .attr("user_sid", json!(r.user_sid))
        .attr("strings", json!(r.strings))
        .attr("event_data", Value::Object(ed))
        .attr("time_created", json!(r.time_created))
        .attr("process_id", json!(r.process_id))
        .attr("thread_id", json!(r.thread_id))
        .attr("known_name", json!(known.map(|k| k.name)))
        .attr("known_category", json!(known.map(|k| k.category)))
        .attr("known_description", json!(known.map(|k| k.description)));
    if !r.event_data_unnamed.is_empty() {
        base = base.attr("event_data_unnamed", json!(r.event_data_unnamed));
    }
    if let Some(u) = &r.user_data {
        base = base.attr("user_data", u.clone());
    }
    if !r.header_crc_ok || !r.data_crc_ok {
        base = base.attr("chunk_crc_ok", false);
    }
    // Promote well-known fields.
    let mut pairs: Vec<(String, String)> = r.event_data.clone();
    if let Some(u) = &r.user_data {
        flatten_user_data(u, &mut pairs, 0);
    }
    for (key, attr) in PROMOTE {
        if base.attrs.contains_key(*attr) {
            continue;
        }
        if let Some((_, v)) = pairs.iter().find(|(k, _)| k == key) {
            if !v.is_empty() && v != "-" {
                base.attrs.insert(attr.to_string(), json!(v));
            }
        }
    }
    base.host = r.computer.clone().filter(|c| !c.is_empty());
    base.source_short = "EVT".into();
    base.source_long = "WinEVTX".into();
    let base = base.provenance(sha, path, r.identifier as i64, "evtx", crate::PARSER_VERSION);
    let mut out = vec![base.clone()];
    if let (Some(tc), Some(w)) = (r.time_created_ns, r.written_ns) {
        if tc != w {
            let mut e = base;
            e.timestamp = Some(tc);
            e.timestamp_desc = desc::CREATION.into();
            out.push(e);
        }
    }
    out
}

pub fn events(f: &EvtxFile, sha: &str, path: &str) -> Vec<Event> {
    f.records.iter().flat_map(|r| record_event(r, sha, path)).collect()
}

// ---------------------------------------------------------------- legacy .evt

#[derive(Debug, Clone, Serialize)]
pub struct EvtRecord {
    pub offset: usize,
    /// Outside the header's live window (recovered from free space).
    pub recovered: bool,
    pub record_number: u32,
    pub time_generated: u32,
    pub time_written: u32,
    pub event_identifier: u32,
    pub event_type: u16,
    pub event_category: u16,
    pub source_name: String,
    pub computer_name: String,
    pub user_sid: Option<String>,
    pub strings: Vec<String>,
    pub data_hex: String,
}

/// Parse a legacy Windows NT event log by scanning for `LfLe` records. Records that wrap
/// around the end of the circular buffer are reassembled. Records outside the header's
/// start..end window are flagged `recovered` (libevt semantics).
pub fn parse_evt(data: &[u8]) -> Result<Vec<EvtRecord>> {
    let sig = need(data, 4, 4)?;
    if sig != b"LfLe" || u32_at(data, 0)? != 0x30 {
        return Err(ParseError::BadSignature { offset: 4, expected: "LfLe".into(), found: hex::encode(sig) });
    }
    let mut start = u32_at(data, 16)? as usize;
    let mut end = u32_at(data, 20)? as usize;
    // A dirty log keeps stale header offsets; the end-of-file record holds the current ones.
    const EOF_SIG: [u8; 20] = [0x28, 0, 0, 0, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44];
    if let Some(e) = data.windows(20).position(|w| w == EOF_SIG) {
        if let (Ok(s), Ok(en)) = (u32_at(data, e + 20), u32_at(data, e + 24)) {
            start = s as usize;
            end = en as usize;
        }
    }
    let in_window = |o: usize| -> bool {
        if start <= end { o >= start && o < end } else { o >= start || (o < end && o >= 0x30) }
    };
    let mut out = Vec::new();
    let mut p = 0x30usize;
    while p + 8 <= data.len() {
        if &data[p + 4..p + 8] != b"LfLe" {
            p += 4;
            continue;
        }
        let size = u32_at(data, p)? as usize;
        if !(0x38..=0x10_0000).contains(&size) {
            p += 4;
            continue;
        }
        let assembled: Vec<u8>;
        let rec: &[u8] = if p + size <= data.len() {
            &data[p..p + size]
        } else {
            // wrap-around: remainder continues right after the file header
            let first = &data[p..];
            let rest = size - first.len();
            match need(data, 0x30, rest) {
                Ok(r) => {
                    assembled = [first, r].concat();
                    &assembled
                }
                Err(_) => break,
            }
        };
        if u32_at(rec, size - 4)? as usize != size {
            p += 4;
            continue;
        }
        if let Ok(mut r) = parse_evt_record(rec, p) {
            r.recovered = !in_window(p);
            out.push(r);
        }
        if p + size > data.len() {
            break;
        }
        p += size;
    }
    out.sort_by_key(|r| (r.recovered, r.record_number, r.offset));
    Ok(out)
}

fn parse_evt_record(rec: &[u8], p: usize) -> Result<EvtRecord> {
    let num_strings = u16_at(rec, 26)? as usize;
    let str_off = u32_at(rec, 36)? as usize;
    let sid_len = u32_at(rec, 40)? as usize;
    let sid_off = u32_at(rec, 44)? as usize;
    let data_len = u32_at(rec, 48)? as usize;
    let data_off = u32_at(rec, 52)? as usize;
    let tail = &rec[0x38.min(rec.len())..];
    let src = utf16le(tail, true);
    let after_src = 0x38 + (src.encode_utf16().count() + 1) * 2;
    let comp = utf16le(&rec[after_src.min(rec.len())..], true);
    let mut strings = Vec::new();
    let mut q = str_off;
    for _ in 0..num_strings.min(1024) {
        if q >= rec.len() {
            break;
        }
        let s = utf16le(&rec[q..], true);
        q += (s.encode_utf16().count() + 1) * 2;
        strings.push(s);
    }
    Ok(EvtRecord {
        offset: p,
        recovered: false,
        record_number: u32_at(rec, 8)?,
        time_generated: u32_at(rec, 12)?,
        time_written: u32_at(rec, 16)?,
        event_identifier: u32_at(rec, 20)?,
        event_type: u16_at(rec, 24)?,
        event_category: u16_at(rec, 28)?,
        source_name: src,
        computer_name: comp,
        user_sid: if sid_len > 0 { need(rec, sid_off, sid_len).ok().and_then(binxml::sid_string) } else { None },
        strings,
        data_hex: need(rec, data_off, data_len).map(crate::util::hex_upper).unwrap_or_default(),
    })
}

pub fn evt_events(recs: &[EvtRecord], sha: &str, path: &str) -> Vec<Event> {
    let mut out = Vec::new();
    for r in recs {
        let eid = r.event_identifier & 0xffff;
        let msg = format!(
            "[{eid} / 0x{eid:04x}] Source Name: {} Strings: [{}] Computer Name: {} Record Number: {} Event Type: {} Event Category: {}",
            r.source_name,
            r.strings.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(", "),
            r.computer_name,
            r.record_number,
            r.event_type,
            r.event_category
        );
        for (t, d) in [(r.time_generated, desc::CREATION), (r.time_written, desc::WRITTEN)] {
            let mut e = Event::new("windows:evt:record", d, msg.clone())
                .with_time(unix_secs_to_ns(t as i64))
                .attr("event_identifier", r.event_identifier)
                .attr("event_type", r.event_type)
                .attr("event_category", r.event_category)
                .attr("source_name", r.source_name.clone())
                .attr("computer_name", r.computer_name.clone())
                .attr("record_number", r.record_number)
                .attr("recovered", r.recovered)
                .attr("user_sid", json!(r.user_sid))
                .attr("strings", json!(r.strings));
            e.source_short = "EVT".into();
            e.source_long = "WinEVT".into();
            out.push(e.provenance(sha, path, r.offset as i64, "evt", crate::PARSER_VERSION));
        }
    }
    out
}

/// Summary for diagnostics: written times as RFC 3339.
pub fn written_times(f: &EvtxFile) -> BTreeMap<u64, String> {
    f.records.iter().filter_map(|r| r.written_ns.map(|t| (r.identifier, format_ns(t)))).collect()
}
