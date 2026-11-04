//! Apple property lists: binary (`bplist00`) and XML, NSKeyedArchiver unarchiving, and
//! timeline events for well-known macOS plists plus a generic event per date value.
// `slice::as_chunks` needs Rust 1.88; the workspace MSRV is 1.80.
#![allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
use crate::error::{ParseError, Result};
use crate::util::{need, u64_be_at, u8_at};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use veritas_timeline::{cocoa_secs_to_ns, desc, format_ns, Event};

const MAX_DEPTH: usize = 512;
const MAX_NODES: usize = 2_000_000;

#[derive(Debug, Clone, PartialEq)]
pub enum PlistValue {
    Null,
    Bool(bool),
    Int(i128),
    Real(f64),
    /// Seconds since 2001-01-01T00:00:00Z (Cocoa absolute time).
    Date(f64),
    Data(Vec<u8>),
    String(String),
    Uid(u64),
    Array(Vec<PlistValue>),
    Set(Vec<PlistValue>),
    /// Keys in file order; `to_json` sorts them.
    Dict(Vec<(String, PlistValue)>),
}

/// Cocoa seconds (float) to epoch nanoseconds, rounded to the nearest nanosecond.
pub fn cocoa_float_to_ns(secs: f64) -> Option<i64> {
    if !secs.is_finite() || secs.abs() > 9.0e9 {
        return None;
    }
    let whole = secs.floor();
    let frac_ns = ((secs - whole) * 1e9).round() as i64;
    cocoa_secs_to_ns(whole as i64)?.checked_add(frac_ns)
}

impl PlistValue {
    pub fn get(&self, key: &str) -> Option<&PlistValue> {
        match self {
            PlistValue::Dict(kv) => kv.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PlistValue::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[PlistValue]> {
        match self {
            PlistValue::Array(a) | PlistValue::Set(a) => Some(a),
            _ => None,
        }
    }
    pub fn date_ns(&self) -> Option<i64> {
        match self {
            PlistValue::Date(s) => cocoa_float_to_ns(*s),
            _ => None,
        }
    }

    /// Deterministic JSON: dict keys sorted, bytes as `{"__bytes__": hex}`, dates as
    /// `{"__date__": rfc3339, "__date_ns__": ns}`, reals as `{"__real__": "repr"}` (no JSON floats).
    pub fn to_json(&self) -> Value {
        self.to_json_d(0)
    }

    fn to_json_d(&self, depth: usize) -> Value {
        if depth > MAX_DEPTH {
            return Value::Null;
        }
        match self {
            PlistValue::Null => Value::Null,
            PlistValue::Bool(b) => json!(b),
            PlistValue::Int(i) => {
                if let Ok(v) = i64::try_from(*i) {
                    json!(v)
                } else if let Ok(v) = u64::try_from(*i) {
                    json!(v)
                } else {
                    json!({"__int__": i.to_string()})
                }
            }
            PlistValue::Real(f) => json!({"__real__": format!("{f:?}")}),
            PlistValue::Date(s) => {
                let ns = cocoa_float_to_ns(*s);
                json!({"__date__": ns.map(format_ns), "__date_ns__": ns})
            }
            PlistValue::Data(b) => json!({"__bytes__": hex::encode(b)}),
            PlistValue::String(s) => json!(s),
            PlistValue::Uid(u) => json!({"__uid__": u}),
            PlistValue::Array(a) => Value::Array(a.iter().map(|v| v.to_json_d(depth + 1)).collect()),
            PlistValue::Set(a) => json!({"__set__": a.iter().map(|v| v.to_json_d(depth + 1)).collect::<Vec<_>>()}),
            PlistValue::Dict(kv) => {
                let mut sorted: Vec<&(String, PlistValue)> = kv.iter().collect();
                sorted.sort_by(|a, b| a.0.cmp(&b.0));
                let mut m = Map::new();
                for (k, v) in sorted {
                    m.insert(k.clone(), v.to_json_d(depth + 1));
                }
                Value::Object(m)
            }
        }
    }
}

pub fn parse(data: &[u8]) -> Result<PlistValue> {
    if data.starts_with(b"bplist0") {
        parse_binary(data)
    } else {
        parse_xml(data)
    }
}

// ---------------------------------------------------------------- binary

struct Bin<'a> {
    d: &'a [u8],
    offsets: Vec<usize>,
    ref_size: usize,
    nodes: usize,
}

fn be_uint(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |a, &x| (a << 8) | x as u64)
}

pub fn parse_binary(d: &[u8]) -> Result<PlistValue> {
    if d.len() < 40 {
        return Err(ParseError::Truncated { offset: 0, needed: 40, available: d.len() });
    }
    let t = d.len() - 32;
    let off_size = u8_at(d, t + 6)? as usize;
    let ref_size = u8_at(d, t + 7)? as usize;
    let n = u64_be_at(d, t + 8)? as usize;
    let top = u64_be_at(d, t + 16)? as usize;
    let table = u64_be_at(d, t + 24)? as usize;
    if !(1..=8).contains(&off_size) || !(1..=8).contains(&ref_size) {
        return Err(ParseError::Invalid { offset: t, reason: format!("offset/ref size {off_size}/{ref_size}") });
    }
    let tb = need(d, table, n.checked_mul(off_size).ok_or_else(|| ParseError::Limit("object count".into()))?)?;
    let offsets: Vec<usize> = tb.chunks_exact(off_size).map(|c| be_uint(c) as usize).collect();
    let mut b = Bin { d, offsets, ref_size, nodes: 0 };
    let mut stack = BTreeSet::new();
    b.obj(top, &mut stack, 0)
}

impl Bin<'_> {
    fn len_and_start(&self, marker: u8, o: usize) -> Result<(usize, usize)> {
        let low = (marker & 0x0f) as usize;
        if low != 0x0f {
            return Ok((low, o + 1));
        }
        let im = u8_at(self.d, o + 1)?;
        if im >> 4 != 1 {
            return Err(ParseError::Invalid { offset: o + 1, reason: "bad length integer".into() });
        }
        let nb = 1usize << (im & 0x0f);
        if nb > 8 {
            return Err(ParseError::Invalid { offset: o + 1, reason: "length integer too wide".into() });
        }
        let v = be_uint(need(self.d, o + 2, nb)?) as usize;
        Ok((v, o + 2 + nb))
    }

    fn refs(&self, start: usize, count: usize) -> Result<Vec<usize>> {
        let b = need(self.d, start, count.checked_mul(self.ref_size).ok_or_else(|| ParseError::Limit("ref count".into()))?)?;
        Ok(b.chunks_exact(self.ref_size).map(|c| be_uint(c) as usize).collect())
    }

    fn obj(&mut self, idx: usize, stack: &mut BTreeSet<usize>, depth: usize) -> Result<PlistValue> {
        self.nodes += 1;
        if self.nodes > MAX_NODES || depth > MAX_DEPTH {
            return Err(ParseError::Limit("plist object graph too large or deep".into()));
        }
        if !stack.insert(idx) {
            return Err(ParseError::Invalid { offset: idx, reason: "object reference cycle".into() });
        }
        let r = self.obj_inner(idx, stack, depth);
        stack.remove(&idx);
        r
    }

    fn obj_inner(&mut self, idx: usize, stack: &mut BTreeSet<usize>, depth: usize) -> Result<PlistValue> {
        let o = *self.offsets.get(idx).ok_or_else(|| ParseError::Invalid { offset: idx, reason: "object index out of range".into() })?;
        let m = u8_at(self.d, o)?;
        let low = (m & 0x0f) as usize;
        Ok(match m >> 4 {
            0x0 => match m {
                0x00 => PlistValue::Null,
                0x08 => PlistValue::Bool(false),
                0x09 => PlistValue::Bool(true),
                _ => PlistValue::Null,
            },
            0x1 => {
                let nb = 1usize << low;
                let b = need(self.d, o + 1, nb.min(16))?;
                let v: i128 = match nb {
                    1 | 2 | 4 => be_uint(b) as i128,
                    8 => be_uint(b) as i64 as i128,
                    16 => i128::from_be_bytes(b.try_into().map_err(|_| ParseError::Invalid { offset: o, reason: "int128".into() })?),
                    _ => return Err(ParseError::Invalid { offset: o, reason: "integer width".into() }),
                };
                PlistValue::Int(v)
            }
            0x2 => {
                let nb = 1usize << low;
                let b = need(self.d, o + 1, nb.min(8))?;
                match nb {
                    4 => PlistValue::Real(f32::from_be_bytes(b.try_into().unwrap_or([0; 4])) as f64),
                    8 => PlistValue::Real(f64::from_be_bytes(b.try_into().unwrap_or([0; 8]))),
                    _ => return Err(ParseError::Invalid { offset: o, reason: "real width".into() }),
                }
            }
            0x3 => PlistValue::Date(f64::from_be_bytes(need(self.d, o + 1, 8)?.try_into().unwrap_or([0; 8]))),
            0x4 => {
                let (n, s) = self.len_and_start(m, o)?;
                PlistValue::Data(need(self.d, s, n)?.to_vec())
            }
            0x5 => {
                let (n, s) = self.len_and_start(m, o)?;
                PlistValue::String(need(self.d, s, n)?.iter().map(|&c| c as char).collect())
            }
            0x6 => {
                let (n, s) = self.len_and_start(m, o)?;
                let b = need(self.d, s, n.checked_mul(2).ok_or_else(|| ParseError::Limit("string".into()))?)?;
                let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                PlistValue::String(String::from_utf16_lossy(&units))
            }
            0x7 => {
                let (n, s) = self.len_and_start(m, o)?;
                PlistValue::String(String::from_utf8_lossy(need(self.d, s, n)?).into_owned())
            }
            0x8 => PlistValue::Uid(be_uint(need(self.d, o + 1, low + 1)?)),
            0xa..=0xc => {
                let (n, s) = self.len_and_start(m, o)?;
                let mut v = Vec::with_capacity(n.min(65536));
                for r in self.refs(s, n)? {
                    v.push(self.obj(r, stack, depth + 1)?);
                }
                if m >> 4 == 0xa { PlistValue::Array(v) } else { PlistValue::Set(v) }
            }
            0xd => {
                let (n, s) = self.len_and_start(m, o)?;
                let keys = self.refs(s, n)?;
                let vals = self.refs(s + n * self.ref_size, n)?;
                let mut kv = Vec::with_capacity(n.min(65536));
                for (k, v) in keys.into_iter().zip(vals) {
                    let key = match self.obj(k, stack, depth + 1)? {
                        PlistValue::String(s) => s,
                        other => format!("{:?}", other),
                    };
                    kv.push((key, self.obj(v, stack, depth + 1)?));
                }
                PlistValue::Dict(kv)
            }
            _ => return Err(ParseError::Unsupported(format!("bplist marker 0x{m:02x}"))),
        })
    }
}

// ---------------------------------------------------------------- XML

fn b64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => continue,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

fn parse_iso_date(s: &str) -> Option<f64> {
    let s = s.trim();
    let dt = chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&chrono::Utc))
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(s.trim_end_matches('Z'), "%Y-%m-%dT%H:%M:%S").map(|n| n.and_utc()))
        .ok()?;
    let ns = dt.timestamp_nanos_opt()?;
    Some((ns as f64 / 1e9) - 978_307_200.0)
}

pub fn parse_xml(data: &[u8]) -> Result<PlistValue> {
    let text = std::str::from_utf8(data).map_err(|e| ParseError::Invalid { offset: e.valid_up_to(), reason: "plist XML is not UTF-8".into() })?;
    let opts = roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() };
    let doc = roxmltree::Document::parse_with_options(text, opts).map_err(|e| ParseError::Invalid { offset: 0, reason: format!("XML: {e}") })?;
    let root = doc.root_element();
    let first = if root.tag_name().name() == "plist" { root.children().find(|n| n.is_element()) } else { Some(root) };
    match first {
        Some(n) => xml_value(n, 0),
        None => Ok(PlistValue::Null),
    }
}

fn xml_value(n: roxmltree::Node, depth: usize) -> Result<PlistValue> {
    if depth > MAX_DEPTH {
        return Err(ParseError::Limit("plist XML nesting".into()));
    }
    let text = || n.text().unwrap_or("").to_string();
    Ok(match n.tag_name().name() {
        "string" => PlistValue::String(text()),
        "integer" => {
            let t = text();
            let t = t.trim();
            let v = if let Some(h) = t.strip_prefix("0x") { i128::from_str_radix(h, 16).ok() } else { t.parse::<i128>().ok() };
            PlistValue::Int(v.ok_or_else(|| ParseError::Invalid { offset: 0, reason: format!("integer {t}") })?)
        }
        "real" => PlistValue::Real(text().trim().parse().unwrap_or(f64::NAN)),
        "true" => PlistValue::Bool(true),
        "false" => PlistValue::Bool(false),
        "date" => PlistValue::Date(parse_iso_date(&text()).ok_or_else(|| ParseError::Invalid { offset: 0, reason: "date".into() })?),
        "data" => PlistValue::Data(b64_decode(&text())),
        "array" => PlistValue::Array(n.children().filter(|c| c.is_element()).map(|c| xml_value(c, depth + 1)).collect::<Result<_>>()?),
        "dict" => {
            let mut kv = Vec::new();
            let mut key: Option<String> = None;
            for c in n.children().filter(|c| c.is_element()) {
                if c.tag_name().name() == "key" {
                    key = Some(c.text().unwrap_or("").to_string());
                } else if let Some(k) = key.take() {
                    kv.push((k, xml_value(c, depth + 1)?));
                }
            }
            PlistValue::Dict(kv)
        }
        other => return Err(ParseError::Unsupported(format!("plist element <{other}>"))),
    })
}

// ---------------------------------------------------------------- NSKeyedArchiver

/// Resolve an NSKeyedArchiver plist into a plain value tree (`$top.root` or the whole `$top`).
pub fn unarchive(p: &PlistValue) -> Option<PlistValue> {
    if p.get("$archiver").and_then(|a| a.as_str()) != Some("NSKeyedArchiver") {
        return None;
    }
    let objects = p.get("$objects")?.as_array()?;
    let top = p.get("$top")?;
    let mut stack = BTreeSet::new();
    let resolve_top = |v: &PlistValue, stack: &mut BTreeSet<u64>| resolve_ka(v, objects, stack, 0);
    if let Some(root) = top.get("root") {
        return Some(resolve_top(root, &mut stack));
    }
    if let PlistValue::Dict(kv) = top {
        return Some(PlistValue::Dict(kv.iter().map(|(k, v)| (k.clone(), resolve_top(v, &mut stack))).collect()));
    }
    None
}

fn resolve_ka(v: &PlistValue, objs: &[PlistValue], stack: &mut BTreeSet<u64>, depth: usize) -> PlistValue {
    if depth > 128 {
        return PlistValue::Null;
    }
    match v {
        PlistValue::Uid(u) => {
            if !stack.insert(*u) {
                return PlistValue::String(format!("<cycle uid {u}>"));
            }
            let r = match objs.get(*u as usize) {
                Some(o) => resolve_obj(o, objs, stack, depth + 1),
                None => PlistValue::Null,
            };
            stack.remove(u);
            r
        }
        PlistValue::Array(a) => PlistValue::Array(a.iter().map(|x| resolve_ka(x, objs, stack, depth + 1)).collect()),
        other => other.clone(),
    }
}

fn resolve_obj(o: &PlistValue, objs: &[PlistValue], stack: &mut BTreeSet<u64>, depth: usize) -> PlistValue {
    match o {
        PlistValue::String(s) if s == "$null" => PlistValue::Null,
        PlistValue::Dict(_) => {
            let class_obj = o.get("$class").map(|c| resolve_ka(c, objs, stack, depth + 1));
            let class = class_obj.as_ref().and_then(|c| c.get("$classname").and_then(|n| n.as_str()).map(String::from)).unwrap_or_default();
            // Inheritance chain ($classes) lets bridged subclasses (e.g. OC_BuiltinPythonDate)
            // resolve to their Foundation base class; fall back to the object's shape.
            let chain: Vec<String> = class_obj
                .as_ref()
                .and_then(|c| c.get("$classes"))
                .and_then(|c| c.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            const BASES: &[&str] = &["NSMutableDictionary", "NSDictionary", "NSMutableArray", "NSArray", "NSMutableOrderedSet", "NSOrderedSet", "NSMutableSet", "NSSet", "NSMutableString", "NSString", "NSDate", "NSMutableData", "NSData", "NSUUID", "NSURL"];
            let base = std::iter::once(class.clone()).chain(chain).find(|c| BASES.contains(&c.as_str())).unwrap_or_else(|| {
                if o.get("NS.keys").is_some() && o.get("NS.objects").is_some() {
                    "NSDictionary".into()
                } else if o.get("NS.objects").is_some() {
                    "NSArray".into()
                } else if o.get("NS.string").is_some() {
                    "NSString".into()
                } else if o.get("NS.time").is_some() {
                    "NSDate".into()
                } else {
                    class.clone()
                }
            });
            let list = |k: &str, stack: &mut BTreeSet<u64>| -> Vec<PlistValue> {
                o.get(k).and_then(|a| a.as_array()).map(|a| a.iter().map(|x| resolve_ka(x, objs, stack, depth + 1)).collect()).unwrap_or_default()
            };
            match base.as_str() {
                "NSDictionary" | "NSMutableDictionary" => {
                    let keys = list("NS.keys", stack);
                    let vals = list("NS.objects", stack);
                    PlistValue::Dict(keys.into_iter().zip(vals).map(|(k, v)| (k.as_str().map(String::from).unwrap_or_else(|| format!("{k:?}")), v)).collect())
                }
                "NSArray" | "NSMutableArray" => PlistValue::Array(list("NS.objects", stack)),
                "NSSet" | "NSMutableSet" | "NSOrderedSet" | "NSMutableOrderedSet" => PlistValue::Set(list("NS.objects", stack)),
                "NSString" | "NSMutableString" => o.get("NS.string").cloned().unwrap_or(PlistValue::Null),
                "NSDate" => match o.get("NS.time") {
                    Some(PlistValue::Real(f)) => PlistValue::Date(*f),
                    Some(PlistValue::Int(i)) => PlistValue::Date(*i as f64),
                    _ => PlistValue::Null,
                },
                "NSData" | "NSMutableData" => o.get("NS.data").cloned().unwrap_or(PlistValue::Null),
                "NSUUID" => o.get("NS.uuidbytes").cloned().unwrap_or(PlistValue::Null),
                "NSURL" => o.get("NS.relative").map(|x| resolve_ka(x, objs, stack, depth + 1)).unwrap_or(PlistValue::Null),
                _ => {
                    let mut kv: Vec<(String, PlistValue)> = Vec::new();
                    if let PlistValue::Dict(items) = o {
                        for (k, v) in items {
                            if k == "$class" {
                                continue;
                            }
                            kv.push((k.clone(), resolve_ka(v, objs, stack, depth + 1)));
                        }
                    }
                    if !class.is_empty() {
                        kv.push(("$class".into(), PlistValue::String(class)));
                    }
                    PlistValue::Dict(kv)
                }
            }
        }
        other => other.clone(),
    }
}

// ---------------------------------------------------------------- events

fn finish(mut e: Event, sha: &str, path: &str, off: i64) -> Event {
    e.source_short = "PLIST".into();
    e.source_long = "Plist".into();
    e.provenance(sha, path, off, "plist", crate::PARSER_VERSION)
}

fn walk_dates(v: &PlistValue, path: &str, out: &mut Vec<(String, i64)>, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    match v {
        PlistValue::Date(_) => {
            if let Some(ns) = v.date_ns() {
                out.push((path.to_string(), ns));
            }
        }
        PlistValue::Array(a) | PlistValue::Set(a) => {
            for (i, x) in a.iter().enumerate() {
                walk_dates(x, &format!("{path}/{i}"), out, depth + 1);
            }
        }
        PlistValue::Dict(kv) => {
            for (k, x) in kv {
                walk_dates(x, &format!("{path}/{k}"), out, depth + 1);
            }
        }
        _ => {}
    }
}

fn s(v: Option<&PlistValue>) -> Value {
    match v {
        Some(PlistValue::String(s)) => json!(s),
        Some(other) => other.to_json(),
        None => Value::Null,
    }
}

/// Timeline events. `path` decides which well-known plist handler applies (by file name).
pub fn events(p: &PlistValue, sha: &str, path: &str) -> Vec<Event> {
    let mut out = Vec::new();
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path).to_ascii_lowercase();
    let mut idx = 0i64;
    let mut push = |e: Event, out: &mut Vec<Event>| {
        out.push(finish(e, sha, path, idx));
        idx += 1;
    };
    match base.as_str() {
        "installhistory.plist" => {
            for it in p.as_array().unwrap_or(&[]) {
                let name = it.get("displayName").and_then(|v| v.as_str()).unwrap_or("");
                let ver = it.get("displayVersion").and_then(|v| v.as_str()).unwrap_or("");
                let proc_ = it.get("processName").and_then(|v| v.as_str()).unwrap_or("");
                let pkgs: Vec<String> = it.get("packageIdentifiers").and_then(|v| v.as_array()).unwrap_or(&[]).iter().filter_map(|x| x.as_str().map(String::from)).collect();
                let e = Event::new("macos:install_history:entry", desc::INSTALLATION, format!("Installation of: {name} {ver} ({proc_}). Packages: {}.", pkgs.join(", ")))
                    .with_time(it.get("date").and_then(|d| d.date_ns()))
                    .attr("display_name", name)
                    .attr("display_version", ver)
                    .attr("process_name", proc_)
                    .attr("package_identifiers", json!(pkgs));
                push(e, &mut out);
            }
        }
        "com.apple.softwareupdate.plist" => {
            let ver = p.get("LastAttemptSystemVersion").and_then(|v| v.as_str()).unwrap_or("").to_string();
            for (key, what) in [("LastFullSuccessfulDate", "full"), ("LastSuccessfulDate", "partial")] {
                if let Some(t) = p.get(key).and_then(|d| d.date_ns()) {
                    let pending = p.get("LastUpdatesAvailable").map(|v| v.to_json()).unwrap_or(Value::Null);
                    let e = Event::new("macos:software_update:entry", desc::WRITTEN, format!("Last Mac OS {ver} {what} update."))
                        .with_time(Some(t))
                        .attr("key", key)
                        .attr("system_version", ver.clone())
                        .attr("updates_available", pending)
                        .attr("recommended_updates", s(p.get("RecommendedUpdates")));
                    push(e, &mut out);
                }
            }
        }
        "com.apple.loginitems.plist" => {
            let items = p.get("SessionItems").and_then(|v| v.get("CustomListItems")).and_then(|v| v.as_array()).unwrap_or(&[]);
            for it in items {
                let name = it.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let e = Event::new("macos:login_items:entry", desc::NOT_A_TIME, format!("Login item: {name}"))
                    .attr("name", name)
                    .attr("alias_hex", s(it.get("Alias")));
                push(e, &mut out);
            }
        }
        "com.apple.timemachine.plist" => {
            for dst in p.get("Destinations").and_then(|v| v.as_array()).unwrap_or(&[]) {
                let id = s(dst.get("DestinationID"));
                for d in dst.get("SnapshotDates").and_then(|v| v.as_array()).unwrap_or(&[]) {
                    let e = Event::new("macos:time_machine:backup", desc::WRITTEN, format!("TimeMachine Backup in {} ({})", id.as_str().unwrap_or(""), dst.get("BackupAlias").map(|_| "alias").unwrap_or("")))
                        .with_time(d.date_ns())
                        .attr("destination_identifier", id.clone());
                    push(e, &mut out);
                }
            }
        }
        "com.apple.airport.preferences.plist" => {
            for n in p.get("RememberedNetworks").and_then(|v| v.as_array()).unwrap_or(&[]) {
                let ssid = n.get("SSIDString").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let sec = n.get("SecurityType").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let e = Event::new("macos:airport:entry", desc::LAST_VISITED, format!("[WiFi] Connected to network: <{ssid}> using security {sec}"))
                    .with_time(n.get("LastConnected").and_then(|d| d.date_ns()))
                    .attr("ssid", ssid)
                    .attr("security_type", sec);
                push(e, &mut out);
            }
            if let Some(PlistValue::Dict(kn)) = p.get("KnownNetworks") {
                for (k, n) in kn {
                    let ssid = n.get("SSIDString").and_then(|v| v.as_str()).unwrap_or(k).to_string();
                    for key in ["LastConnected", "LastAutoJoinAt", "AddedAt"] {
                        if let Some(t) = n.get(key).and_then(|d| d.date_ns()) {
                            let e = Event::new("macos:airport:entry", desc::LAST_VISITED, format!("[WiFi] {key}: <{ssid}>")).with_time(Some(t)).attr("ssid", ssid.clone()).attr("key", key);
                            push(e, &mut out);
                        }
                    }
                }
            }
        }
        "com.apple.bluetooth.plist" => {
            if let Some(PlistValue::Dict(cache)) = p.get("DeviceCache") {
                for (mac, dev) in cache {
                    let name = dev.get("Name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    for (key, d) in [("LastInquiryUpdate", "Last Inquiry Update"), ("LastNameUpdate", "Last Name Update"), ("LastServicesUpdate", "Last Services Update")] {
                        if let Some(t) = dev.get(key).and_then(|x| x.date_ns()) {
                            let e = Event::new("macos:bluetooth:entry", desc::WRITTEN, format!("Bluetooth {mac} [{name}] {d}"))
                                .with_time(Some(t))
                                .attr("mac_address", mac.clone())
                                .attr("name", name.clone())
                                .attr("key", key);
                            push(e, &mut out);
                        }
                    }
                }
            }
        }
        _ => {}
    }
    // Generic: every date value anywhere in the (unarchived) tree.
    let tree = unarchive(p).unwrap_or_else(|| p.clone());
    let mut dates = Vec::new();
    walk_dates(&tree, "", &mut dates, 0);
    for (kp, ns) in dates {
        let (root, key) = kp.rsplit_once('/').unwrap_or(("", &kp));
        let root = if root.is_empty() { "/" } else { root };
        let e = Event::new("plist:key", desc::WRITTEN, format!("{}/{key} {}", root.trim_end_matches('/'), format_ns(ns)))
            .with_time(Some(ns))
            .attr("root", root)
            .attr("key", key)
            .attr("key_path", kp.clone());
        push(e, &mut out);
    }
    out
}
