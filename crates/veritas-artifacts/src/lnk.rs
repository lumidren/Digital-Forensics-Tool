//! Windows Shell Link (.lnk) parser, MS-SHLLINK.
use crate::error::{ParseError, Result};
use crate::shellitems::{
    decode_ansi, guid_string, parse_shell_item_list, shell_item_path, ShellItem,
};
use crate::util::{need, u16_at, u32_at, u64_at, utf16le};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use veritas_timeline::{desc, filetime_to_ns, Event};

pub const LNK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46,
];
const MAX_EXTRA_BLOCKS: usize = 256;
const MAX_PROPS: usize = 4096;

pub mod flags {
    pub const HAS_TARGET_ID_LIST: u32 = 0x1;
    pub const HAS_LINK_INFO: u32 = 0x2;
    pub const HAS_NAME: u32 = 0x4;
    pub const HAS_RELATIVE_PATH: u32 = 0x8;
    pub const HAS_WORKING_DIR: u32 = 0x10;
    pub const HAS_ARGUMENTS: u32 = 0x20;
    pub const HAS_ICON_LOCATION: u32 = 0x40;
    pub const IS_UNICODE: u32 = 0x80;
    pub const FORCE_NO_LINK_INFO: u32 = 0x100;
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LinkInfo {
    pub flags: u32,
    pub drive_type: Option<u32>,
    pub drive_serial_number: Option<u32>,
    pub volume_label: Option<String>,
    pub local_base_path: Option<String>,
    pub common_path_suffix: Option<String>,
    pub network_share_name: Option<String>,
    pub device_name: Option<String>,
    pub network_provider_type: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Tracker {
    pub machine_identifier: String,
    pub droid_volume_identifier: String,
    pub droid_file_identifier: String,
    pub birth_droid_volume_identifier: String,
    pub birth_droid_file_identifier: String,
    /// Timestamp embedded in the (version 1) droid file UUID.
    pub droid_file_time_ns: Option<i64>,
    pub birth_droid_file_time_ns: Option<i64>,
    /// MAC address embedded in the droid file UUID node field.
    pub droid_mac_address: Option<String>,
    pub birth_droid_mac_address: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PropertyValue {
    pub format_id: String,
    pub id: Value,
    pub vtype: u16,
    pub value: Value,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LnkFile {
    pub link_flags: u32,
    pub file_attribute_flags: u32,
    pub creation_ns: Option<i64>,
    pub access_ns: Option<i64>,
    pub modification_ns: Option<i64>,
    pub creation_filetime: u64,
    pub access_filetime: u64,
    pub modification_filetime: u64,
    pub file_size: u32,
    pub icon_index: i32,
    pub show_command: u32,
    pub hot_key: u16,
    pub target_id_list: Vec<ShellItem>,
    pub target_id_list_raw_hex: String,
    pub link_info: Option<LinkInfo>,
    pub description: Option<String>,
    pub relative_path: Option<String>,
    pub working_directory: Option<String>,
    pub command_line_arguments: Option<String>,
    pub icon_location: Option<String>,
    pub environment_variables_location: Option<String>,
    pub icon_environment_location: Option<String>,
    pub darwin_application_identifier: Option<String>,
    pub known_folder_id: Option<String>,
    pub special_folder_id: Option<u32>,
    pub shim_layer_name: Option<String>,
    pub console_code_page: Option<u32>,
    pub console: Option<BTreeMap<String, Value>>,
    pub tracker: Option<Tracker>,
    pub property_store: Vec<PropertyValue>,
    pub vista_id_list: Vec<ShellItem>,
    pub extra_block_signatures: Vec<String>,
    /// Non-fatal problems (truncated trailing blocks etc.).
    pub warnings: Vec<String>,
    /// Number of bytes consumed by the link (header through terminal block).
    pub size: usize,
}

impl LnkFile {
    /// Local path as libyal reports it: local base path + common path suffix.
    pub fn local_path(&self) -> Option<String> {
        let li = self.link_info.as_ref()?;
        let base = li.local_base_path.clone()?;
        let suffix = li.common_path_suffix.clone().unwrap_or_default();
        Some(join_suffix(&base, &suffix))
    }

    /// Network path: share name + common path suffix.
    pub fn network_path(&self) -> Option<String> {
        let li = self.link_info.as_ref()?;
        let share = li.network_share_name.clone()?;
        let suffix = li.common_path_suffix.clone().unwrap_or_default();
        Some(join_suffix(&share, &suffix))
    }

    pub fn target_path(&self) -> Option<String> {
        self.local_path()
            .or_else(|| self.network_path())
            .or_else(|| {
                if self.target_id_list.is_empty() {
                    None
                } else {
                    Some(shell_item_path(&self.target_id_list))
                }
            })
    }
}

fn join_suffix(base: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        base.to_string()
    } else if base.ends_with('\\') {
        format!("{base}{suffix}")
    } else {
        format!("{base}\\{suffix}")
    }
}

fn cstr_ansi(d: &[u8], o: usize) -> Option<String> {
    if o >= d.len() {
        return None;
    }
    let rest = &d[o..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    Some(decode_ansi(&rest[..end]))
}

fn cstr_utf16(d: &[u8], o: usize) -> Option<String> {
    if o >= d.len() {
        return None;
    }
    Some(utf16le(&d[o..], true))
}

/// Return true if the data starts with a Shell Link header.
pub fn is_lnk(data: &[u8]) -> bool {
    data.len() >= 20 && u32_at(data, 0).ok() == Some(0x4c) && data[4..20] == LNK_CLSID
}

/// Parse a .lnk file.
pub fn parse(data: &[u8]) -> Result<LnkFile> {
    let hs = u32_at(data, 0)?;
    let clsid = need(data, 4, 16)?;
    if hs != 0x4c || clsid != LNK_CLSID {
        return Err(ParseError::BadSignature {
            offset: 0,
            expected: "4c000000 + shell link CLSID".into(),
            found: hex::encode(&data[..20.min(data.len())]),
        });
    }
    need(data, 0, 76)?;
    let mut l = LnkFile {
        link_flags: u32_at(data, 20)?,
        file_attribute_flags: u32_at(data, 24)?,
        creation_filetime: u64_at(data, 28)?,
        access_filetime: u64_at(data, 36)?,
        modification_filetime: u64_at(data, 44)?,
        file_size: u32_at(data, 52)?,
        icon_index: u32_at(data, 56)? as i32,
        show_command: u32_at(data, 60)?,
        hot_key: u16_at(data, 64)?,
        ..Default::default()
    };
    l.creation_ns = filetime_to_ns(l.creation_filetime);
    l.access_ns = filetime_to_ns(l.access_filetime);
    l.modification_ns = filetime_to_ns(l.modification_filetime);
    let f = l.link_flags;
    let mut off = 76usize;
    if f & flags::HAS_TARGET_ID_LIST != 0 {
        let sz = u16_at(data, off)? as usize;
        let idl = need(data, off + 2, sz)?;
        l.target_id_list_raw_hex = hex::encode(idl);
        match parse_shell_item_list(idl) {
            Ok(items) => l.target_id_list = items,
            Err(e) => l.warnings.push(format!("target id list: {e}")),
        }
        off += 2 + sz;
    }
    if f & flags::HAS_LINK_INFO != 0 && f & flags::FORCE_NO_LINK_INFO == 0 {
        let sz = u32_at(data, off)? as usize;
        let li = need(data, off, sz)?;
        l.link_info = Some(parse_link_info(li)?);
        off += sz;
    } else if f & flags::HAS_LINK_INFO != 0 {
        let sz = u32_at(data, off)? as usize;
        need(data, off, sz)?;
        off += sz;
    }
    let unicode = f & flags::IS_UNICODE != 0;
    let read_string = |off: &mut usize| -> Result<String> {
        let n = u16_at(data, *off)? as usize;
        *off += 2;
        if unicode {
            let b = need(data, *off, n * 2)?;
            *off += n * 2;
            Ok(utf16le(b, false))
        } else {
            let b = need(data, *off, n)?;
            *off += n;
            Ok(decode_ansi(b))
        }
    };
    if f & flags::HAS_NAME != 0 {
        l.description = Some(read_string(&mut off)?);
    }
    if f & flags::HAS_RELATIVE_PATH != 0 {
        l.relative_path = Some(read_string(&mut off)?);
    }
    if f & flags::HAS_WORKING_DIR != 0 {
        l.working_directory = Some(read_string(&mut off)?);
    }
    if f & flags::HAS_ARGUMENTS != 0 {
        l.command_line_arguments = Some(read_string(&mut off)?);
    }
    if f & flags::HAS_ICON_LOCATION != 0 {
        l.icon_location = Some(read_string(&mut off)?);
    }
    l.size = parse_extra(data, off, &mut l);
    Ok(l)
}

fn parse_link_info(li: &[u8]) -> Result<LinkInfo> {
    let header_size = u32_at(li, 4)? as usize;
    let lflags = u32_at(li, 8)?;
    let vol_off = u32_at(li, 12)? as usize;
    let lbp_off = u32_at(li, 16)? as usize;
    let cnrl_off = u32_at(li, 20)? as usize;
    let cps_off = u32_at(li, 24)? as usize;
    let mut out = LinkInfo {
        flags: lflags,
        ..Default::default()
    };
    let (lbp_u, cps_u) = if header_size >= 0x24 {
        (
            u32_at(li, 28).ok().map(|v| v as usize),
            u32_at(li, 32).ok().map(|v| v as usize),
        )
    } else {
        (None, None)
    };
    if lflags & 0x1 != 0 {
        if vol_off > 0 && vol_off < li.len() {
            let v = &li[vol_off..];
            let vsize = u32_at(v, 0)? as usize;
            let v = need(v, 0, vsize.min(v.len()))?;
            out.drive_type = u32_at(v, 4).ok();
            out.drive_serial_number = u32_at(v, 8).ok();
            let lab_off = u32_at(v, 12).unwrap_or(0) as usize;
            out.volume_label = if lab_off == 0x14 {
                u32_at(v, 16).ok().and_then(|o| cstr_utf16(v, o as usize))
            } else {
                cstr_ansi(v, lab_off)
            };
        }
        out.local_base_path = match lbp_u {
            Some(o) if o > 0 => cstr_utf16(li, o),
            _ => {
                if lbp_off > 0 {
                    cstr_ansi(li, lbp_off)
                } else {
                    None
                }
            }
        };
    }
    if lflags & 0x2 != 0 && cnrl_off > 0 && cnrl_off < li.len() {
        let c = &li[cnrl_off..];
        let csize = (u32_at(c, 0)? as usize).min(c.len());
        let c = &c[..csize];
        let cflags = u32_at(c, 4).unwrap_or(0);
        let net_off = u32_at(c, 8).unwrap_or(0) as usize;
        let dev_off = u32_at(c, 12).unwrap_or(0) as usize;
        out.network_provider_type = if cflags & 0x2 != 0 {
            u32_at(c, 16).ok()
        } else {
            None
        };
        if net_off > 0x14 {
            out.network_share_name = u32_at(c, 20).ok().and_then(|o| cstr_utf16(c, o as usize));
            if cflags & 0x1 != 0 {
                out.device_name = u32_at(c, 24).ok().and_then(|o| cstr_utf16(c, o as usize));
            }
        } else {
            out.network_share_name = cstr_ansi(c, net_off);
            if cflags & 0x1 != 0 && dev_off > 0 {
                out.device_name = cstr_ansi(c, dev_off);
            }
        }
    }
    out.common_path_suffix = match cps_u {
        Some(o) if o > 0 => cstr_utf16(li, o),
        _ => {
            if cps_off > 0 {
                cstr_ansi(li, cps_off)
            } else {
                None
            }
        }
    };
    Ok(out)
}

fn uuid_time_ns(g: &[u8]) -> Option<i64> {
    if g.len() < 16 {
        return None;
    }
    let version = g[7] >> 4;
    if version != 1 {
        return None;
    }
    let low = u32::from_le_bytes([g[0], g[1], g[2], g[3]]) as u64;
    let mid = u16::from_le_bytes([g[4], g[5]]) as u64;
    let hi = (u16::from_le_bytes([g[6], g[7]]) & 0x0fff) as u64;
    let ts = (hi << 48) | (mid << 32) | low;
    let rel = ts.checked_sub(0x01b2_1dd2_1381_4000)? as i64;
    rel.checked_mul(100)
}

fn uuid_mac(g: &[u8]) -> Option<String> {
    if g.len() < 16 || g[7] >> 4 != 1 {
        return None;
    }
    Some(
        g[10..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn parse_extra(data: &[u8], mut off: usize, l: &mut LnkFile) -> usize {
    let mut count = 0;
    while let Ok(size) = u32_at(data, off) {
        let size = size as usize;
        if size < 4 {
            off += 4;
            break;
        }
        count += 1;
        if count > MAX_EXTRA_BLOCKS {
            l.warnings.push("too many extra data blocks".into());
            break;
        }
        let b = match need(data, off, size) {
            Ok(b) => b,
            Err(e) => {
                l.warnings.push(format!("extra data block at {off}: {e}"));
                break;
            }
        };
        let sig = u32_at(b, 4).unwrap_or(0);
        l.extra_block_signatures.push(format!("0x{sig:08x}"));
        match sig {
            0xa0000001 | 0xa0000007 | 0xa0000006 => {
                let ansi = cstr_ansi(b, 8).filter(|s| !s.is_empty());
                let uni = need(b, 268, 520)
                    .ok()
                    .map(|u| utf16le(u, true))
                    .filter(|s| !s.is_empty());
                let v = uni.or(ansi);
                match sig {
                    0xa0000001 => l.environment_variables_location = v,
                    0xa0000007 => l.icon_environment_location = v,
                    _ => l.darwin_application_identifier = v,
                }
            }
            0xa0000002 => {
                let mut m = BTreeMap::new();
                for (k, o) in [("fill_attributes", 8usize), ("popup_fill_attributes", 10)] {
                    if let Ok(v) = u16_at(b, o) {
                        m.insert(k.to_string(), json!(v));
                    }
                }
                for (k, o) in [
                    ("screen_buffer_size_x", 12usize),
                    ("screen_buffer_size_y", 14),
                    ("window_size_x", 16),
                    ("window_size_y", 18),
                ] {
                    if let Ok(v) = u16_at(b, o) {
                        m.insert(k.to_string(), json!(v));
                    }
                }
                if let Ok(fb) = need(b, 44, 64) {
                    m.insert("face_name".into(), json!(utf16le(fb, true)));
                }
                l.console = Some(m);
            }
            0xa0000004 => l.console_code_page = u32_at(b, 8).ok(),
            0xa0000003 => {
                let g = |o| need(b, o, 16).ok();
                l.tracker = Some(Tracker {
                    machine_identifier: need(b, 16, 16)
                        .map(|m| decode_ansi(&m[..m.iter().position(|&c| c == 0).unwrap_or(16)]))
                        .unwrap_or_default(),
                    droid_volume_identifier: g(32).and_then(guid_string).unwrap_or_default(),
                    droid_file_identifier: g(48).and_then(guid_string).unwrap_or_default(),
                    birth_droid_volume_identifier: g(64).and_then(guid_string).unwrap_or_default(),
                    birth_droid_file_identifier: g(80).and_then(guid_string).unwrap_or_default(),
                    droid_file_time_ns: g(48).and_then(uuid_time_ns),
                    birth_droid_file_time_ns: g(80).and_then(uuid_time_ns),
                    droid_mac_address: g(48).and_then(uuid_mac),
                    birth_droid_mac_address: g(80).and_then(uuid_mac),
                });
            }
            0xa0000005 => l.special_folder_id = u32_at(b, 8).ok(),
            0xa0000008 => {
                l.shim_layer_name = need(b, 8, b.len() - 8).ok().map(|s| utf16le(s, true))
            }
            0xa000000b => l.known_folder_id = need(b, 8, 16).ok().and_then(guid_string),
            0xa0000009 => {
                if let Ok(ps) = need(b, 8, b.len() - 8) {
                    l.property_store = parse_property_store(ps);
                }
            }
            0xa000000c => {
                if let Ok(idl) = need(b, 8, b.len() - 8) {
                    l.vista_id_list = parse_shell_item_list(idl).unwrap_or_default();
                }
            }
            _ => {}
        }
        off += size;
    }
    off.min(data.len())
}

/// Parse a sequence of serialized property storage structures (MS-PROPSTORE).
pub fn parse_property_store(d: &[u8]) -> Vec<PropertyValue> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 24 <= d.len() && out.len() < MAX_PROPS {
        let ssize = match u32_at(d, off) {
            Ok(s) => s as usize,
            Err(_) => break,
        };
        if ssize < 24 || off + ssize > d.len() {
            break;
        }
        let st = &d[off..off + ssize];
        if u32_at(st, 4).ok() != Some(0x5350_5331) {
            break;
        }
        let fmt = guid_string(&st[8..24]).unwrap_or_default();
        let named = fmt == "d5cdd505-2e9c-101b-9397-08002b2cf9ae";
        let mut p = 24usize;
        while p + 4 <= st.len() && out.len() < MAX_PROPS {
            let vsize = u32_at(st, p).unwrap_or(0) as usize;
            if vsize < 9 || p + vsize > st.len() {
                break;
            }
            let v = &st[p..p + vsize];
            let (id, typed_off) = if named {
                let nsize = u32_at(v, 4).unwrap_or(0) as usize;
                let name = need(v, 9, nsize)
                    .map(|n| utf16le(n, true))
                    .unwrap_or_default();
                (json!(name), 9 + nsize)
            } else {
                (json!(u32_at(v, 4).unwrap_or(0)), 9)
            };
            let vtype = u16_at(v, typed_off).unwrap_or(0);
            let value = typed_value(v, typed_off + 4, vtype);
            out.push(PropertyValue {
                format_id: fmt.clone(),
                id,
                vtype,
                value,
            });
            p += vsize;
        }
        off += ssize;
    }
    out
}

fn typed_value(v: &[u8], o: usize, vtype: u16) -> Value {
    match vtype {
        0x1f | 0x08 => {
            let n = u32_at(v, o).unwrap_or(0) as usize;
            let b = need(v, o + 4, n.saturating_mul(2)).unwrap_or(&v[(o + 4).min(v.len())..]);
            json!(utf16le(b, true))
        }
        0x1e => {
            let n = u32_at(v, o).unwrap_or(0) as usize;
            json!(need(v, o + 4, n)
                .map(|b| decode_ansi(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]))
                .unwrap_or_default())
        }
        0x13 | 0x17 => json!(u32_at(v, o).unwrap_or(0)),
        0x03 | 0x16 => json!(u32_at(v, o).unwrap_or(0) as i32),
        0x02 => json!(u16_at(v, o).unwrap_or(0) as i16),
        0x12 => json!(u16_at(v, o).unwrap_or(0)),
        0x0b => json!(u16_at(v, o).unwrap_or(0) != 0),
        0x15 => json!(u64_at(v, o).unwrap_or(0)),
        0x14 => json!(u64_at(v, o).unwrap_or(0) as i64),
        0x40 => {
            let ft = u64_at(v, o).unwrap_or(0);
            json!({"filetime": ft, "ns": filetime_to_ns(ft)})
        }
        0x48 => json!(need(v, o, 16).ok().and_then(guid_string)),
        _ => json!({"hex": hex::encode(&v[o.min(v.len())..v.len().min(o + 64)])}),
    }
}

fn opt(v: &Option<String>) -> Value {
    match v {
        Some(s) => json!(s),
        None => Value::Null,
    }
}

/// Attributes shared by all events derived from one link (also used for jump-list entries).
pub fn link_attrs(l: &LnkFile) -> BTreeMap<String, Value> {
    let mut a = BTreeMap::new();
    a.insert("description".into(), opt(&l.description));
    a.insert("relative_path".into(), opt(&l.relative_path));
    a.insert("working_directory".into(), opt(&l.working_directory));
    a.insert(
        "command_line_arguments".into(),
        opt(&l.command_line_arguments),
    );
    a.insert("icon_location".into(), opt(&l.icon_location));
    a.insert(
        "env_var_location".into(),
        opt(&l.environment_variables_location),
    );
    a.insert("local_path".into(), opt(&l.local_path()));
    a.insert("network_path".into(), opt(&l.network_path()));
    a.insert("file_size".into(), json!(l.file_size));
    a.insert("file_attribute_flags".into(), json!(l.file_attribute_flags));
    a.insert("link_flags".into(), json!(l.link_flags));
    if let Some(li) = &l.link_info {
        a.insert("drive_type".into(), json!(li.drive_type));
        a.insert("drive_serial_number".into(), json!(li.drive_serial_number));
        a.insert("volume_label".into(), opt(&li.volume_label));
    }
    if !l.target_id_list.is_empty() {
        a.insert(
            "link_target".into(),
            json!(shell_item_path(&l.target_id_list)),
        );
    }
    if let Some(t) = &l.tracker {
        a.insert("machine_identifier".into(), json!(t.machine_identifier));
        a.insert(
            "droid_volume_identifier".into(),
            json!(t.droid_volume_identifier),
        );
        a.insert(
            "droid_file_identifier".into(),
            json!(t.droid_file_identifier),
        );
        a.insert(
            "birth_droid_volume_identifier".into(),
            json!(t.birth_droid_volume_identifier),
        );
        a.insert(
            "birth_droid_file_identifier".into(),
            json!(t.birth_droid_file_identifier),
        );
        a.insert("droid_mac_address".into(), opt(&t.droid_mac_address));
    }
    if let Some(k) = &l.known_folder_id {
        a.insert("known_folder_identifier".into(), json!(k));
    }
    a
}

fn link_message(l: &LnkFile) -> String {
    let mut parts = Vec::new();
    if let Some(d) = &l.description {
        parts.push(format!("[{d}]"));
    }
    parts.push(format!("File size: {}", l.file_size));
    if let Some(p) = l.local_path() {
        parts.push(format!("Local path: {p}"));
    }
    if let Some(p) = l.network_path() {
        parts.push(format!("Network path: {p}"));
    }
    if let Some(p) = &l.command_line_arguments {
        parts.push(format!("cmd arguments: {p}"));
    }
    if let Some(p) = &l.environment_variables_location {
        parts.push(format!("env location: {p}"));
    }
    if let Some(p) = &l.relative_path {
        parts.push(format!("Relative path: {p}"));
    }
    if let Some(p) = &l.working_directory {
        parts.push(format!("Working dir: {p}"));
    }
    if let Some(p) = &l.icon_location {
        parts.push(format!("Icon location: {p}"));
    }
    if !l.target_id_list.is_empty() {
        parts.push(format!(
            "Link target: {}",
            shell_item_path(&l.target_id_list)
        ));
    }
    parts.join(" ")
}

/// Timeline events for a link file. `offset` is the byte offset of the link inside its container.
pub fn events(l: &LnkFile, evidence_sha256: &str, evidence_path: &str, offset: i64) -> Vec<Event> {
    let attrs = link_attrs(l);
    let msg = link_message(l);
    let mut out = Vec::new();
    let times = [
        (l.creation_ns, desc::CREATION),
        (l.modification_ns, desc::MODIFICATION),
        (l.access_ns, desc::ACCESS),
    ];
    let mut any = false;
    for (t, d) in times {
        if t.is_some() {
            any = true;
            out.push(mk(
                Event::new("windows:lnk:link", d, msg.clone()).with_time(t),
                &attrs,
                evidence_sha256,
                evidence_path,
                offset,
            ));
        }
    }
    if !any {
        out.push(mk(
            Event::new("windows:lnk:link", desc::NOT_A_TIME, msg.clone()),
            &attrs,
            evidence_sha256,
            evidence_path,
            offset,
        ));
    }
    if let Some(t) = &l.tracker {
        for (ts, file_id, vol_id, mac) in [
            (
                t.droid_file_time_ns,
                &t.droid_file_identifier,
                &t.droid_volume_identifier,
                &t.droid_mac_address,
            ),
            (
                t.birth_droid_file_time_ns,
                &t.birth_droid_file_identifier,
                &t.birth_droid_volume_identifier,
                &t.birth_droid_mac_address,
            ),
        ] {
            if ts.is_none() {
                continue;
            }
            let m = format!(
                "{} MAC address: {} Origin: {}",
                file_id,
                mac.clone().unwrap_or_default(),
                l.target_path().unwrap_or_default()
            );
            let e = Event::new(
                "windows:distributed_link_tracking:creation",
                desc::CREATION,
                m,
            )
            .with_time(ts)
            .attr("uuid", file_id.clone())
            .attr(
                "mac_address",
                mac.clone().map(Value::from).unwrap_or(Value::Null),
            )
            .attr("droid_volume_identifier", vol_id.clone())
            .attr("machine_identifier", t.machine_identifier.clone());
            let e = finish(e, evidence_sha256, evidence_path, offset);
            if !out.iter().any(|x: &Event| {
                x.data_type == e.data_type
                    && x.timestamp == e.timestamp
                    && x.attrs.get("uuid") == e.attrs.get("uuid")
            }) {
                out.push(e);
            }
        }
    }
    out
}

fn mk(mut e: Event, attrs: &BTreeMap<String, Value>, sha: &str, path: &str, offset: i64) -> Event {
    for (k, v) in attrs {
        e.attrs.insert(k.clone(), v.clone());
    }
    finish(e, sha, path, offset)
}

fn finish(mut e: Event, sha: &str, path: &str, offset: i64) -> Event {
    e.source_short = "LNK".into();
    e.source_long = "Windows Shortcut".into();
    e.provenance(sha, path, offset, "lnk", crate::PARSER_VERSION)
}
