//! Windows shell item (ITEMIDLIST) parser, MS-SHLLINK section 2.2 plus the undocumented
//! shell item classes described by libfwsi. Shared with the registry ShellBags parser.
//!
//! Contract (shared with `registry`): [`parse_shell_item_list`], [`ShellItem`],
//! [`ExtensionBlock`], [`shell_item_path`].
use crate::error::{ParseError, Result};
use crate::util::{need, u16_at, u32_at, u64_at, u8_at, utf16le};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use veritas_timeline::{fat_datetime_to_ns, filetime_to_ns};

/// Upper bound on the number of items in one ID list.
const MAX_ITEMS: usize = 4096;
/// Upper bound on extension blocks per item.
const MAX_EXT_BLOCKS: usize = 64;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShellItem {
    pub item_type: String,
    pub name: String,
    pub long_name: Option<String>,
    pub modification_ns: Option<i64>,
    pub creation_ns: Option<i64>,
    pub access_ns: Option<i64>,
    pub mft_entry: Option<u64>,
    pub mft_sequence: Option<u16>,
    pub class_id: Option<String>,
    pub raw_size: usize,
    pub extension_blocks: Vec<ExtensionBlock>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtensionBlock {
    pub signature: u32,
    pub version: u16,
    pub fields: BTreeMap<String, Value>,
}

impl ShellItem {
    fn new(item_type: &str, raw_size: usize) -> Self {
        ShellItem {
            item_type: item_type.to_string(),
            name: String::new(),
            long_name: None,
            modification_ns: None,
            creation_ns: None,
            access_ns: None,
            mft_entry: None,
            mft_sequence: None,
            class_id: None,
            raw_size,
            extension_blocks: Vec::new(),
        }
    }

    /// Display name: long name when present, else the primary name.
    pub fn display_name(&self) -> &str {
        match &self.long_name {
            Some(l) if !l.is_empty() => l,
            _ => &self.name,
        }
    }
}

/// Format a little-endian Windows GUID as lowercase `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
pub fn guid_string(b: &[u8]) -> Option<String> {
    if b.len() < 16 {
        return None;
    }
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ))
}

/// Known shell folder / known folder identifiers (CLSID and FOLDERID values).
pub const KNOWN_FOLDERS: &[(&str, &str)] = &[
    ("031e4825-7b94-4dc3-b131-e946b44c8dd5", "Libraries"),
    ("04731b67-d933-450a-90e6-4acd2e9408fe", "Search Folder"),
    ("088e3905-0323-4b02-9826-5d99428e115f", "Downloads"),
    ("0ac0837c-bbf8-452a-850d-79d08e667ca7", "Computer"),
    ("1ac14e77-02e7-4e5d-b744-2eb1ae5198b7", "System32"),
    ("1cf1260c-4dd0-4ebb-811f-33c572699fde", "Music"),
    (
        "1f4de370-d627-11d1-ba4f-00a0c91eedba",
        "Search Results - Computers",
    ),
    ("18989b1d-99b5-455b-841c-ab7c74e4ddfc", "Videos"),
    ("208d2c60-3aea-1069-a2d7-08002b30309d", "My Network Places"),
    ("20d04fe0-3aea-1069-a2d8-08002b30309d", "My Computer"),
    ("21ec2020-3aea-1069-a2dd-08002b30309d", "Control Panel"),
    ("2227a280-3aea-1069-a2de-08002b30309d", "Printers"),
    ("22877a6d-37a1-461a-91b0-dbda5aaebc99", "Recent Places"),
    ("24ad3ad4-a569-4530-98e1-ab02f9417aa8", "Pictures"),
    ("2559a1f2-21d7-11d4-bdaf-00c04f60b9f0", "Help and Support"),
    ("2559a1f3-21d7-11d4-bdaf-00c04f60b9f0", "Run"),
    ("2559a1f4-21d7-11d4-bdaf-00c04f60b9f0", "Search"),
    ("26ee0668-a00a-44d7-9371-beb064c98683", "Control Panel"),
    ("323ca680-c24d-4099-b94d-446dd2d7249e", "Favorites"),
    ("33e28130-4e1e-4676-835a-98395c3bc3bb", "Pictures"),
    ("35786d3c-b075-49b9-88dd-029876e11c01", "Portable Devices"),
    ("374de290-123f-4565-9164-39c4925e467b", "Downloads"),
    ("3add1653-eb32-4cb0-bbd7-dfa0abb5acca", "Pictures"),
    ("3dfdf296-dbec-4fb4-81d1-6a3438bcf4de", "Music"),
    ("3eb685db-65f9-4cf6-a03a-e3ef65729f3d", "AppData Roaming"),
    ("4234d49b-0245-4df3-b780-3893943456e1", "Applications"),
    ("450d8fba-ad25-11d0-98a8-0800361b1103", "My Documents"),
    ("4bd8d571-6d19-48d3-be97-422220080e43", "Music"),
    ("4c5c32ff-bb9d-43b0-b5b4-2d72e54eaaa4", "Saved Games"),
    ("56784854-c6cb-462b-8169-88e350acb882", "Contacts"),
    ("59031a47-3f72-44a7-89c5-5595fe6b30ee", "Users Files"),
    ("5399e694-6ce5-4d6c-8fce-1d8870fdcba0", "Control Panel Home"),
    ("5e6c858f-0e22-4760-9afe-ea3317b67173", "User Profile"),
    ("625b53c3-ab48-4ec1-ba1f-a1ef4146fc19", "Start Menu"),
    ("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97", "ProgramData"),
    ("645ff040-5081-101b-9f08-00aa002f954e", "Recycle Bin"),
    ("679f85cb-0220-4080-b29b-5540cc05aab6", "Quick Access"),
    (
        "7b81be6a-ce2b-4676-a29e-eb907a5126c5",
        "Programs and Features",
    ),
    (
        "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e",
        "Program Files (x86)",
    ),
    ("82a5ea35-d9cd-47c5-9629-e15d2f714e6e", "Common Startup"),
    ("871c5380-42a0-1069-a2ea-08002b30309d", "Internet Explorer"),
    ("8983036c-27c0-404b-8f08-102d10dcfd74", "SendTo"),
    ("905e63b6-c1bf-494e-b29c-65b732d3d21a", "Program Files"),
    ("9e3995ab-1f9c-4f13-b827-48b24b6c7174", "User Pinned"),
    ("a0953c92-50dc-43bf-be83-3742fed03c9c", "Videos"),
    (
        "a00ee528-ebd9-48b8-944a-8942113d46ac",
        "Start Menu Commanding",
    ),
    ("a77f5d77-2e2b-44c3-a6a2-aba601054a51", "Programs"),
    ("a8cdff1c-4878-43be-b5fd-f8091c1c60d0", "Documents"),
    ("ae50c081-ebd2-438a-8655-8a092e34987a", "Recent Items"),
    ("b4bfcc3a-db2c-424c-b029-7fe99a87c641", "Desktop"),
    ("b4fb3f98-c1ea-428d-a78a-d1f5659cba93", "Other Users Folder"),
    ("b7534046-3ecb-4c18-be4e-64cd4cb7d6ac", "Recycle Bin"),
    ("b97d20bb-f46a-4c97-ba10-5e3608430854", "Startup"),
    ("bfb9d5e0-c6a9-404c-b2b2-ae6db6af4968", "Links"),
    ("c4900540-2379-4c75-844b-64e6faf8716b", "Sample Pictures"),
    ("d20beec4-5ca8-4905-ae3b-bf251ea09b53", "Network"),
    ("d3162b92-9365-467a-956b-92703aca08af", "Documents"),
    (
        "d34a6ca6-62c2-4c34-8a7c-14709c1ad938",
        "Common Places FS Folder",
    ),
    (
        "dffacdc5-679f-4156-8947-c5c76bc0b67f",
        "Delegate folder in Users Files",
    ),
    ("e17d4fc0-5564-11d1-83f2-00a0c90dc849", "Search Results"),
    ("ed228fdf-9ea8-4870-83b1-96b02cfe0d52", "Games"),
    ("f02c1a0d-be21-4350-88b0-7367fc96ef3c", "Network"),
    ("f1b32785-6fba-4fcf-9d55-7b8e7f157091", "AppData Local"),
    ("f38bf404-1d43-42f2-9305-67de0b28fc23", "Windows"),
    ("f3ce0f7c-4901-4acc-8648-d5d44b04ef8f", "Users Files"),
    ("f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a", "Videos"),
    ("f874310e-b6b7-47dc-bc84-b9e6b38f5903", "Home"),
    ("fdd39ad0-238f-46af-adb4-6c85480369c7", "Documents"),
];

/// Look up a known folder name by lowercase GUID string.
pub fn known_folder_name(guid: &str) -> Option<&'static str> {
    let g = guid.to_ascii_lowercase();
    KNOWN_FOLDERS.iter().find(|(k, _)| *k == g).map(|(_, v)| *v)
}

fn fat_pair(d: &[u8], o: usize) -> Option<i64> {
    let date = u16_at(d, o).ok()?;
    let time = u16_at(d, o + 2).ok()?;
    if date == 0 && time == 0 {
        return None;
    }
    fat_datetime_to_ns(date, time, 0)
}

/// Read a NUL-terminated UTF-16LE string starting at `o`; returns (string, bytes consumed incl. NUL).
fn utf16z(d: &[u8], o: usize) -> (String, usize) {
    if o >= d.len() {
        return (String::new(), 0);
    }
    let rest = &d[o..];
    let mut end = rest.len() & !1;
    let mut i = 0;
    while i + 1 < rest.len() {
        if rest[i] == 0 && rest[i + 1] == 0 {
            end = i;
            break;
        }
        i += 2;
    }
    let consumed = if end + 2 <= rest.len() { end + 2 } else { end };
    (utf16le(&rest[..end], false), consumed)
}

/// Read a NUL-terminated 8-bit string at `o`; returns (string, bytes consumed incl. NUL).
fn asciiz(d: &[u8], o: usize) -> (String, usize) {
    if o >= d.len() {
        return (String::new(), 0);
    }
    let rest = &d[o..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let s = decode_ansi(&rest[..end]);
    (s, (end + 1).min(rest.len()))
}

/// Windows-1252 decode (the common OEM/ANSI code page in the corpus).
pub fn decode_ansi(b: &[u8]) -> String {
    let (s, _, _) = encoding_rs::WINDOWS_1252.decode(b);
    s.into_owned()
}

/// Parse a shell item ID list (sequence of `u16 size` prefixed items, terminated by size 0).
pub fn parse_shell_item_list(data: &[u8]) -> Result<Vec<ShellItem>> {
    let mut items = Vec::new();
    let mut off = 0usize;
    while off + 2 <= data.len() {
        let size = u16_at(data, off)? as usize;
        if size == 0 {
            break;
        }
        if size < 3 {
            return Err(ParseError::Invalid {
                offset: off,
                reason: format!("shell item size {size} too small"),
            });
        }
        let raw = need(data, off, size)?;
        items.push(parse_shell_item(raw)?);
        if items.len() >= MAX_ITEMS {
            return Err(ParseError::Limit(format!(
                "more than {MAX_ITEMS} shell items"
            )));
        }
        off += size;
    }
    Ok(items)
}

/// Parse one shell item (including its 2-byte size prefix).
pub fn parse_shell_item(d: &[u8]) -> Result<ShellItem> {
    let size = d.len();
    let class = u8_at(d, 2)?;
    let mut item = match class {
        0x1f => root_folder(d),
        0x20..=0x2f => volume(d, class),
        0x30..=0x3f => file_entry(d, class)?,
        0x40..=0x4f => network(d),
        0x52 => {
            let mut it = ShellItem::new("compressed_folder", size);
            it.name = "<compressed folder>".into();
            it
        }
        0x61 => uri(d),
        0x71 => control_panel(d),
        0x74 => delegate(d)?,
        0x00 | 0x01 => users_property_view(d, class),
        _ => unknown(d, class),
    };
    item.raw_size = size;
    Ok(item)
}

fn root_folder(d: &[u8]) -> ShellItem {
    let mut it = ShellItem::new("root_folder", d.len());
    if let Ok(g) = need(d, 4, 16) {
        if let Some(gs) = guid_string(g) {
            it.name = known_folder_name(&gs)
                .map(|n| n.to_string())
                .unwrap_or_else(|| format!("{{{gs}}}"));
            it.class_id = Some(gs);
        }
    }
    if d.len() > 20 {
        it.extension_blocks = parse_extension_blocks(d, 20);
    }
    it
}

fn volume(d: &[u8], class: u8) -> ShellItem {
    let mut it = ShellItem::new("volume", d.len());
    if class & 0x01 != 0 {
        let (s, _) = asciiz(d, 3);
        it.name = s;
    } else if d.len() >= 20 {
        // Volume shell item carrying a class identifier (e.g. removable media).
        if let Some(g) = need(d, 4, 16).ok().and_then(guid_string) {
            it.name = known_folder_name(&g)
                .map(|n| n.to_string())
                .unwrap_or_else(|| format!("{{{g}}}"));
            it.class_id = Some(g);
        }
    }
    it
}

fn file_entry(d: &[u8], class: u8) -> Result<ShellItem> {
    let kind = if class & 0x01 != 0 {
        "directory"
    } else if class & 0x02 != 0 {
        "file"
    } else {
        "file_entry"
    };
    let mut it = ShellItem::new(kind, d.len());
    if d.len() < 14 {
        return Ok(it);
    }
    it.modification_ns = fat_pair(d, 8);
    let unicode = class & 0x04 != 0;
    let (name, consumed) = if unicode {
        utf16z(d, 14)
    } else {
        asciiz(d, 14)
    };
    it.name = name;
    let mut next = 14 + consumed;
    if next % 2 == 1 {
        next += 1;
    }
    if next < d.len() {
        it.extension_blocks = parse_extension_blocks(d, next);
    }
    apply_beef0004(&mut it);
    Ok(it)
}

fn apply_beef0004(it: &mut ShellItem) {
    if let Some(b) = it
        .extension_blocks
        .iter()
        .find(|b| b.signature == 0xbeef0004)
    {
        if let Some(v) = b.fields.get("creation_ns").and_then(|v| v.as_i64()) {
            it.creation_ns = Some(v);
        }
        if let Some(v) = b.fields.get("access_ns").and_then(|v| v.as_i64()) {
            it.access_ns = Some(v);
        }
        if let Some(v) = b.fields.get("mft_entry").and_then(|v| v.as_u64()) {
            it.mft_entry = Some(v);
        }
        if let Some(v) = b.fields.get("mft_sequence").and_then(|v| v.as_u64()) {
            it.mft_sequence = Some(v as u16);
        }
        if let Some(v) = b.fields.get("long_name").and_then(|v| v.as_str()) {
            it.long_name = Some(v.to_string());
        }
    }
}

fn network(d: &[u8]) -> ShellItem {
    let mut it = ShellItem::new("network_location", d.len());
    let flags = u8_at(d, 3).unwrap_or(0);
    let (loc, c1) = asciiz(d, 5);
    it.name = loc;
    let mut o = 5 + c1;
    let mut f = BTreeMap::new();
    if flags & 0x80 != 0 {
        let (desc, c) = asciiz(d, o);
        f.insert("description".to_string(), Value::from(desc));
        o += c;
    }
    if flags & 0x40 != 0 {
        let (com, _) = asciiz(d, o);
        f.insert("comments".to_string(), Value::from(com));
    }
    f.insert("flags".to_string(), Value::from(flags));
    it.extension_blocks.push(ExtensionBlock {
        signature: 0,
        version: 0,
        fields: f,
    });
    it
}

fn uri(d: &[u8]) -> ShellItem {
    let mut it = ShellItem::new("uri", d.len());
    let flags = u8_at(d, 3).unwrap_or(0);
    let data_size = u16_at(d, 4).unwrap_or(0) as usize;
    let unicode = flags & 0x80 != 0;
    let start = if data_size == 0 { 6 } else { 6 + data_size };
    if data_size >= 0x24 {
        // Data: unknown(4) unknown(4) FILETIME(8) ...
        if let Ok(ft) = u64_at(d, 14) {
            it.modification_ns = filetime_to_ns(ft);
        }
    }
    let probe = if start < d.len() { start } else { 6 };
    let (s, _) = if unicode {
        utf16z(d, probe)
    } else {
        asciiz(d, probe)
    };
    it.name = s;
    it
}

fn control_panel(d: &[u8]) -> ShellItem {
    let mut it = ShellItem::new("control_panel", d.len());
    if let Some(g) = need(d, 14, 16).ok().and_then(guid_string) {
        it.name = known_folder_name(&g)
            .map(|n| n.to_string())
            .unwrap_or_else(|| format!("{{{g}}}"));
        it.class_id = Some(g);
    }
    it
}

fn delegate(d: &[u8]) -> Result<ShellItem> {
    // 0x74: u16 inner size at 4, "CFSF" at 6, inner (sub) shell item at 10.
    let mut it = ShellItem::new("delegate", d.len());
    if need(d, 6, 4).map(|s| s == b"CFSF").unwrap_or(false) {
        let inner_size = u16_at(d, 10).unwrap_or(0) as usize;
        if inner_size >= 3 {
            if let Ok(inner) = need(d, 10, inner_size) {
                // Inner item: size(2) class(1) unknown(1) filesize(4) fat(4) attrs(2) name...
                let class = u8_at(inner, 2).unwrap_or(0x31);
                if let Ok(fe) = file_entry(inner, class | 0x30) {
                    it.name = fe.name;
                    it.modification_ns = fe.modification_ns;
                }
            }
            let after = 10 + inner_size;
            // delegate item identifier GUID + item class identifier GUID
            if let Some(g) = need(d, after + 16, 16).ok().and_then(guid_string) {
                it.class_id = Some(g);
            }
            let ext_start = after + 32;
            if ext_start < d.len() {
                it.extension_blocks = parse_extension_blocks(d, ext_start);
            }
            apply_beef0004(&mut it);
        }
    } else {
        it.item_type = "unknown".into();
        it.name = format!("<unknown 0x74 {}>", hex::encode(&d[..d.len().min(64)]));
    }
    Ok(it)
}

fn users_property_view(d: &[u8], class: u8) -> ShellItem {
    let mut it = ShellItem::new(
        if class == 0x01 {
            "control_panel_category"
        } else {
            "users_property_view"
        },
        d.len(),
    );
    if class == 0x01 {
        let cat = u32_at(d, 8).unwrap_or(0);
        it.name = format!("<control panel category {cat}>");
        return it;
    }
    let sig = u32_at(d, 6).unwrap_or(0);
    let mut f = BTreeMap::new();
    f.insert("signature".to_string(), Value::from(format!("0x{sig:08x}")));
    // Known folder GUIDs frequently follow at 14 (0x23febbee) or the property store.
    if let Some(g) = need(d, 14, 16).ok().and_then(guid_string) {
        if let Some(n) = known_folder_name(&g) {
            it.name = n.to_string();
            it.class_id = Some(g);
        }
    }
    if it.name.is_empty() {
        it.name = format!("<users property view 0x{sig:08x}>");
    }
    f.insert(
        "hex".to_string(),
        Value::from(hex::encode(&d[..d.len().min(256)])),
    );
    it.extension_blocks.push(ExtensionBlock {
        signature: 0,
        version: 0,
        fields: f,
    });
    it
}

fn unknown(d: &[u8], class: u8) -> ShellItem {
    let mut it = ShellItem::new("unknown", d.len());
    it.name = format!("<unknown 0x{class:02x}>");
    let mut f = BTreeMap::new();
    f.insert("class_type".to_string(), Value::from(class));
    f.insert(
        "hex".to_string(),
        Value::from(hex::encode(&d[..d.len().min(256)])),
    );
    it.extension_blocks.push(ExtensionBlock {
        signature: 0,
        version: 0,
        fields: f,
    });
    it
}

/// Parse a run of extension blocks starting at `start` inside item `d`.
pub fn parse_extension_blocks(d: &[u8], start: usize) -> Vec<ExtensionBlock> {
    let mut out = Vec::new();
    let mut o = start;
    while o + 8 <= d.len() && out.len() < MAX_EXT_BLOCKS {
        let size = match u16_at(d, o) {
            Ok(s) => s as usize,
            Err(_) => break,
        };
        if size < 8 || o + size > d.len() {
            break;
        }
        let version = u16_at(d, o + 2).unwrap_or(0);
        let sig = u32_at(d, o + 4).unwrap_or(0);
        if sig & 0xffff_0000 != 0xbeef_0000 {
            break;
        }
        let b = &d[o..o + size];
        out.push(ExtensionBlock {
            signature: sig,
            version,
            fields: ext_fields(b, sig, version),
        });
        o += size;
    }
    out
}

fn ins(f: &mut BTreeMap<String, Value>, k: &str, v: impl Into<Value>) {
    f.insert(k.to_string(), v.into());
}

fn ext_fields(b: &[u8], sig: u32, version: u16) -> BTreeMap<String, Value> {
    let mut f = BTreeMap::new();
    match sig {
        0xbeef0004 => {
            if let Some(t) = fat_pair(b, 8) {
                ins(&mut f, "creation_ns", t);
            }
            if let Some(t) = fat_pair(b, 12) {
                ins(&mut f, "access_ns", t);
            }
            let mut o = 18usize;
            if version >= 7 {
                if let Ok(r) = u64_at(b, 20) {
                    ins(&mut f, "file_reference", r);
                    ins(&mut f, "mft_entry", r & 0x0000_ffff_ffff_ffff);
                    ins(&mut f, "mft_sequence", r >> 48);
                }
                o = 36;
            }
            let mut long_string_size = 0u16;
            if version >= 3 {
                long_string_size = u16_at(b, o).unwrap_or(0);
                o += 2;
            }
            if version >= 9 {
                o += 4;
            }
            if version >= 8 {
                o += 4;
            }
            let (ln, c) = utf16z(b, o);
            ins(&mut f, "long_name", ln);
            o += c;
            if version >= 3 && long_string_size > 0 && o + 2 < b.len() {
                let (loc, _) = if version >= 7 {
                    utf16z(b, o)
                } else {
                    asciiz(b, o)
                };
                ins(&mut f, "localized_name", loc);
            }
        }
        0xbeef0003 => {
            if let Some(g) = need(b, 8, 16).ok().and_then(guid_string) {
                ins(&mut f, "guid", g);
            }
        }
        0xbeef0005 => {
            if let Some(g) = need(b, 8, 16).ok().and_then(guid_string) {
                ins(&mut f, "guid", g);
            }
        }
        0xbeef0006 => {
            let (s, _) = utf16z(b, 8);
            ins(&mut f, "user_name", s);
        }
        0xbeef0019 => {
            if let Some(g) = need(b, 8, 16).ok().and_then(guid_string) {
                ins(&mut f, "guid1", g);
            }
            if let Some(g) = need(b, 24, 16).ok().and_then(guid_string) {
                ins(&mut f, "guid2", g);
            }
        }
        0xbeef0025 => {
            if let Some(t) = u64_at(b, 12).ok().and_then(filetime_to_ns) {
                ins(&mut f, "filetime1_ns", t);
            }
            if let Some(t) = u64_at(b, 20).ok().and_then(filetime_to_ns) {
                ins(&mut f, "filetime2_ns", t);
            }
        }
        0xbeef0026 => {
            if let Some(t) = u64_at(b, 12).ok().and_then(filetime_to_ns) {
                ins(&mut f, "creation_ns", t);
            }
            if let Some(t) = u64_at(b, 20).ok().and_then(filetime_to_ns) {
                ins(&mut f, "modification_ns", t);
            }
            if let Some(t) = u64_at(b, 28).ok().and_then(filetime_to_ns) {
                ins(&mut f, "access_ns", t);
            }
        }
        _ => {}
    }
    ins(&mut f, "size", b.len() as u64);
    if !matches!(sig, 0xbeef0004 | 0xbeef0006) {
        ins(&mut f, "hex", hex::encode(&b[..b.len().min(256)]));
    }
    f
}

/// Join item names with backslashes (`My Computer\C:\Windows\...`).
pub fn shell_item_path(items: &[ShellItem]) -> String {
    let mut out = String::new();
    for it in items {
        let n = it.display_name();
        if n.is_empty() {
            continue;
        }
        if !out.is_empty() && !out.ends_with('\\') {
            out.push('\\');
        }
        out.push_str(n);
    }
    out
}

/// Parse a hex string (whitespace allowed) into bytes, for CLI input.
pub fn parse_hex_input(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(cleaned).map_err(|e| ParseError::Invalid {
        offset: 0,
        reason: format!("hex: {e}"),
    })
}
