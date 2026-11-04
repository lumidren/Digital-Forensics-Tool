//! REGF (Windows registry hive) parser.
//!
//! Format reference: Maxim Suhanov, "Windows registry file format specification"
//! (github.com/msuhanov/regf) and libregf documentation (github.com/libyal/libregf).
//!
//! Supported:
//! - base block (signature, sequence numbers, timestamp, version, file name, XOR-32 checksum);
//! - hive bins and cells; key nodes (`nk`), values (`vk`), subkey lists (`lf`, `lh`, `li`,
//!   nested `ri`), value lists, class names, big data (`db`) for values > 16344 bytes in
//!   hives of version 1.4 and later, resident data (data length with bit 31 set);
//! - transaction logs in the "new" format (Windows 8.1 and later, `HvLE` log entries with
//!   Marvin32 hashes), applied in sequence order on top of a dirty primary file;
//! - best-effort recovery of deleted / unreachable key and value cells.
//!
//! Not supported: old-format transaction logs (Windows XP .. 8.0, `DIRT` dirty vector). Such logs
//! are detected, reported in [`LogRecovery::notes`] and skipped. Volatile keys do not exist on
//! disk and are therefore never reported.
//!
//! Every read is bounds-checked; malformed structures produce `Err` or are skipped, never a
//! panic. Recursion is bounded: key tree depth <= [`MAX_KEY_DEPTH`], `ri` nesting <=
//! [`MAX_LIST_DEPTH`], total keys <= [`MAX_KEYS`]. THREAT:T3.2
use crate::error::{ParseError, Result};
use crate::util::{ascii, i32_at, need, u16_at, u32_at, u64_at, utf16le};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use veritas_timeline::filetime_to_ns;

pub const BASE_BLOCK_SIZE: usize = 4096;
pub const HBIN_HEADER_SIZE: usize = 32;
pub const MAX_KEY_DEPTH: usize = 512;
pub const MAX_LIST_DEPTH: usize = 32;
pub const MAX_KEYS: usize = 4_000_000;
pub const MAX_VALUES_PER_KEY: usize = 1_000_000;
pub const BIG_DATA_SEGMENT_SIZE: usize = 16344;
/// Upper bound for a hive reconstructed from transaction logs.
pub const MAX_HIVE_SIZE: usize = 1 << 30;
const NONE_OFFSET: u32 = 0xFFFF_FFFF;

/// Key node flags.
pub mod key_flags {
    pub const VOLATILE: u16 = 0x0001;
    pub const HIVE_EXIT: u16 = 0x0002;
    pub const HIVE_ENTRY: u16 = 0x0004;
    pub const NO_DELETE: u16 = 0x0008;
    pub const SYM_LINK: u16 = 0x0010;
    pub const COMP_NAME: u16 = 0x0020;
}

// ---------------------------------------------------------------------------------------------
// Base block
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseBlock {
    pub primary_sequence: u32,
    pub secondary_sequence: u32,
    pub last_written_raw: u64,
    pub last_written_ns: Option<i64>,
    pub major_version: u32,
    pub minor_version: u32,
    /// 0 = primary, 1/2 = old-format log, 6 = new-format log.
    pub file_type: u32,
    pub file_format: u32,
    pub root_cell_offset: u32,
    pub hive_bins_data_size: u32,
    pub clustering_factor: u32,
    pub file_name: String,
    pub checksum: u32,
    pub computed_checksum: u32,
}

/// XOR-32 checksum over the first 508 bytes of a base block.
pub fn base_block_checksum(b: &[u8]) -> Result<u32> {
    let block = need(b, 0, 508)?;
    let mut x = 0u32;
    for c in block.chunks_exact(4) {
        x ^= u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    Ok(match x {
        0xFFFF_FFFF => 0xFFFF_FFFE,
        0 => 1,
        v => v,
    })
}

impl BaseBlock {
    pub fn parse(d: &[u8]) -> Result<Self> {
        let sig = need(d, 0, 4)?;
        if sig != b"regf" {
            return Err(ParseError::BadSignature { offset: 0, expected: "regf".into(), found: hex::encode(sig) });
        }
        need(d, 0, 512)?;
        let raw_ts = u64_at(d, 12)?;
        Ok(Self {
            primary_sequence: u32_at(d, 4)?,
            secondary_sequence: u32_at(d, 8)?,
            last_written_raw: raw_ts,
            last_written_ns: filetime_to_ns(raw_ts),
            major_version: u32_at(d, 20)?,
            minor_version: u32_at(d, 24)?,
            file_type: u32_at(d, 28)?,
            file_format: u32_at(d, 32)?,
            root_cell_offset: u32_at(d, 36)?,
            hive_bins_data_size: u32_at(d, 40)?,
            clustering_factor: u32_at(d, 44)?,
            file_name: utf16le(need(d, 48, 64)?, true),
            checksum: u32_at(d, 508)?,
            computed_checksum: base_block_checksum(d)?,
        })
    }
    pub fn checksum_ok(&self) -> bool {
        self.checksum == self.computed_checksum
    }
    /// A hive is dirty when the sequence numbers differ or the checksum fails.
    pub fn is_dirty(&self) -> bool {
        self.primary_sequence != self.secondary_sequence || !self.checksum_ok()
    }
}

// ---------------------------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValueType {
    None,
    Sz,
    ExpandSz,
    Binary,
    Dword,
    DwordBigEndian,
    Link,
    MultiSz,
    ResourceList,
    FullResourceDescriptor,
    ResourceRequirementsList,
    Qword,
    Other(u32),
}

impl ValueType {
    pub fn from_u32(t: u32) -> Self {
        match t {
            0 => Self::None,
            1 => Self::Sz,
            2 => Self::ExpandSz,
            3 => Self::Binary,
            4 => Self::Dword,
            5 => Self::DwordBigEndian,
            6 => Self::Link,
            7 => Self::MultiSz,
            8 => Self::ResourceList,
            9 => Self::FullResourceDescriptor,
            10 => Self::ResourceRequirementsList,
            11 => Self::Qword,
            o => Self::Other(o),
        }
    }
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Sz => 1,
            Self::ExpandSz => 2,
            Self::Binary => 3,
            Self::Dword => 4,
            Self::DwordBigEndian => 5,
            Self::Link => 6,
            Self::MultiSz => 7,
            Self::ResourceList => 8,
            Self::FullResourceDescriptor => 9,
            Self::ResourceRequirementsList => 10,
            Self::Qword => 11,
            Self::Other(o) => *o,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "REG_NONE",
            Self::Sz => "REG_SZ",
            Self::ExpandSz => "REG_EXPAND_SZ",
            Self::Binary => "REG_BINARY",
            Self::Dword => "REG_DWORD_LITTLE_ENDIAN",
            Self::DwordBigEndian => "REG_DWORD_BIG_ENDIAN",
            Self::Link => "REG_LINK",
            Self::MultiSz => "REG_MULTI_SZ",
            Self::ResourceList => "REG_RESOURCE_LIST",
            Self::FullResourceDescriptor => "REG_FULL_RESOURCE_DESCRIPTOR",
            Self::ResourceRequirementsList => "REG_RESOURCE_REQUIREMENTS_LIST",
            Self::Qword => "REG_QWORD",
            Self::Other(_) => "REG_UNKNOWN",
        }
    }
}

/// Typed decode of value data. Binary-like types keep their bytes in [`Value::raw`] only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueData {
    None,
    String(String),
    ExpandString(String),
    Binary,
    Dword(u32),
    DwordBigEndian(u32),
    Link(String),
    MultiString(Vec<String>),
    Qword(u64),
    Resource,
    /// Declared type could not be decoded from the stored bytes (e.g. a 2-byte DWORD).
    Unparsed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// Cell offset (relative to the first hive bin).
    pub offset: u32,
    /// Empty for the default value.
    pub name: String,
    pub kind: ValueType,
    pub flags: u16,
    /// Declared data size (bit 31 removed).
    pub data_size: u32,
    pub resident: bool,
    pub raw: Vec<u8>,
    pub data: ValueData,
    /// Set when the data could not be read completely (raw holds what was readable).
    pub data_error: Option<String>,
}

fn decode_multi_sz(raw: &[u8]) -> Vec<String> {
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let mut out: Vec<String> = units.split(|&u| u == 0).map(String::from_utf16_lossy).collect();
    while out.last().is_some_and(|s| s.is_empty()) {
        out.pop();
    }
    out
}

pub fn decode_value_data(kind: ValueType, raw: &[u8]) -> ValueData {
    match kind {
        ValueType::None => ValueData::None,
        ValueType::Sz => ValueData::String(utf16le(raw, true)),
        ValueType::ExpandSz => ValueData::ExpandString(utf16le(raw, true)),
        ValueType::Link => ValueData::Link(utf16le(raw, false)),
        ValueType::MultiSz => ValueData::MultiString(decode_multi_sz(raw)),
        ValueType::Dword => u32_at(raw, 0).map(ValueData::Dword).unwrap_or(ValueData::Unparsed),
        ValueType::DwordBigEndian => crate::util::u32_be_at(raw, 0).map(ValueData::DwordBigEndian).unwrap_or(ValueData::Unparsed),
        ValueType::Qword => u64_at(raw, 0).map(ValueData::Qword).unwrap_or(ValueData::Unparsed),
        ValueType::ResourceList | ValueType::FullResourceDescriptor | ValueType::ResourceRequirementsList => ValueData::Resource,
        ValueType::Binary | ValueType::Other(_) => ValueData::Binary,
    }
}

impl Value {
    /// String form of the data (strings, numbers in decimal, multi-strings joined by `" "`,
    /// binary as `"(N bytes)"`).
    pub fn display_string(&self) -> String {
        match &self.data {
            ValueData::None => if self.raw.is_empty() { String::new() } else { format!("({} bytes)", self.raw.len()) },
            ValueData::String(s) | ValueData::ExpandString(s) | ValueData::Link(s) => s.clone(),
            ValueData::Dword(v) | ValueData::DwordBigEndian(v) => v.to_string(),
            ValueData::Qword(v) => v.to_string(),
            ValueData::MultiString(v) => v.join(" "),
            ValueData::Binary | ValueData::Resource | ValueData::Unparsed => format!("({} bytes)", self.raw.len()),
        }
    }
    /// String data for REG_SZ / REG_EXPAND_SZ / REG_LINK, and UTF-16 decoded binary otherwise.
    pub fn as_string(&self) -> Option<String> {
        match &self.data {
            ValueData::String(s) | ValueData::ExpandString(s) | ValueData::Link(s) => Some(s.clone()),
            ValueData::MultiString(v) => Some(v.join(" ")),
            ValueData::Dword(v) | ValueData::DwordBigEndian(v) => Some(v.to_string()),
            ValueData::Qword(v) => Some(v.to_string()),
            ValueData::Binary | ValueData::None if self.raw.len() >= 2 && self.raw.len() % 2 == 0 => Some(utf16le(&self.raw, true)),
            _ => None,
        }
    }
    pub fn as_u32(&self) -> Option<u32> {
        match &self.data {
            ValueData::Dword(v) | ValueData::DwordBigEndian(v) => Some(*v),
            ValueData::Qword(v) => u32::try_from(*v).ok(),
            _ => u32_at(&self.raw, 0).ok().filter(|_| self.raw.len() == 4),
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match &self.data {
            ValueData::Qword(v) => Some(*v),
            ValueData::Dword(v) | ValueData::DwordBigEndian(v) => Some(*v as u64),
            _ => u64_at(&self.raw, 0).ok().filter(|_| self.raw.len() == 8),
        }
    }
    pub fn as_multi(&self) -> Vec<String> {
        match &self.data {
            ValueData::MultiString(v) => v.clone(),
            ValueData::String(s) | ValueData::ExpandString(s) => vec![s.clone()],
            _ if self.raw.len() >= 2 => decode_multi_sz(&self.raw),
            _ => vec![],
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
pub struct Key<'a> {
    hive: &'a Hive,
    pub offset: u32,
    pub name: String,
    pub flags: u16,
    pub last_written_raw: u64,
    pub last_written_ns: Option<i64>,
    pub access_bits: u32,
    pub parent_offset: u32,
    pub subkey_count: u32,
    pub subkey_list_offset: u32,
    pub value_count: u32,
    pub values_list_offset: u32,
    pub security_offset: u32,
    pub class_name: Option<String>,
    /// True when parsed from a cell not reachable from the root (see [`Hive::recover_deleted`]).
    pub deleted: bool,
}

impl fmt::Debug for Key<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("offset", &self.offset)
            .field("name", &self.name)
            .field("last_written_ns", &self.last_written_ns)
            .field("subkey_count", &self.subkey_count)
            .field("value_count", &self.value_count)
            .field("class_name", &self.class_name)
            .field("deleted", &self.deleted)
            .finish()
    }
}

impl<'a> Key<'a> {
    pub fn hive(&self) -> &'a Hive {
        self.hive
    }

    /// Offsets of all subkey cells (strict: any malformed list is an error).
    pub fn subkey_offsets(&self) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        if self.subkey_count == 0 || self.subkey_list_offset == NONE_OFFSET {
            return Ok(out);
        }
        self.hive.collect_subkey_offsets(self.subkey_list_offset, 0, &mut out)?;
        Ok(out)
    }

    /// Strict subkey enumeration: the first malformed entry is returned as an error.
    pub fn try_subkeys(&self) -> Result<Vec<Key<'a>>> {
        let offs = self.subkey_offsets()?;
        let mut v = Vec::with_capacity(offs.len());
        for o in offs {
            v.push(self.hive.key_at(o)?);
        }
        Ok(v)
    }

    /// Lenient subkey enumeration: malformed lists or cells are skipped (and counted in
    /// [`Key::subkey_errors`]).
    pub fn subkeys(&self) -> Vec<Key<'a>> {
        let mut offs = Vec::new();
        if self.subkey_count != 0 && self.subkey_list_offset != NONE_OFFSET {
            let _ = self.hive.collect_subkey_offsets(self.subkey_list_offset, 0, &mut offs);
        }
        offs.into_iter().filter(|&o| o != self.offset).filter_map(|o| self.hive.key_at(o).ok()).collect()
    }

    /// Number of subkeys that could not be read (declared count vs readable).
    pub fn subkey_errors(&self) -> usize {
        (self.subkey_count as usize).saturating_sub(self.subkeys().len())
    }

    pub fn value_offsets(&self) -> Result<Vec<u32>> {
        if self.value_count == 0 || self.values_list_offset == NONE_OFFSET {
            return Ok(Vec::new());
        }
        let cell = if self.deleted { self.hive.cell_any(self.values_list_offset)? } else { self.hive.cell(self.values_list_offset)? };
        let n = (self.value_count as usize).min(cell.len() / 4).min(MAX_VALUES_PER_KEY);
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            out.push(u32_at(cell, i * 4)?);
        }
        Ok(out)
    }

    pub fn try_values(&self) -> Result<Vec<Value>> {
        let offs = self.value_offsets()?;
        if offs.len() < self.value_count as usize {
            return Err(ParseError::Invalid { offset: self.values_list_offset as usize, reason: "value list shorter than value count".into() });
        }
        offs.into_iter().map(|o| self.hive.value_at(o, self.deleted)).collect()
    }

    /// Lenient value enumeration (unreadable values are skipped).
    pub fn values(&self) -> Vec<Value> {
        match self.value_offsets() {
            Ok(offs) => offs.into_iter().filter_map(|o| self.hive.value_at(o, self.deleted).ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Case-insensitive direct child lookup.
    pub fn subkey(&self, name: &str) -> Option<Key<'a>> {
        let want = name.to_lowercase();
        self.subkeys().into_iter().find(|k| k.name.to_lowercase() == want)
    }

    /// Case-insensitive descendant lookup by backslash-separated path.
    pub fn path(&self, path: &str) -> Option<Key<'a>> {
        let mut cur = self.clone();
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            cur = cur.subkey(part)?;
        }
        Some(cur)
    }

    /// Case-insensitive value lookup; `""` selects the default value.
    pub fn value(&self, name: &str) -> Option<Value> {
        let want = name.to_lowercase();
        self.values().into_iter().find(|v| v.name.to_lowercase() == want)
    }
    pub fn value_string(&self, name: &str) -> Option<String> {
        self.value(name).and_then(|v| v.as_string())
    }
    pub fn value_u32(&self, name: &str) -> Option<u32> {
        self.value(name).and_then(|v| v.as_u32())
    }
    pub fn value_u64(&self, name: &str) -> Option<u64> {
        self.value(name).and_then(|v| v.as_u64())
    }
    pub fn value_bytes(&self, name: &str) -> Option<Vec<u8>> {
        self.value(name).map(|v| v.raw)
    }
    pub fn value_multi(&self, name: &str) -> Option<Vec<String>> {
        self.value(name).map(|v| v.as_multi())
    }
}

// ---------------------------------------------------------------------------------------------
// Hive
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HbinInfo {
    /// Offset relative to the first hive bin.
    pub offset: u32,
    pub size: u32,
    pub timestamp_ns: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellInfo {
    pub offset: u32,
    pub size: u32,
    pub allocated: bool,
    /// First two bytes of the cell data (`nk`, `vk`, `lf`, ...), when present.
    pub signature: [u8; 2],
}

/// Result of applying transaction logs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogRecovery {
    pub was_dirty: bool,
    pub applied_entries: u32,
    pub dirty_pages: u32,
    pub first_sequence: Option<u32>,
    pub last_sequence: Option<u32>,
    pub notes: Vec<String>,
}

/// A key or value cell not reachable from the root key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedKey {
    pub offset: u32,
    pub name: String,
    pub last_written_ns: Option<i64>,
    pub parent_offset: u32,
    /// Path of the parent when the parent is a live key ("" for the root).
    pub parent_path: Option<String>,
    /// Whether the cell is still marked allocated (orphaned rather than freed).
    pub allocated: bool,
    pub values: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedValue {
    pub offset: u32,
    pub allocated: bool,
    /// Offset of the recovered deleted key whose value list references this value.
    pub owner_key_offset: Option<u32>,
    pub value: Value,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeletedItems {
    pub keys: Vec<DeletedKey>,
    pub values: Vec<DeletedValue>,
}

pub struct Hive {
    data: Vec<u8>,
    base: BaseBlock,
    bins_end: usize,
    pub recovery: Option<LogRecovery>,
    pub warnings: Vec<String>,
}

impl fmt::Debug for Hive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hive").field("len", &self.data.len()).field("base", &self.base).field("warnings", &self.warnings).finish()
    }
}

impl Hive {
    /// Parse a primary hive file. A dirty hive is parsed as-is (with a warning).
    pub fn parse(data: &[u8]) -> Result<Hive> {
        Self::from_vec(data.to_vec())
    }

    fn from_vec(data: Vec<u8>) -> Result<Hive> {
        let base = BaseBlock::parse(&data)?;
        let mut warnings = Vec::new();
        if base.major_version != 1 {
            return Err(ParseError::Unsupported(format!("regf major version {}", base.major_version)));
        }
        if !base.checksum_ok() {
            warnings.push(format!("base block checksum mismatch: stored {:#010x} computed {:#010x}", base.checksum, base.computed_checksum));
        }
        if base.primary_sequence != base.secondary_sequence {
            warnings.push(format!(
                "hive is dirty (sequence {} != {}); provide transaction logs for an up-to-date view",
                base.primary_sequence, base.secondary_sequence
            ));
        }
        if data.len() < BASE_BLOCK_SIZE + HBIN_HEADER_SIZE {
            return Err(ParseError::Truncated { offset: BASE_BLOCK_SIZE, needed: HBIN_HEADER_SIZE, available: data.len().saturating_sub(BASE_BLOCK_SIZE) });
        }
        let declared = BASE_BLOCK_SIZE.saturating_add(base.hive_bins_data_size as usize);
        let bins_end = if base.hive_bins_data_size == 0 || declared > data.len() {
            if base.hive_bins_data_size != 0 {
                warnings.push(format!("hive bins data size {} exceeds file; truncated hive", base.hive_bins_data_size));
            }
            data.len()
        } else {
            declared
        };
        let hive = Hive { data, base, bins_end, recovery: None, warnings };
        let root = hive.key_at(hive.base.root_cell_offset)?;
        let _ = root;
        Ok(hive)
    }

    /// Parse a primary hive and apply new-format (`HvLE`) transaction logs when the primary is
    /// dirty. Logs may be passed in any order. Old-format logs are reported and skipped.
    pub fn parse_with_logs(primary: &[u8], logs: &[&[u8]]) -> Result<Hive> {
        let mut data = primary.to_vec();
        let mut rec = LogRecovery::default();

        // Pick a usable base block: the primary's, or the newest valid one from a log.
        let primary_base = BaseBlock::parse(&data).ok().filter(|b| b.checksum_ok());
        let mut log_bases: Vec<BaseBlock> = Vec::new();
        for (i, l) in logs.iter().enumerate() {
            match BaseBlock::parse(l) {
                Ok(b) if b.checksum_ok() => log_bases.push(b),
                Ok(_) => rec.notes.push(format!("log {i}: base block checksum mismatch")),
                Err(e) => rec.notes.push(format!("log {i}: {e}")),
            }
        }
        let primary_ok = primary_base.is_some();
        let base = match primary_base {
            Some(b) => b,
            None => {
                let best_idx = (0..logs.len())
                    .filter(|&i| BaseBlock::parse(logs[i]).map(|b| b.checksum_ok()).unwrap_or(false))
                    .max_by_key(|&i| BaseBlock::parse(logs[i]).map(|b| b.secondary_sequence).unwrap_or(0));
                match best_idx {
                    Some(i) => {
                        if data.len() < 512 {
                            data.resize(BASE_BLOCK_SIZE, 0);
                        }
                        data[..512].copy_from_slice(&logs[i][..512]);
                        rec.notes.push(format!("primary base block invalid; using base block from log {i}"));
                        BaseBlock::parse(&data)?
                    }
                    None => return Err(ParseError::Invalid { offset: 0, reason: "no valid base block in primary or logs".into() }),
                }
            }
        };
        rec.was_dirty = base.is_dirty() || !primary_ok;
        if !rec.was_dirty {
            rec.notes.push("primary hive is clean; logs not applied".into());
            let mut h = Self::from_vec(data)?;
            h.recovery = Some(rec);
            return Ok(h);
        }

        // Gather valid log entries.
        let mut entries: BTreeMap<u32, LogEntry> = BTreeMap::new();
        for (i, l) in logs.iter().enumerate() {
            match BaseBlock::parse(l) {
                Ok(b) if b.file_type == 1 || b.file_type == 2 => {
                    rec.notes.push(format!("log {i}: old-format (DIRT) transaction log is not supported; skipped"));
                    continue;
                }
                Ok(_) => {}
                Err(_) => continue,
            }
            if l.get(512..516) == Some(b"DIRT".as_slice()) {
                rec.notes.push(format!("log {i}: old-format (DIRT) transaction log is not supported; skipped"));
                continue;
            }
            let (es, note) = parse_log_entries(l);
            if let Some(n) = note {
                rec.notes.push(format!("log {i}: {n}"));
            }
            for e in es {
                entries.entry(e.sequence).or_insert(e);
            }
        }
        let start = base.secondary_sequence;
        let mut seq = match entries.range(start..).next() {
            Some((s, _)) => *s,
            None => {
                rec.notes.push(format!("no log entries with sequence >= {start}"));
                let mut h = Self::from_vec(data)?;
                h.recovery = Some(rec);
                return Ok(h);
            }
        };
        let mut hbins_size = base.hive_bins_data_size;
        while let Some(e) = entries.get(&seq) {
            let new_len = BASE_BLOCK_SIZE.saturating_add(e.hive_bins_size as usize);
            if new_len > MAX_HIVE_SIZE {
                return Err(ParseError::Limit(format!("log entry {seq} grows hive to {new_len} bytes")));
            }
            if data.len() < new_len {
                data.resize(new_len, 0);
            }
            for (off, bytes) in &e.pages {
                let dst = BASE_BLOCK_SIZE.saturating_add(*off as usize);
                let end = dst.saturating_add(bytes.len());
                if end > MAX_HIVE_SIZE {
                    return Err(ParseError::Limit(format!("dirty page at {off:#x} beyond limit")));
                }
                if data.len() < end {
                    data.resize(end, 0);
                }
                data[dst..end].copy_from_slice(bytes);
                rec.dirty_pages += 1;
            }
            hbins_size = e.hive_bins_size;
            rec.first_sequence.get_or_insert(seq);
            rec.last_sequence = Some(seq);
            rec.applied_entries += 1;
            seq = match seq.checked_add(1) {
                Some(s) => s,
                None => break,
            };
        }
        if let Some(last) = rec.last_sequence {
            let ns = last.wrapping_add(1);
            data[4..8].copy_from_slice(&ns.to_le_bytes());
            data[8..12].copy_from_slice(&ns.to_le_bytes());
            data[40..44].copy_from_slice(&hbins_size.to_le_bytes());
            let ck = base_block_checksum(&data)?;
            data[508..512].copy_from_slice(&ck.to_le_bytes());
        }
        let mut h = Self::from_vec(data)?;
        h.recovery = Some(rec);
        Ok(h)
    }

    pub fn base_block(&self) -> &BaseBlock {
        &self.base
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Allocated cell data (without the 4-byte size header).
    pub fn cell(&self, off: u32) -> Result<&[u8]> {
        let (d, alloc) = self.cell_raw(off)?;
        if !alloc {
            return Err(ParseError::Invalid { offset: off as usize, reason: "cell is not allocated".into() });
        }
        Ok(d)
    }

    /// Cell data regardless of allocation state (used for deleted-item recovery).
    pub fn cell_any(&self, off: u32) -> Result<&[u8]> {
        self.cell_raw(off).map(|(d, _)| d)
    }

    fn cell_raw(&self, off: u32) -> Result<(&[u8], bool)> {
        if off == NONE_OFFSET {
            return Err(ParseError::Invalid { offset: off as usize, reason: "null cell offset".into() });
        }
        let abs = BASE_BLOCK_SIZE.checked_add(off as usize).ok_or(ParseError::Invalid { offset: off as usize, reason: "cell offset overflow".into() })?;
        let bins = self.data.get(..self.bins_end).unwrap_or(&self.data);
        let size = i32_at(bins, abs)?;
        let len = size.unsigned_abs() as usize;
        if len < 8 {
            return Err(ParseError::Invalid { offset: abs, reason: format!("cell size {size} too small") });
        }
        let d = need(bins, abs + 4, len - 4)?;
        Ok((d, size < 0))
    }

    fn collect_subkey_offsets(&self, list: u32, depth: usize, out: &mut Vec<u32>) -> Result<()> {
        if depth > MAX_LIST_DEPTH {
            return Err(ParseError::Limit("ri subkey list nesting".into()));
        }
        let c = self.cell(list)?;
        let sig = need(c, 0, 2)?;
        let count = u16_at(c, 2)? as usize;
        match sig {
            b"lf" | b"lh" => {
                for i in 0..count {
                    out.push(u32_at(c, 4 + i * 8)?);
                }
            }
            b"li" => {
                for i in 0..count {
                    out.push(u32_at(c, 4 + i * 4)?);
                }
            }
            b"ri" => {
                for i in 0..count {
                    let sub = u32_at(c, 4 + i * 4)?;
                    if sub == list {
                        return Err(ParseError::Invalid { offset: list as usize, reason: "self-referencing ri list".into() });
                    }
                    self.collect_subkey_offsets(sub, depth + 1, out)?;
                }
            }
            _ => return Err(ParseError::BadSignature { offset: list as usize, expected: "lf|lh|li|ri".into(), found: hex::encode(sig) }),
        }
        if out.len() > MAX_KEYS {
            return Err(ParseError::Limit("too many subkeys".into()));
        }
        Ok(())
    }

    /// Parse the key node at a cell offset (allocated cells only).
    pub fn key_at(&self, off: u32) -> Result<Key<'_>> {
        let c = self.cell(off)?;
        self.parse_nk(off, c, false)
    }

    fn parse_nk(&self, off: u32, c: &[u8], deleted: bool) -> Result<Key<'_>> {
        let sig = need(c, 0, 2)?;
        if sig != b"nk" {
            return Err(ParseError::BadSignature { offset: off as usize, expected: "nk".into(), found: hex::encode(sig) });
        }
        let flags = u16_at(c, 2)?;
        let lw = u64_at(c, 4)?;
        let name_len = u16_at(c, 72)? as usize;
        let class_len = u16_at(c, 74)? as usize;
        let name_bytes = need(c, 76, name_len)?;
        let name = if flags & key_flags::COMP_NAME != 0 { ascii(name_bytes, false) } else { utf16le(name_bytes, false) };
        let class_off = u32_at(c, 48)?;
        let class_name = if class_off != NONE_OFFSET && class_len > 0 {
            let cell = if deleted { self.cell_any(class_off) } else { self.cell(class_off) };
            cell.ok().and_then(|cd| need(cd, 0, class_len).ok()).map(|b| utf16le(b, false))
        } else {
            None
        };
        Ok(Key {
            hive: self,
            offset: off,
            name,
            flags,
            last_written_raw: lw,
            last_written_ns: filetime_to_ns(lw),
            access_bits: u32_at(c, 12)?,
            parent_offset: u32_at(c, 16)?,
            subkey_count: u32_at(c, 20)?,
            subkey_list_offset: u32_at(c, 28)?,
            value_count: u32_at(c, 36)?,
            values_list_offset: u32_at(c, 40)?,
            security_offset: u32_at(c, 44)?,
            class_name,
            deleted,
        })
    }

    /// Parse the value at a cell offset. `lenient` accepts unallocated cells.
    pub fn value_at(&self, off: u32, lenient: bool) -> Result<Value> {
        let c = if lenient { self.cell_any(off)? } else { self.cell(off)? };
        self.parse_vk(off, c, lenient)
    }

    fn parse_vk(&self, off: u32, c: &[u8], lenient: bool) -> Result<Value> {
        let sig = need(c, 0, 2)?;
        if sig != b"vk" {
            return Err(ParseError::BadSignature { offset: off as usize, expected: "vk".into(), found: hex::encode(sig) });
        }
        let name_len = u16_at(c, 2)? as usize;
        let size_field = u32_at(c, 4)?;
        let data_off = u32_at(c, 8)?;
        let raw_type = u32_at(c, 12)?;
        let flags = u16_at(c, 16)?;
        let name_bytes = need(c, 20, name_len)?;
        let name = if flags & 0x0001 != 0 { ascii(name_bytes, false) } else { utf16le(name_bytes, false) };
        let resident = size_field & 0x8000_0000 != 0;
        let size = (size_field & 0x7FFF_FFFF) as usize;
        let mut data_error = None;
        let raw: Vec<u8> = if resident {
            let b = data_off.to_le_bytes();
            if size > 4 {
                data_error = Some(format!("resident data size {size} > 4"));
            }
            b[..size.min(4)].to_vec()
        } else if size == 0 {
            Vec::new()
        } else {
            match self.read_data(data_off, size, lenient) {
                Ok((d, err)) => {
                    data_error = err;
                    d
                }
                Err(e) => {
                    data_error = Some(e.to_string());
                    Vec::new()
                }
            }
        };
        let kind = ValueType::from_u32(raw_type);
        let data = decode_value_data(kind, &raw);
        Ok(Value { offset: off, name, kind, flags, data_size: size as u32, resident, raw, data, data_error })
    }

    fn read_data(&self, off: u32, size: usize, lenient: bool) -> Result<(Vec<u8>, Option<String>)> {
        let c = if lenient { self.cell_any(off)? } else { self.cell(off)? };
        if size > BIG_DATA_SEGMENT_SIZE && self.base.minor_version >= 4 && c.get(0..2) == Some(b"db".as_slice()) {
            let count = u16_at(c, 2)? as usize;
            let list_off = u32_at(c, 4)?;
            let list = if lenient { self.cell_any(list_off)? } else { self.cell(list_off)? };
            let mut out = Vec::with_capacity(size.min(self.data.len()));
            for i in 0..count {
                if out.len() >= size {
                    break;
                }
                let seg_off = u32_at(list, i * 4)?;
                let seg = if lenient { self.cell_any(seg_off)? } else { self.cell(seg_off)? };
                let take = (size - out.len()).min(BIG_DATA_SEGMENT_SIZE).min(seg.len());
                out.extend_from_slice(&seg[..take]);
            }
            let err = if out.len() < size { Some(format!("big data truncated: {} of {size} bytes", out.len())) } else { None };
            return Ok((out, err));
        }
        if c.len() < size {
            return Ok((c.to_vec(), Some(format!("data cell holds {} of {size} bytes", c.len()))));
        }
        Ok((c[..size].to_vec(), None))
    }

    pub fn root(&self) -> Result<Key<'_>> {
        self.key_at(self.base.root_cell_offset)
    }

    /// Case-insensitive lookup of a backslash-separated path relative to the root key.
    /// A leading root key name is accepted but not required.
    pub fn key(&self, path: &str) -> Option<Key<'_>> {
        let root = self.root().ok()?;
        if let Some(k) = root.path(path) {
            return Some(k);
        }
        let mut parts = path.split('\\').filter(|p| !p.is_empty());
        let first = parts.next()?;
        if first.eq_ignore_ascii_case(&root.name) {
            let rest: Vec<&str> = parts.collect();
            return root.path(&rest.join("\\"));
        }
        None
    }

    /// Visit every reachable key depth-first (pre-order, on-disk subkey order). The callback
    /// gets the path relative to the root (`""` for the root) and the depth.
    pub fn walk<F: FnMut(&str, usize, &Key<'_>)>(&self, mut f: F) -> Result<usize> {
        let root = self.root()?;
        let mut visited: BTreeSet<u32> = BTreeSet::new();
        let mut stack: Vec<(String, usize, Key<'_>)> = vec![(String::new(), 0, root)];
        let mut n = 0usize;
        while let Some((path, depth, k)) = stack.pop() {
            if !visited.insert(k.offset) {
                continue;
            }
            n += 1;
            if n > MAX_KEYS {
                return Err(ParseError::Limit("too many keys".into()));
            }
            f(&path, depth, &k);
            if depth >= MAX_KEY_DEPTH {
                continue;
            }
            let subs = k.subkeys();
            for s in subs.into_iter().rev() {
                if visited.contains(&s.offset) {
                    continue;
                }
                let p = if path.is_empty() { s.name.clone() } else { format!("{}\\{}", path, s.name) };
                stack.push((p, depth + 1, s));
            }
        }
        Ok(n)
    }

    /// All reachable keys with their root-relative paths, depth-first.
    pub fn keys(&self) -> Vec<(String, Key<'_>)> {
        let mut out: Vec<(String, u32)> = Vec::new();
        let _ = self.walk(|p, _, k| out.push((p.to_string(), k.offset)));
        out.into_iter().filter_map(|(p, o)| self.key_at(o).ok().map(|k| (p, k))).collect()
    }

    /// Hive bins in file order. Walking stops at the first bin with a bad header.
    pub fn hbins(&self) -> Vec<HbinInfo> {
        let mut out = Vec::new();
        let mut pos = BASE_BLOCK_SIZE;
        while pos + HBIN_HEADER_SIZE <= self.bins_end {
            if self.data.get(pos..pos + 4) != Some(b"hbin".as_slice()) {
                break;
            }
            let size = u32_at(&self.data, pos + 8).unwrap_or(0) as usize;
            if size < HBIN_HEADER_SIZE || size % 4096 != 0 || pos + size > self.bins_end {
                break;
            }
            let ts = u64_at(&self.data, pos + 0x14).ok().and_then(filetime_to_ns);
            out.push(HbinInfo { offset: (pos - BASE_BLOCK_SIZE) as u32, size: size as u32, timestamp_ns: ts });
            pos += size;
        }
        out
    }

    /// Every cell of every hive bin. Walking a bin stops at the first malformed cell size.
    pub fn cells(&self) -> Vec<CellInfo> {
        let mut out = Vec::new();
        for b in self.hbins() {
            let start = BASE_BLOCK_SIZE + b.offset as usize;
            let end = start + b.size as usize;
            let mut pos = start + HBIN_HEADER_SIZE;
            while pos + 8 <= end {
                let size = match i32_at(&self.data, pos) {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let len = size.unsigned_abs() as usize;
                if len < 8 || pos + len > end {
                    break;
                }
                let sig = [self.data[pos + 4], self.data[pos + 5]];
                out.push(CellInfo { offset: (pos - BASE_BLOCK_SIZE) as u32, size: len as u32, allocated: size < 0, signature: sig });
                pos += len;
            }
        }
        out
    }

    /// Best-effort recovery of key and value cells that are not reachable from the root:
    /// unallocated cells (and former cells inside merged free space, scanned at 8-byte
    /// alignment) plus allocated-but-orphaned cells.
    pub fn recover_deleted(&self) -> DeletedItems {
        let mut live_keys: BTreeMap<u32, String> = BTreeMap::new();
        let mut live_values: BTreeSet<u32> = BTreeSet::new();
        let _ = self.walk(|p, _, k| {
            live_keys.insert(k.offset, p.to_string());
            if let Ok(v) = k.value_offsets() {
                live_values.extend(v);
            }
        });
        let mut cand_keys: Vec<(u32, bool)> = Vec::new();
        let mut cand_vals: Vec<(u32, bool)> = Vec::new();
        for c in self.cells() {
            let abs = BASE_BLOCK_SIZE + c.offset as usize;
            if c.allocated {
                match &c.signature {
                    b"nk" if !live_keys.contains_key(&c.offset) => cand_keys.push((c.offset, true)),
                    b"vk" if !live_values.contains(&c.offset) => cand_vals.push((c.offset, true)),
                    _ => {}
                }
                continue;
            }
            let end = abs + c.size as usize;
            let mut p = abs;
            while p + 8 <= end {
                let inner = i32_at(&self.data, p).map(|s| s.unsigned_abs() as usize).unwrap_or(0);
                if inner >= 8 && p + inner <= end {
                    let sig = &self.data[p + 4..p + 6];
                    let rel = (p - BASE_BLOCK_SIZE) as u32;
                    if sig == b"nk" && !live_keys.contains_key(&rel) {
                        cand_keys.push((rel, false));
                    } else if sig == b"vk" && !live_values.contains(&rel) {
                        cand_vals.push((rel, false));
                    }
                }
                p += 8;
            }
        }
        let mut items = DeletedItems::default();
        let mut owner: BTreeMap<u32, u32> = BTreeMap::new();
        for (off, allocated) in cand_keys {
            let Ok(c) = self.cell_any(off) else { continue };
            let Ok(k) = self.parse_nk(off, c, true) else { continue };
            if k.name.is_empty() || k.last_written_ns.is_none() {
                continue;
            }
            let values = k.values();
            for v in &values {
                owner.entry(v.offset).or_insert(off);
            }
            let parent_path = live_keys.get(&k.parent_offset).cloned();
            items.keys.push(DeletedKey { offset: off, name: k.name, last_written_ns: k.last_written_ns, parent_offset: k.parent_offset, parent_path, allocated, values });
        }
        for (off, allocated) in cand_vals {
            let Ok(v) = self.value_at(off, true) else { continue };
            if v.kind.as_u32() > 0x0B && v.kind.as_u32() & 0xFFFF_0000 == 0 {
                continue;
            }
            items.values.push(DeletedValue { offset: off, allocated, owner_key_offset: owner.get(&off).copied(), value: v });
        }
        items
    }

    pub fn deleted_keys(&self) -> Vec<DeletedKey> {
        self.recover_deleted().keys
    }
    pub fn deleted_values(&self) -> Vec<DeletedValue> {
        self.recover_deleted().values
    }
}

// ---------------------------------------------------------------------------------------------
// Transaction logs (new format)
// ---------------------------------------------------------------------------------------------

struct LogEntry {
    sequence: u32,
    hive_bins_size: u32,
    pages: Vec<(u32, Vec<u8>)>,
}

/// Default Marvin32 seed used by the registry for `HvLE` log entry hashes.
pub const MARVIN32_REGISTRY_SEED: u64 = 0x82EF_4D88_7A4E_55C5;

/// Marvin32 hash (as used by Windows for registry log entries).
pub fn marvin32(data: &[u8], seed: u64) -> u64 {
    fn block(lo: &mut u32, hi: &mut u32) {
        *hi ^= *lo;
        *lo = lo.rotate_left(20);
        *lo = lo.wrapping_add(*hi);
        *hi = hi.rotate_left(9);
        *hi ^= *lo;
        *lo = lo.rotate_left(27);
        *lo = lo.wrapping_add(*hi);
        *hi = hi.rotate_left(19);
    }
    let mut lo = seed as u32;
    let mut hi = (seed >> 32) as u32;
    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        lo = lo.wrapping_add(u32::from_le_bytes([c[0], c[1], c[2], c[3]]));
        block(&mut lo, &mut hi);
    }
    let t = chunks.remainder();
    let fin: u32 = match t.len() {
        0 => 0x80,
        1 => 0x8000 | t[0] as u32,
        2 => 0x80_0000 | t[0] as u32 | (t[1] as u32) << 8,
        _ => 0x8000_0000 | t[0] as u32 | (t[1] as u32) << 8 | (t[2] as u32) << 16,
    };
    lo = lo.wrapping_add(fin);
    block(&mut lo, &mut hi);
    block(&mut lo, &mut hi);
    ((hi as u64) << 32) | lo as u64
}

/// Parse consecutive valid `HvLE` entries starting at offset 512. Parsing stops at the first
/// entry with a bad signature, size, hash or non-consecutive sequence number.
fn parse_log_entries(l: &[u8]) -> (Vec<LogEntry>, Option<String>) {
    let mut out: Vec<LogEntry> = Vec::new();
    let mut off = 512usize;
    let mut note = None;
    loop {
        if l.get(off..off + 4) != Some(b"HvLE".as_slice()) {
            break;
        }
        let parsed = (|| -> Result<(LogEntry, usize)> {
            let size = u32_at(l, off + 4)? as usize;
            if size < 40 || size % 512 != 0 {
                return Err(ParseError::Invalid { offset: off, reason: format!("log entry size {size}") });
            }
            let e = need(l, off, size)?;
            let seq = u32_at(e, 12)?;
            let hbs = u32_at(e, 16)?;
            let npages = u32_at(e, 20)? as usize;
            let h1 = u64_at(e, 24)?;
            let h2 = u64_at(e, 32)?;
            if marvin32(need(e, 0, 32)?, MARVIN32_REGISTRY_SEED) != h2 {
                return Err(ParseError::Invalid { offset: off, reason: "log entry header hash mismatch".into() });
            }
            if marvin32(&e[40..], MARVIN32_REGISTRY_SEED) != h1 {
                return Err(ParseError::Invalid { offset: off, reason: "log entry data hash mismatch".into() });
            }
            let refs_len = npages.checked_mul(8).ok_or(ParseError::Limit("dirty pages".into()))?;
            let mut data_pos = 40usize.checked_add(refs_len).ok_or(ParseError::Limit("dirty pages".into()))?;
            need(e, 40, refs_len)?;
            let mut pages = Vec::with_capacity(npages.min(4096));
            for i in 0..npages {
                let po = u32_at(e, 40 + i * 8)?;
                let ps = u32_at(e, 44 + i * 8)? as usize;
                let bytes = need(e, data_pos, ps)?.to_vec();
                data_pos += ps;
                pages.push((po, bytes));
            }
            Ok((LogEntry { sequence: seq, hive_bins_size: hbs, pages }, size))
        })();
        match parsed {
            Ok((e, size)) => {
                if let Some(prev) = out.last() {
                    if prev.sequence.wrapping_add(1) != e.sequence {
                        note = Some(format!("non-consecutive sequence {} after {} at {off:#x}", e.sequence, prev.sequence));
                        break;
                    }
                }
                out.push(e);
                off += size;
            }
            Err(err) => {
                note = Some(format!("stopped at {off:#x}: {err}"));
                break;
            }
        }
    }
    (out, note)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regf_marvin32_matches_windows_log_entry_hash() {
        // Header (first 32 bytes) of the first HvLE entry of a Windows 11 Default-profile
        // NTUSER.DAT.LOG1, and the hash-2 field Windows stored for it.
        let hdr = hex::decode("48764c45002e0000000000002200000000c0020002000000d85151f9c1eb5540").unwrap();
        assert_eq!(marvin32(&hdr, MARVIN32_REGISTRY_SEED), 0x48d3_9573_7b76_d700);
    }

    #[test]
    fn regf_rejects_garbage() {
        assert!(Hive::parse(b"").is_err());
        assert!(Hive::parse(&[0u8; 8192]).is_err());
        let mut d = vec![0u8; 8192];
        d[..4].copy_from_slice(b"regf");
        d[20] = 1;
        assert!(Hive::parse(&d).is_err());
    }
}
