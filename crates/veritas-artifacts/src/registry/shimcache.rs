//! AppCompatCache / ShimCache (`windows:registry:appcompatcache`).
//!
//! Location: `SYSTEM\<CCS>\Control\Session Manager\AppCompatCache\AppCompatCache`
//! (Windows 2003+) or `...\Session Manager\AppCompatibility\AppCompatCache` (XP).
//!
//! Formats (reference: Mandiant "Leveraging the Application Compatibility Cache in Forensic
//! Investigations" and the ShimCacheParser / Plaso appcompatcache plugin descriptions):
//!
//! | format | signature | header | entry |
//! |---|---|---|---|
//! | XP 32-bit | `0xDEADBEEF` | 400 | 552 bytes: path[520] UTF-16, mtime@528, size@536, update@544 |
//! | 2003/Vista/2008 | `0xBADC0FFE` | 8 | 32-bit 24 B / 64-bit 32 B: len, maxlen, path offset, mtime, size-or-flags |
//! | Win7/2008R2 | `0xBADC0FEE` | 128 | 32-bit 32 B / 64-bit 48 B: len, maxlen, path offset, mtime, insert flags, shim flags, data size, data offset |
//! | Win8.0 | header 0x80, entries `00ts` | 128 | sig, unk, size; path, insert flags, shim flags, mtime, data |
//! | Win8.1 | header 0x80, entries `10ts` | 128 | as 8.0 plus package name after the path |
//! | Win10/11 | header 0x30 / 0x34, entries `10ts` | 0x30/0x34 | sig, unk, size; path, mtime, data |
//!
//! 32 vs 64-bit layouts are told apart by the first entry: in 64-bit layouts the dword after
//! the two length words is padding (zero). The executed flag is insert-flags bit 0x2 (Win7,
//! Win8.x and, heuristically, Vista when every size-or-flags field looks like flags);
//! Windows 10+ entries carry no executed flag. Entry order is insertion (MRU) order.
use super::{current_control_set, Ctx};
use crate::error::{ParseError, Result};
use crate::regf::Hive;
use crate::util::{need, u16_at, u32_at, u64_at, utf16le};
use veritas_timeline::{desc, filetime_to_ns, Event};

pub const MAX_ENTRIES: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimCacheEntry {
    /// Position in the cache (0 = most recently inserted).
    pub index: usize,
    pub path: String,
    pub last_modified_raw: u64,
    pub last_modified_ns: Option<i64>,
    pub executed: Option<bool>,
    pub insert_flags: Option<u32>,
    pub shim_flags: Option<u32>,
    pub file_size: Option<u64>,
    pub data_size: Option<u64>,
    pub last_update_ns: Option<i64>,
    pub package: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimCache {
    pub format: &'static str,
    pub declared_entries: Option<u32>,
    pub entries: Vec<ShimCacheEntry>,
}

fn entry(index: usize, path: String, mtime: u64) -> ShimCacheEntry {
    ShimCacheEntry {
        index,
        path,
        last_modified_raw: mtime,
        last_modified_ns: filetime_to_ns(mtime),
        executed: None,
        insert_flags: None,
        shim_flags: None,
        file_size: None,
        data_size: None,
        last_update_ns: None,
        package: None,
    }
}

fn path_at(d: &[u8], off: u64, len: u16) -> Result<String> {
    let off = usize::try_from(off).map_err(|_| ParseError::Invalid { offset: 0, reason: "path offset".into() })?;
    Ok(utf16le(need(d, off, len as usize)?, true))
}

/// Parse an AppCompatCache value.
pub fn parse(d: &[u8]) -> Result<ShimCache> {
    let sig = u32_at(d, 0)?;
    match sig {
        0xDEAD_BEEF => {
            let n = u32_at(d, 4)?;
            let mut entries = Vec::new();
            for i in 0..(n as usize).min(MAX_ENTRIES) {
                let o = 400 + i * 552;
                let Ok(e) = need(d, o, 552) else { break };
                let mut x = entry(i, utf16le(&e[..520], true), u64_at(e, 528)?);
                x.file_size = Some(u64_at(e, 536)?);
                x.last_update_ns = filetime_to_ns(u64_at(e, 544)?);
                entries.push(x);
            }
            Ok(ShimCache { format: "winxp_32", declared_entries: Some(n), entries })
        }
        0xBADC_0FFE => {
            let n = u32_at(d, 4)?;
            let is64 = n > 0 && u32_at(d, 8 + 4)? == 0;
            let (size, fmt) = if is64 { (32, "win2003_vista_64") } else { (24, "win2003_vista_32") };
            let mut entries = Vec::new();
            let mut raw_fields = Vec::new();
            for i in 0..(n as usize).min(MAX_ENTRIES) {
                let o = 8 + i * size;
                let Ok(e) = need(d, o, size) else { break };
                let len = u16_at(e, 0)?;
                let (poff, mt, extra) = if is64 { (u64_at(e, 8)?, u64_at(e, 16)?, u64_at(e, 24)?) } else { (u32_at(e, 4)? as u64, u64_at(e, 8)?, u64_at(e, 16)?) };
                let Ok(p) = path_at(d, poff, len) else { break };
                raw_fields.push(extra);
                entries.push(entry(i, p, mt));
            }
            // Vista/2008 store (insert flags, shim flags); 2003 stores a file size.
            let looks_like_flags = !raw_fields.is_empty() && raw_fields.iter().all(|v| (v & 0xFFFF_FFFF) <= 0xFFFF && (v >> 32) <= 0xFFFF);
            for (e, v) in entries.iter_mut().zip(raw_fields) {
                if looks_like_flags {
                    e.insert_flags = Some(v as u32);
                    e.shim_flags = Some((v >> 32) as u32);
                    e.executed = Some(v & 0x2 != 0);
                } else {
                    e.file_size = Some(v);
                }
            }
            Ok(ShimCache { format: fmt, declared_entries: Some(n), entries })
        }
        0xBADC_0FEE => {
            let n = u32_at(d, 4)?;
            let is64 = n > 0 && u32_at(d, 128 + 4)? == 0;
            let (size, fmt) = if is64 { (48, "win7_64") } else { (32, "win7_32") };
            let mut entries = Vec::new();
            for i in 0..(n as usize).min(MAX_ENTRIES) {
                let o = 128 + i * size;
                let Ok(e) = need(d, o, size) else { break };
                let len = u16_at(e, 0)?;
                let (poff, mt, fl, sf, ds) = if is64 {
                    (u64_at(e, 8)?, u64_at(e, 16)?, u32_at(e, 24)?, u32_at(e, 28)?, u64_at(e, 32)?)
                } else {
                    (u32_at(e, 4)? as u64, u64_at(e, 8)?, u32_at(e, 16)?, u32_at(e, 20)?, u32_at(e, 24)? as u64)
                };
                let Ok(p) = path_at(d, poff, len) else { break };
                let mut x = entry(i, p, mt);
                x.insert_flags = Some(fl);
                x.shim_flags = Some(sf);
                x.executed = Some(fl & 0x2 != 0);
                x.data_size = Some(ds);
                entries.push(x);
            }
            Ok(ShimCache { format: fmt, declared_entries: Some(n), entries })
        }
        0x80 if matches!(d.get(128..132), Some(b"00ts") | Some(b"10ts")) => {
            let win81 = d.get(128..132) == Some(b"10ts".as_slice());
            let mut entries = Vec::new();
            let mut o = 128usize;
            while d.get(o..o + 4).is_some_and(|s| s == b"00ts" || s == b"10ts") && entries.len() < MAX_ENTRIES {
                let size = u32_at(d, o + 8)? as usize;
                let e = need(d, o + 12, size)?;
                let plen = u16_at(e, 0)? as usize;
                let path = utf16le(need(e, 2, plen)?, true);
                let mut p = 2 + plen;
                let mut package = None;
                if win81 {
                    let pk = u16_at(e, p)? as usize;
                    package = Some(utf16le(need(e, p + 2, pk)?, true)).filter(|s| !s.is_empty());
                    p += 2 + pk;
                }
                let fl = u32_at(e, p)?;
                let sf = u32_at(e, p + 4)?;
                let mt = u64_at(e, p + 8)?;
                let ds = u32_at(e, p + 16)?;
                let mut x = entry(entries.len(), path, mt);
                x.insert_flags = Some(fl);
                x.shim_flags = Some(sf);
                x.executed = Some(fl & 0x2 != 0);
                x.data_size = Some(ds as u64);
                x.package = package;
                entries.push(x);
                o = o + 12 + size;
            }
            Ok(ShimCache { format: if win81 { "win8.1" } else { "win8.0" }, declared_entries: None, entries })
        }
        0x30 | 0x34 => {
            let n = None;
            let mut entries = Vec::new();
            let mut o = sig as usize;
            while d.get(o..o + 4) == Some(b"10ts".as_slice()) && entries.len() < MAX_ENTRIES {
                let size = u32_at(d, o + 8)? as usize;
                let e = need(d, o + 12, size)?;
                let plen = u16_at(e, 0)? as usize;
                let path = utf16le(need(e, 2, plen)?, true);
                let mt = u64_at(e, 2 + plen)?;
                let ds = u32_at(e, 10 + plen)?;
                let mut x = entry(entries.len(), path, mt);
                x.data_size = Some(ds as u64);
                entries.push(x);
                o = o + 12 + size;
            }
            Ok(ShimCache { format: if sig == 0x30 { "win10" } else { "win10_creators" }, declared_entries: n, entries })
        }
        other => Err(ParseError::Unsupported(format!("AppCompatCache signature {other:#010x}"))),
    }
}

/// Locate and parse the cache in a SYSTEM hive: (root-relative key path, key offset, cache).
pub fn from_hive(hive: &Hive) -> Option<(String, u32, Result<ShimCache>)> {
    let ccs = current_control_set(hive)?;
    for sub in ["AppCompatCache", "AppCompatibility"] {
        let rel = format!("{ccs}\\Control\\Session Manager\\{sub}");
        if let Some(k) = hive.key(&rel) {
            if let Some(v) = k.value("AppCompatCache") {
                return Some((rel, k.offset, parse(&v.raw)));
            }
        }
    }
    None
}

pub fn events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    let Some((rel, off, res)) = from_hive(hive) else { return vec![] };
    let Ok(cache) = res else { return vec![] };
    cache
        .entries
        .into_iter()
        .map(|e| {
            let mut ev = ctx
                .event("appcompatcache", "windows:registry:appcompatcache", desc::MODIFICATION, e.last_modified_ns, format!("[{}] Cached entry: {} Path: {}", ctx.full_path(&rel), e.index + 1, e.path), &rel, off)
                .attr("path", e.path.clone())
                .attr("entry_index", e.index as u64)
                .attr("format", cache.format);
            if let Some(x) = e.executed {
                ev = ev.attr("executed", x);
            }
            if let Some(x) = e.insert_flags {
                ev = ev.attr("insert_flags", x);
            }
            if let Some(x) = e.file_size {
                ev = ev.attr("file_size", x);
            }
            if let Some(x) = &e.package {
                ev = ev.attr("package", x.clone());
            }
            ev
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn registry_shimcache_win10_synthetic() {
        let mut d = vec![0u8; 0x34];
        d[..4].copy_from_slice(&0x34u32.to_le_bytes());
        for (p, t) in [("C:\\a.exe", 130_000_000_000_000_000u64), ("C:\\b.exe", 131_000_000_000_000_000)] {
            let path = utf16(p);
            let mut body = Vec::new();
            body.extend((path.len() as u16).to_le_bytes());
            body.extend(&path);
            body.extend(t.to_le_bytes());
            body.extend(0u32.to_le_bytes());
            d.extend(b"10ts");
            d.extend(0u32.to_le_bytes());
            d.extend((body.len() as u32).to_le_bytes());
            d.extend(body);
        }
        let c = parse(&d).unwrap();
        assert_eq!(c.format, "win10_creators");
        assert_eq!(c.entries.len(), 2);
        assert_eq!(c.entries[1].path, "C:\\b.exe");
        assert_eq!(c.entries[1].last_modified_raw, 131_000_000_000_000_000);
        // Truncations never panic.
        for n in 0..d.len() {
            let _ = parse(&d[..n]);
        }
    }

    #[test]
    fn registry_shimcache_win8_synthetic() {
        let mut d = vec![0u8; 128];
        d[..4].copy_from_slice(&0x80u32.to_le_bytes());
        let path = utf16("C:\\x.exe");
        let mut body = Vec::new();
        body.extend((path.len() as u16).to_le_bytes());
        body.extend(&path);
        body.extend(0u16.to_le_bytes()); // package length (8.1)
        body.extend(2u32.to_le_bytes());
        body.extend(0u32.to_le_bytes());
        body.extend(129_000_000_000_000_000u64.to_le_bytes());
        body.extend(0u32.to_le_bytes());
        d.extend(b"10ts");
        d.extend(0u32.to_le_bytes());
        d.extend((body.len() as u32).to_le_bytes());
        d.extend(body);
        let c = parse(&d).unwrap();
        assert_eq!(c.format, "win8.1");
        assert_eq!(c.entries[0].executed, Some(true));
        assert_eq!(c.entries[0].path, "C:\\x.exe");
    }
}
