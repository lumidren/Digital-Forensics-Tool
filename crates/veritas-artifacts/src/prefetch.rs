//! Windows Prefetch (.pf) parser: SCCA versions 17 (XP/2003), 23 (Vista/7), 26 (8/8.1),
//! 30 and 31 (10/11), including the Windows 10+ `MAM\x04` LZXPRESS Huffman container.
use crate::error::{ParseError, Result};
use crate::util::{need, u16_at, u32_at, u64_at, utf16le};
use serde::Serialize;
use serde_json::json;
use veritas_timeline::{desc, filetime_to_ns, Event};

/// Maximum decompressed size accepted from a MAM header.
pub const MAX_DECOMPRESSED: usize = 64 * 1024 * 1024; // THREAT:T3.5 decompression-bomb cap
const MAX_METRICS: usize = 1 << 20;
const MAX_VOLUMES: usize = 1024;
const MAX_DIR_STRINGS: usize = 1 << 20;

#[derive(Debug, Clone, Serialize)]
pub struct FileMetric {
    pub filename: String,
    pub flags: u32,
    pub mft_entry: Option<u64>,
    pub mft_sequence: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Volume {
    pub device_path: String,
    pub creation_filetime: u64,
    pub creation_ns: Option<i64>,
    pub serial_number: u32,
    pub directory_strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Prefetch {
    pub version: u32,
    pub compressed: bool,
    pub executable_filename: String,
    pub prefetch_hash: u32,
    pub run_count: u32,
    /// Raw FILETIMEs, zero entries dropped, most recent first.
    pub last_run_filetimes: Vec<u64>,
    pub last_run_ns: Vec<i64>,
    pub file_metrics: Vec<FileMetric>,
    pub volumes: Vec<Volume>,
}

impl Prefetch {
    pub fn filenames(&self) -> Vec<String> {
        self.file_metrics.iter().map(|m| m.filename.clone()).collect()
    }
}

// ---------------------------------------------------------------- LZXPRESS Huffman (MS-XCA 2.2.4)

struct Table {
    // index: 15-bit prefix → (symbol, bit length)
    entries: Vec<(u16, u8)>,
}

fn build_table(lengths: &[u8; 512]) -> Result<Table> {
    let mut entries = vec![(0u16, 0u8); 1 << 15];
    let mut code: u32 = 0;
    let mut filled = false;
    for len in 1..=15u8 {
        for (sym, &l) in lengths.iter().enumerate() {
            if l != len {
                continue;
            }
            let shift = 15 - len as u32;
            let start = (code << shift) as usize;
            let count = 1usize << shift;
            if start + count > entries.len() {
                return Err(ParseError::Invalid { offset: 0, reason: "LZXPRESS Huffman table over-subscribed".into() });
            }
            for e in &mut entries[start..start + count] {
                *e = (sym as u16, len);
            }
            filled = true;
            code += 1;
        }
        code <<= 1;
    }
    if !filled {
        return Err(ParseError::Invalid { offset: 0, reason: "empty LZXPRESS Huffman table".into() });
    }
    Ok(Table { entries })
}

/// Decompress an LZXPRESS Huffman stream into exactly `out_size` bytes.
pub fn lzxpress_huffman_decompress(input: &[u8], out_size: usize) -> Result<Vec<u8>> {
    if out_size > MAX_DECOMPRESSED {
        return Err(ParseError::Limit(format!("decompressed size {out_size} exceeds {MAX_DECOMPRESSED}")));
    }
    let mut out: Vec<u8> = Vec::with_capacity(out_size);
    let mut pos = 0usize;
    let rd16 = |p: usize| -> u32 { if p + 1 < input.len() { u16::from_le_bytes([input[p], input[p + 1]]) as u32 } else if p < input.len() { input[p] as u32 } else { 0 } };
    while out.len() < out_size {
        let tbytes = need(input, pos, 256)?;
        let mut lengths = [0u8; 512];
        for (i, b) in tbytes.iter().enumerate() {
            lengths[2 * i] = b & 0x0f;
            lengths[2 * i + 1] = b >> 4;
        }
        let table = build_table(&lengths)?;
        pos += 256;
        let mut next_bits: u32 = (rd16(pos) << 16) | rd16(pos + 2);
        pos += 4;
        let mut extra: i32 = 16;
        let block_end = (out.len() + 65536).min(out_size);
        while out.len() < block_end {
            let (sym, len) = table.entries[(next_bits >> 17) as usize];
            if len == 0 {
                return Err(ParseError::Invalid { offset: pos, reason: "invalid Huffman code".into() });
            }
            next_bits <<= len;
            extra -= len as i32;
            if extra < 0 {
                if pos > input.len() + 4 {
                    return Err(ParseError::Truncated { offset: pos, needed: 2, available: 0 });
                }
                next_bits |= rd16(pos) << (-extra) as u32;
                extra += 16;
                pos += 2;
            }
            if sym < 256 {
                out.push(sym as u8);
                continue;
            }
            let s = sym - 256;
            let mut mlen = (s & 15) as usize;
            let obits = (s >> 4) as u32;
            if mlen == 15 {
                mlen = *input.get(pos).ok_or(ParseError::Truncated { offset: pos, needed: 1, available: 0 })? as usize;
                pos += 1;
                if mlen == 255 {
                    mlen = u16_at(input, pos)? as usize;
                    pos += 2;
                    if mlen == 0 {
                        mlen = u32_at(input, pos)? as usize;
                        pos += 4;
                    }
                    if mlen < 15 {
                        return Err(ParseError::Invalid { offset: pos, reason: "bad match length".into() });
                    }
                    mlen -= 15;
                }
                mlen += 15;
            }
            mlen += 3;
            let moff = if obits == 0 { 1usize } else { ((next_bits >> (32 - obits)) as usize) + (1usize << obits) };
            if obits > 0 {
                next_bits = if obits >= 32 { 0 } else { next_bits << obits };
                extra -= obits as i32;
                if extra < 0 {
                    next_bits |= rd16(pos) << (-extra) as u32;
                    extra += 16;
                    pos += 2;
                }
            }
            if moff > out.len() {
                return Err(ParseError::Invalid { offset: pos, reason: format!("match offset {moff} before start of output") });
            }
            let mlen = mlen.min(out_size - out.len());
            let start = out.len() - moff;
            for i in 0..mlen {
                let b = out[start + i];
                out.push(b);
            }
        }
        // MS-XCA: the next block's 256-byte table starts at the current input position.
    }
    Ok(out)
}

/// Unwrap a `MAM\x04` / `MAM\x84` container; returns the input unchanged if not compressed.
pub fn decompress_mam(data: &[u8]) -> Result<(Vec<u8>, bool)> {
    let sig = need(data, 0, 4)?;
    if &sig[..3] != b"MAM" {
        return Ok((data.to_vec(), false));
    }
    let size = u32_at(data, 4)? as usize;
    let (kind, start) = (sig[3] & 0x0f, if sig[3] & 0x80 != 0 { 12 } else { 8 });
    if kind != 4 {
        return Err(ParseError::Unsupported(format!("MAM compression format {kind}")));
    }
    if size > MAX_DECOMPRESSED {
        return Err(ParseError::Limit(format!("MAM declares {size} bytes"))); // THREAT:T3.5
    }
    Ok((lzxpress_huffman_decompress(&data[start.min(data.len())..], size)?, true))
}

// ---------------------------------------------------------------- SCCA

pub fn parse(raw: &[u8]) -> Result<Prefetch> {
    let (d, compressed) = decompress_mam(raw)?;
    let d = &d[..];
    let version = u32_at(d, 0)?;
    let sig = need(d, 4, 4)?;
    if sig != b"SCCA" {
        return Err(ParseError::BadSignature { offset: 4, expected: "SCCA".into(), found: hex::encode(sig) });
    }
    let exe = utf16le(need(d, 16, 60)?, true);
    let hash = u32_at(d, 76)?;
    let metrics_off = u32_at(d, 84)? as usize;
    let metrics_cnt = u32_at(d, 88)? as usize;
    let fn_off = u32_at(d, 100)? as usize;
    let fn_size = u32_at(d, 104)? as usize;
    let vol_off = u32_at(d, 108)? as usize;
    let vol_cnt = u32_at(d, 112)? as usize;
    let vol_size = u32_at(d, 116)? as usize;
    let (run_times_off, n_runs, run_count_off) = match version {
        17 => (120, 1, 144),
        23 => (128, 1, 152),
        26 => (128, 8, 208),
        30 | 31 => {
            // Two variants exist; the shorter header (metrics at 0x128) moves the run count.
            if metrics_off == 0x128 { (128, 8, 200) } else { (128, 8, 208) }
        }
        v => return Err(ParseError::Unsupported(format!("prefetch format version {v}"))),
    };
    let mut times = Vec::new();
    for i in 0..n_runs {
        let t = u64_at(d, run_times_off + i * 8)?;
        if t != 0 {
            times.push(t);
        }
    }
    let run_count = u32_at(d, run_count_off)?;

    if metrics_cnt > MAX_METRICS || vol_cnt > MAX_VOLUMES {
        return Err(ParseError::Limit(format!("metrics {metrics_cnt} / volumes {vol_cnt}")));
    }
    let fn_block = need(d, fn_off, fn_size)?; // THREAT:T3.2 length field checked against the slice
    let msize = if version == 17 { 20 } else { 32 };
    let mut metrics = Vec::with_capacity(metrics_cnt);
    for i in 0..metrics_cnt {
        let m = need(d, metrics_off + i * msize, msize)?;
        let (name_off, name_len, flags) = if version == 17 { (u32_at(m, 8)?, u32_at(m, 12)?, u32_at(m, 16)?) } else { (u32_at(m, 12)?, u32_at(m, 16)?, u32_at(m, 20)?) };
        let name = need(fn_block, name_off as usize, (name_len as usize).saturating_mul(2)).map(|b| utf16le(b, true)).unwrap_or_default();
        let (mft_entry, mft_sequence) = if version == 17 {
            (None, None)
        } else {
            let r = u64_at(m, 24)?;
            if r == 0 { (None, None) } else { (Some(r & 0x0000_ffff_ffff_ffff), Some((r >> 48) as u16)) }
        };
        metrics.push(FileMetric { filename: name, flags, mft_entry, mft_sequence });
    }
    let vblock = need(d, vol_off, vol_size)?;
    let vsize = match version {
        17 => 40,
        23 | 26 => 104,
        _ => 96,
    };
    let mut volumes = Vec::with_capacity(vol_cnt);
    for i in 0..vol_cnt {
        let v = need(vblock, i * vsize, vsize)?;
        let dp_off = u32_at(v, 0)? as usize;
        let dp_len = u32_at(v, 4)? as usize;
        let ct = u64_at(v, 8)?;
        let serial = u32_at(v, 16)?;
        let ds_off = u32_at(v, 28)? as usize;
        let ds_cnt = u32_at(v, 32)? as usize;
        let device_path = utf16le(need(vblock, dp_off, dp_len.saturating_mul(2))?, true);
        let mut dirs = Vec::new();
        let mut p = ds_off;
        for _ in 0..ds_cnt.min(MAX_DIR_STRINGS) {
            let Ok(n) = u16_at(vblock, p) else { break };
            let Ok(s) = need(vblock, p + 2, n as usize * 2) else { break };
            dirs.push(utf16le(s, false));
            p += 2 + (n as usize + 1) * 2;
        }
        volumes.push(Volume { device_path, creation_filetime: ct, creation_ns: filetime_to_ns(ct), serial_number: serial, directory_strings: dirs });
    }
    Ok(Prefetch {
        version,
        compressed,
        executable_filename: exe,
        prefetch_hash: hash,
        run_count,
        last_run_ns: times.iter().filter_map(|t| filetime_to_ns(*t)).collect(),
        last_run_filetimes: times,
        file_metrics: metrics,
        volumes,
    })
}

pub fn events(p: &Prefetch, sha: &str, path: &str) -> Vec<Event> {
    let mut mapped: Vec<String> = p.filenames();
    mapped.sort();
    mapped.dedup();
    let devs: Vec<String> = p.volumes.iter().map(|v| v.device_path.clone()).collect();
    let serials: Vec<String> = p.volumes.iter().map(|v| format!("0x{:08X}", v.serial_number)).collect();
    let vol_desc: Vec<String> = p.volumes.iter().map(|v| format!("volume: {} [serial number: 0x{:08X}, device path: {}]", 1, v.serial_number, v.device_path)).collect();
    let path_hint = p
        .filenames()
        .into_iter()
        .find(|f| f.to_ascii_uppercase().ends_with(&format!("\\{}", p.executable_filename.to_ascii_uppercase())));
    let mut out = Vec::new();
    for (i, t) in p.last_run_ns.iter().enumerate() {
        let d = if i == 0 { desc::LAST_RUN } else { desc::PREVIOUS_RUN };
        let msg = format!(
            "Prefetch [{}] was executed - run count {} path hints: {} hash: 0x{:08X} {}",
            p.executable_filename,
            p.run_count,
            path_hint.clone().unwrap_or_default(),
            p.prefetch_hash,
            vol_desc.join(" ")
        );
        let mut e = Event::new("windows:prefetch:execution", d, msg)
            .with_time(Some(*t))
            .attr("executable", p.executable_filename.clone())
            .attr("prefetch_hash", format!("0x{:08X}", p.prefetch_hash))
            .attr("run_count", p.run_count)
            .attr("version", p.version)
            .attr("mapped_files", json!(mapped))
            .attr("volume_device_paths", json!(devs))
            .attr("volume_serial_numbers", json!(serials))
            .attr("path_hints", json!(path_hint));
        e.source_short = "LOG".into();
        e.source_long = "WinPrefetch".into();
        out.push(e.provenance(sha, path, i as i64, "prefetch", crate::PARSER_VERSION));
    }
    out
}
