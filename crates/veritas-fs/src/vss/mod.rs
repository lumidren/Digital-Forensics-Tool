//! Volume Shadow Copies: volume header at 0x1E00, catalog, store headers, store block lists and
//! a read-through view of each shadow copy (unmapped blocks come from newer stores, then from the
//! current volume).
use crate::error::{FsError, Result};
use crate::io::{read_vec, read_vec_padded, ReadAt, Source};
use crate::util::{guid_le, need, u16_at, u32_at, u64_at, utf16le};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

pub const VSS_IDENTIFIER: &str = "3808876b-c176-4e48-b7ae-04046e6cc752";
pub const VOLUME_HEADER_OFFSET: u64 = 0x1E00;
pub const BLOCK_SIZE: u64 = 0x4000;
/// Maximum catalog / block-list / bitmap blocks followed per chain.
pub const MAX_CHAIN_BLOCKS: usize = 1 << 16;
/// Maximum stores enumerated.
pub const MAX_STORES: usize = 512;

const FLAG_FORWARDER: u32 = 0x1;
const FLAG_OVERLAY: u32 = 0x2;
const FLAG_NOT_USED: u32 = 0x4;
/// Record types of 16 KiB metadata blocks: 1 volume header, 2 catalog, 3 block list, 4 store header,
/// 5 block range list, 6 bitmap.
const RT_BITMAP: u32 = 6;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockDescriptor {
    pub original_offset: u64,
    pub relative_offset: u64,
    pub store_data_offset: u64,
    pub flags: u32,
    pub bitmap: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreInfo {
    pub index: usize,
    pub identifier: String,
    pub copy_identifier: String,
    pub copy_set_identifier: String,
    pub creation_time_raw: u64,
    pub creation_time: Option<i64>,
    pub volume_size: u64,
    pub sequence: u64,
    pub attribute_flags: u32,
    pub operating_machine: String,
    pub service_machine: String,
    pub block_list_offset: u64,
    pub store_header_offset: u64,
    pub block_range_list_offset: u64,
    pub current_bitmap_offset: u64,
    pub previous_bitmap_offset: u64,
    pub descriptor_count: usize,
    /// Bytes of copied data held by the store (16 KiB per non-forwarder descriptor).
    pub store_size: u64,
}

struct StoreMap {
    /// original block offset -> (store data offset)
    direct: BTreeMap<u64, u64>,
    /// original block offset -> forwarded original offset
    forward: BTreeMap<u64, u64>,
    /// original block offset -> (store data offset, sector bitmap)
    overlay: BTreeMap<u64, (u64, u32)>,
    /// Current bitmap: a set bit marks a 16 KiB block that was unused when the snapshot was taken.
    unused: Option<Vec<u8>>,
}

pub struct Vss {
    src: Source,
    pub volume_size: u64,
    pub stores: Vec<StoreInfo>,
    maps: Vec<StoreMap>,
}

fn block_header_ok(b: &[u8], rtype: u32) -> bool {
    guid_le(&b[0..16]).map(|g| g == VSS_IDENTIFIER).unwrap_or(false) && u32_at(b, 20).ok() == Some(rtype)
}

impl Vss {
    /// Open shadow copy metadata of an NTFS volume (`src` is the volume, not the disk).
    pub fn open(src: Source) -> Result<Self> {
        let h = read_vec(src.as_ref(), VOLUME_HEADER_OFFSET, 128)?;
        if guid_le(&h[0..16])? != VSS_IDENTIFIER {
            return Err(FsError::sig(VOLUME_HEADER_OFFSET, VSS_IDENTIFIER, &h[0..16]));
        }
        if u32_at(&h, 20)? != 1 {
            return Err(FsError::invalid(VOLUME_HEADER_OFFSET + 20, "not a VSS volume header"));
        }
        let catalog = u64_at(&h, 48)?;
        let mut info2: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new(); // id -> (vol size, seq, ctime)
        let mut info3: BTreeMap<String, [u64; 6]> = BTreeMap::new();
        let mut order: Vec<String> = Vec::new();
        let mut off = catalog;
        let mut n = 0;
        while off != 0 && n < MAX_CHAIN_BLOCKS {
            n += 1;
            let blk = read_vec(src.as_ref(), off, BLOCK_SIZE)?;
            if !block_header_ok(&blk, 2) {
                break;
            }
            for e in blk[128..].chunks_exact(128) {
                let t = u64_at(e, 0)?;
                let id = guid_le(&e[16..32])?;
                match t {
                    2 => {
                        if !order.contains(&id) {
                            order.push(id.clone());
                        }
                        info2.insert(id, (u64_at(e, 8)?, u64_at(e, 32)?, u64_at(e, 48)?));
                    }
                    3 => {
                        info3.insert(id, [u64_at(e, 8)?, u64_at(e, 32)?, u64_at(e, 40)?, u64_at(e, 48)?, u64_at(e, 72)?, u64_at(e, 64)?]);
                    }
                    _ => {}
                }
            }
            off = u64_at(&blk, 40)?;
        }
        let mut stores = Vec::new();
        let mut maps = Vec::new();
        // Oldest first (pyvshadow / libvshadow order).
        let mut ids: Vec<(u64, u64, String)> = order.iter().filter_map(|id| info2.get(id).map(|i| (i.2, i.1, id.clone()))).collect();
        ids.sort();
        for (_, _, id) in ids.into_iter().take(MAX_STORES) {
            let Some(&(vsize, seq, ctime)) = info2.get(&id) else { continue };
            let Some(&[bl, sh, brl, cbm, pbm, _]) = info3.get(&id) else { continue };
            let (copy_id, copy_set, attr, om, sm) = match read_vec(src.as_ref(), sh, BLOCK_SIZE) {
                Ok(b) if block_header_ok(&b, 4) => {
                    let i = &b[128..];
                    let om_len = u16_at(i, 64)? as usize;
                    let om = utf16le(need(i, 66, om_len)?, false);
                    let sm_off = 66 + om_len;
                    let sm_len = u16_at(i, sm_off)? as usize;
                    let sm = utf16le(need(i, sm_off + 2, sm_len)?, false);
                    (guid_le(&i[16..32])?, guid_le(&i[32..48])?, u32_at(i, 56)?, om, sm)
                }
                _ => (String::new(), String::new(), 0, String::new(), String::new()),
            };
            let descs = read_block_list(src.as_ref(), bl)?;
            let mut m = StoreMap { direct: BTreeMap::new(), forward: BTreeMap::new(), overlay: BTreeMap::new(), unused: None };
            let mut copied = 0u64;
            for d in &descs {
                if d.flags & FLAG_NOT_USED != 0 {
                    continue;
                }
                if d.flags & FLAG_OVERLAY != 0 {
                    let e = m.overlay.entry(d.original_offset).or_insert((d.store_data_offset, 0));
                    e.0 = d.store_data_offset;
                    e.1 |= d.bitmap;
                    copied += BLOCK_SIZE;
                } else if d.flags & FLAG_FORWARDER != 0 {
                    m.forward.insert(d.original_offset, d.relative_offset);
                } else {
                    m.direct.insert(d.original_offset, d.store_data_offset);
                    copied += BLOCK_SIZE;
                }
            }
            m.unused = read_bitmap(src.as_ref(), cbm).ok();
            stores.push(StoreInfo {
                index: stores.len(),
                identifier: id.clone(),
                copy_identifier: copy_id,
                copy_set_identifier: copy_set,
                creation_time_raw: ctime,
                creation_time: veritas_timeline::filetime_to_ns(ctime),
                volume_size: vsize,
                sequence: seq,
                attribute_flags: attr,
                operating_machine: om,
                service_machine: sm,
                block_list_offset: bl,
                store_header_offset: sh,
                block_range_list_offset: brl,
                current_bitmap_offset: cbm,
                previous_bitmap_offset: pbm,
                descriptor_count: descs.len(),
                store_size: copied,
            });
            maps.push(m);
        }
        let volume_size = stores.first().map(|s| s.volume_size).unwrap_or(src.size());
        Ok(Vss { src, volume_size, stores, maps })
    }

    /// Raw block descriptors of a store (for inspection).
    pub fn descriptors(&self, store: usize) -> Result<Vec<BlockDescriptor>> {
        let s = self.stores.get(store).ok_or_else(|| FsError::NotFound(format!("store {store}")))?;
        read_block_list(self.src.as_ref(), s.block_list_offset)
    }

    /// Read one 512-byte-aligned piece of a 16 KiB block of shadow copy `store`.
    fn read_block(&self, store: usize, block_off: u64, out: &mut [u8], within: u64) -> Result<()> {
        let mut off = block_off;
        let mut k = store;
        let mut hops = 0;
        // Overlays of the requested store take precedence for the sectors they cover.
        let mut overlay: Option<(u64, u32)> = self.maps[store].overlay.get(&block_off).copied();
        while k < self.maps.len() && hops < MAX_STORES * 4 {
            hops += 1;
            let m = &self.maps[k];
            if let Some(&sd) = m.direct.get(&off) {
                let d = read_vec_padded(self.src.as_ref(), sd + within, out.len() as u64)?;
                out.copy_from_slice(&d);
                return self.apply_overlay(overlay.take(), out, within);
            }
            if let Some(&fwd) = m.forward.get(&off) {
                off = fwd;
            }
            k += 1;
        }
        // Not preserved by any store. For the most recent store, blocks flagged in its current bitmap
        // were unused when the snapshot was taken and read as zeros; everything else comes from the
        // current volume. (Matches libvshadow/pyvshadow byte-for-byte on dfvfs vss.raw, both stores.)
        let newest = store + 1 == self.maps.len();
        let in_use = match &self.maps[store].unused {
            Some(_) if !newest => true,
            Some(bm) => {
                let idx = block_off / BLOCK_SIZE;
                !bm.get((idx / 8) as usize).is_some_and(|b| b & (1 << (idx % 8)) != 0)
            }
            None => true,
        };
        if in_use {
            let d = read_vec_padded(self.src.as_ref(), off + within, out.len() as u64)?;
            out.copy_from_slice(&d);
        } else {
            out.fill(0);
        }
        self.apply_overlay(overlay, out, within)
    }

    fn apply_overlay(&self, overlay: Option<(u64, u32)>, out: &mut [u8], within: u64) -> Result<()> {
        if let Some((sd, bm)) = overlay {
            let start = within / 512;
            let end = (within + out.len() as u64).div_ceil(512);
            for s in start..end.min(32) {
                if bm & (1 << s) != 0 {
                    let a = (s * 512).max(within);
                    let b = ((s + 1) * 512).min(within + out.len() as u64);
                    let d = read_vec_padded(self.src.as_ref(), sd + a, b - a)?;
                    out[(a - within) as usize..(b - within) as usize].copy_from_slice(&d);
                }
            }
        }
        Ok(())
    }

    /// Read `len` bytes at `offset` of shadow copy `store`.
    pub fn read_store(&self, store: usize, offset: u64, len: u64) -> Result<Vec<u8>> {
        if store >= self.maps.len() {
            return Err(FsError::NotFound(format!("store {store}")));
        }
        if len > crate::io::MAX_SINGLE_READ {
            return Err(FsError::Limit("store read too large".into()));
        }
        let end = offset.saturating_add(len).min(self.volume_size);
        let mut out = Vec::with_capacity(len as usize);
        let mut pos = offset;
        while pos < end {
            let bo = pos - pos % BLOCK_SIZE;
            let within = pos - bo;
            let n = (BLOCK_SIZE - within).min(end - pos);
            let mut buf = vec![0u8; n as usize];
            self.read_block(store, bo, &mut buf, within)?;
            out.extend_from_slice(&buf);
            pos += n;
        }
        Ok(out)
    }

    /// A `ReadAt` view of shadow copy `store`, usable by the NTFS parser.
    pub fn store_source(self: &Arc<Self>, store: usize) -> Result<Source> {
        if store >= self.maps.len() {
            return Err(FsError::NotFound(format!("store {store}")));
        }
        Ok(Arc::new(StoreSource { vss: self.clone(), store }))
    }
}

struct StoreSource {
    vss: Arc<Vss>,
    store: usize,
}

impl ReadAt for StoreSource {
    fn size(&self) -> u64 { self.vss.volume_size }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.vss.volume_size {
            return Ok(0);
        }
        let d = self.vss.read_store(self.store, offset, buf.len() as u64)?;
        buf[..d.len()].copy_from_slice(&d);
        Ok(d.len())
    }
}

fn read_block_list(src: &dyn ReadAt, first: u64) -> Result<Vec<BlockDescriptor>> {
    let mut out = Vec::new();
    let mut off = first;
    let mut n = 0;
    while off != 0 && n < MAX_CHAIN_BLOCKS {
        n += 1;
        let blk = read_vec(src, off, BLOCK_SIZE)?;
        if !block_header_ok(&blk, 3) {
            break;
        }
        for d in blk[128..].chunks_exact(32) {
            let orig = u64_at(d, 0)?;
            let rel = u64_at(d, 8)?;
            let sd = u64_at(d, 16)?;
            let flags = u32_at(d, 24)?;
            if orig == 0 && rel == 0 && sd == 0 && flags == 0 {
                continue;
            }
            out.push(BlockDescriptor { original_offset: orig, relative_offset: rel, store_data_offset: sd, flags, bitmap: u32_at(d, 28)? });
        }
        off = u64_at(&blk, 40)?;
    }
    Ok(out)
}

fn read_bitmap(src: &dyn ReadAt, first: u64) -> Result<Vec<u8>> {
    if first == 0 {
        return Err(FsError::NotFound("bitmap".into()));
    }
    let mut out = Vec::new();
    let mut off = first;
    let mut n = 0;
    while off != 0 && n < MAX_CHAIN_BLOCKS {
        n += 1;
        let blk = read_vec(src, off, BLOCK_SIZE)?;
        if !block_header_ok(&blk, RT_BITMAP) {
            break;
        }
        out.extend_from_slice(&blk[128..]);
        off = u64_at(&blk, 40)?;
    }
    if out.is_empty() {
        return Err(FsError::NotFound("bitmap".into()));
    }
    Ok(out)
}

/// True when the volume carries a VSS volume header.
pub fn probe(src: &dyn ReadAt) -> bool {
    read_vec(src, VOLUME_HEADER_OFFSET, 16).ok().and_then(|h| guid_le(&h).ok()).is_some_and(|g| g == VSS_IDENTIFIER)
}
