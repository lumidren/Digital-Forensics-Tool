//! APFS (unencrypted volumes): container superblock and checkpoint selection, object maps, volume
//! superblocks, file-system B-tree records (inode, dir record, file extent, xattr) and snapshot
//! metadata. Encrypted volumes are reported and must be unlocked by the Python decrypt adapter.
use crate::error::{FsError, Result};
use crate::io::{read_vec, read_vec_padded, Source};
use crate::util::{need, u16_at, u32_at, u64_at, utf8z};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

/// Maximum B-tree depth followed.
pub const MAX_BTREE_DEPTH: usize = 16;
/// Maximum B-tree nodes visited per tree.
pub const MAX_BTREE_NODES: usize = 1 << 20;
/// Maximum records collected from one tree.
pub const MAX_RECORDS: usize = 1 << 23;
/// Maximum checkpoint descriptor blocks scanned.
pub const MAX_CHECKPOINT_BLOCKS: u64 = 1 << 16;
/// Maximum file size read into memory.
pub const MAX_FILE_READ: u64 = 1 << 30;
/// Maximum directory depth walked.
pub const MAX_DIR_DEPTH: usize = 128;

const OBJ_PHYSICAL: u32 = 0x4000_0000;
const OT_NX_SUPERBLOCK: u32 = 0x1;
const OT_BTREE: u32 = 0x2;
const OT_BTREE_NODE: u32 = 0x3;
const OT_OMAP: u32 = 0xB;
const OT_FS: u32 = 0xD;

const T_SNAP_METADATA: u8 = 1;
const T_INODE: u8 = 3;
const T_XATTR: u8 = 4;
const T_FILE_EXTENT: u8 = 8;
const T_DIR_REC: u8 = 9;

/// Fletcher-64 as used by APFS object headers.
pub fn fletcher64(block: &[u8]) -> u64 {
    let mut s1: u64 = 0;
    let mut s2: u64 = 0;
    let m = 0xFFFF_FFFFu64;
    for c in block[8..].chunks_exact(4) {
        s1 = (s1 + u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64) % m;
        s2 = (s2 + s1) % m;
    }
    let c1 = m - ((s1 + s2) % m);
    let c2 = m - ((s1 + c1) % m);
    (c2 << 32) | c1
}

pub fn checksum_ok(block: &[u8]) -> bool {
    block.len() >= 32
        && u64::from_le_bytes(block[0..8].try_into().unwrap_or([0; 8])) == fletcher64(block)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Container {
    pub block_size: u32,
    pub block_count: u64,
    pub xid: u64,
    pub uuid: String,
    pub omap_oid: u64,
    pub fs_oids: Vec<u64>,
    pub checkpoint_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VolumeInfo {
    pub index: usize,
    pub oid: u64,
    pub name: String,
    pub uuid: String,
    pub fs_flags: u64,
    pub encrypted: bool,
    pub incompat: u64,
    pub num_files: u64,
    pub num_directories: u64,
    pub num_symlinks: u64,
    pub num_snapshots: u64,
    pub last_mod_time: Option<i64>,
    pub formatted_by: String,
    pub role: u16,
    #[serde(skip)]
    omap_oid: u64,
    #[serde(skip)]
    root_tree_oid: u64,
    #[serde(skip)]
    root_tree_type: u32,
    #[serde(skip)]
    snap_meta_tree_oid: u64,
    #[serde(skip)]
    snap_meta_tree_type: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ApfsEntry {
    pub path: String,
    pub name: String,
    pub id: u64,
    pub parent_id: u64,
    pub private_id: u64,
    pub kind: String,
    pub mode: u16,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub nlink: i32,
    pub bsd_flags: u32,
    pub crtime: Option<i64>,
    pub mtime: Option<i64>,
    pub ctime: Option<i64>,
    pub atime: Option<i64>,
    pub added: Option<i64>,
    pub xattrs: Vec<String>,
    pub symlink_target: Option<String>,
    pub compressed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub xid: u64,
    pub name: String,
    pub create_time: Option<i64>,
    pub change_time: Option<i64>,
    pub sblock_oid: u64,
    pub inum: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, Default)]
struct InodeRec {
    parent_id: u64,
    private_id: u64,
    crtime: u64,
    mtime: u64,
    ctime: u64,
    atime: u64,
    nlink: i32,
    bsd_flags: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    size: u64,
}

#[derive(Debug, Clone)]
struct XattrRec {
    name: String,
    flags: u16,
    data: Vec<u8>,
}

/// Parsed file-system tree of one volume.
#[derive(Debug, Default)]
struct FsTree {
    inodes: BTreeMap<u64, InodeRec>,
    /// parent id -> (name, file id, date added, flags)
    drecs: BTreeMap<u64, Vec<(String, u64, u64, u16)>>,
    /// private (dstream) id -> logical -> (length, physical block)
    extents: BTreeMap<u64, BTreeMap<u64, (u64, u64)>>,
    xattrs: BTreeMap<u64, Vec<XattrRec>>,
}

pub struct Apfs {
    src: Source,
    pub container: Container,
    pub volumes: Vec<VolumeInfo>,
    omap: BTreeMap<u64, Vec<(u64, u64)>>,
    trees: Mutex<BTreeMap<usize, Arc<FsTree>>>,
}

fn ns(v: u64) -> Option<i64> {
    if v == 0 {
        None
    } else {
        i64::try_from(v).ok()
    }
}

impl Apfs {
    pub fn open(src: Source) -> Result<Self> {
        let b0 = read_vec(src.as_ref(), 0, 4096)?;
        if need(&b0, 32, 4)? != b"NXSB" {
            return Err(FsError::sig(32, "NXSB", &b0[32..36]));
        }
        let bs = u32_at(&b0, 0x24)?;
        if !(4096..=65536).contains(&bs) || !bs.is_power_of_two() {
            return Err(FsError::invalid(0x24, "APFS block size"));
        }
        let b0 = read_vec_padded(src.as_ref(), 0, bs as u64)?;
        let mut best = (u64_at(&b0, 0x10)?, b0.clone(), 0u64);
        // Latest valid checkpoint superblock in the (contiguous) checkpoint descriptor area.
        let desc_blocks = u32_at(&b0, 0x68)?;
        let desc_base = u64_at(&b0, 0x70)?;
        if desc_blocks & 0x8000_0000 == 0 {
            for i in 0..(desc_blocks as u64).min(MAX_CHECKPOINT_BLOCKS) {
                let addr = desc_base.saturating_add(i);
                let Ok(blk) = read_vec(src.as_ref(), addr.saturating_mul(bs as u64), bs as u64)
                else {
                    break;
                };
                if u32_at(&blk, 0x18)? & 0xFFFF == OT_NX_SUPERBLOCK
                    && &blk[32..36] == b"NXSB"
                    && checksum_ok(&blk)
                {
                    let xid = u64_at(&blk, 0x10)?;
                    if xid > best.0 || best.2 == 0 && !checksum_ok(&best.1) {
                        best = (xid, blk, addr);
                    }
                }
            }
        }
        let nx = best.1;
        let max_fs = (u32_at(&nx, 0xB4)? as usize).min(100);
        let mut fs_oids = Vec::new();
        for i in 0..max_fs {
            let o = u64_at(&nx, 0xB8 + i * 8)?;
            if o != 0 {
                fs_oids.push(o);
            }
        }
        let container = Container {
            block_size: bs,
            block_count: u64_at(&nx, 0x28)?,
            xid: best.0,
            uuid: crate::util::uuid_be(need(&nx, 0x48, 16)?)?,
            omap_oid: u64_at(&nx, 0xA0)?,
            fs_oids,
            checkpoint_block: best.2,
        };
        let mut fs = Apfs {
            src,
            container,
            volumes: Vec::new(),
            omap: BTreeMap::new(),
            trees: Mutex::new(BTreeMap::new()),
        };
        fs.omap = fs.load_omap(fs.container.omap_oid)?;
        for (i, &oid) in fs.container.fs_oids.clone().iter().enumerate() {
            let Some(paddr) = Self::omap_lookup(&fs.omap, oid, fs.container.xid) else {
                continue;
            };
            let Ok(b) = fs.read_block(paddr) else {
                continue;
            };
            if need(&b, 32, 4)? != b"APSB" || u32_at(&b, 0x18)? & 0xFFFF != OT_FS {
                continue;
            }
            let fs_flags = u64_at(&b, 0x108)?;
            fs.volumes.push(VolumeInfo {
                index: i,
                oid,
                name: utf8z(need(&b, 0x2C0, 256)?),
                uuid: crate::util::uuid_be(need(&b, 0xF0, 16)?)?,
                fs_flags,
                encrypted: fs_flags & 0x1 == 0,
                incompat: u64_at(&b, 0x38)?,
                num_files: u64_at(&b, 0xB8)?,
                num_directories: u64_at(&b, 0xC0)?,
                num_symlinks: u64_at(&b, 0xC8)?,
                num_snapshots: u64_at(&b, 0xD8)?,
                last_mod_time: ns(u64_at(&b, 0x100)?),
                formatted_by: utf8z(need(&b, 0x110, 32)?),
                role: u16_at(&b, 0x3C4)?,
                omap_oid: u64_at(&b, 0x80)?,
                root_tree_oid: u64_at(&b, 0x88)?,
                root_tree_type: u32_at(&b, 0x74)?,
                snap_meta_tree_oid: u64_at(&b, 0x98)?,
                snap_meta_tree_type: u32_at(&b, 0x7C)?,
            });
        }
        Ok(fs)
    }

    fn read_block(&self, paddr: u64) -> Result<Vec<u8>> {
        let bs = self.container.block_size as u64;
        if paddr >= self.container.block_count.max(1) && paddr.saturating_mul(bs) >= self.src.size()
        {
            return Err(FsError::invalid(paddr, "block beyond container"));
        }
        read_vec(
            self.src.as_ref(),
            paddr
                .checked_mul(bs)
                .ok_or_else(|| FsError::invalid(paddr, "overflow"))?,
            bs,
        )
    }

    fn omap_lookup(map: &BTreeMap<u64, Vec<(u64, u64)>>, oid: u64, max_xid: u64) -> Option<u64> {
        map.get(&oid)?
            .iter()
            .filter(|(x, _)| *x <= max_xid)
            .max_by_key(|(x, _)| *x)
            .map(|(_, p)| *p)
    }

    /// Load an object map (physical omap object) into oid -> [(xid, paddr)].
    fn load_omap(&self, omap_oid: u64) -> Result<BTreeMap<u64, Vec<(u64, u64)>>> {
        let ob = self.read_block(omap_oid)?;
        if u32_at(&ob, 0x18)? & 0xFFFF != OT_OMAP {
            return Err(FsError::invalid(omap_oid, "not an omap object"));
        }
        let tree = u64_at(&ob, 0x30)?;
        let mut recs = Vec::new();
        self.collect(tree, &|o| Some(o), &mut recs)?;
        let mut m: BTreeMap<u64, Vec<(u64, u64)>> = BTreeMap::new();
        for (k, v) in recs {
            if k.len() >= 16 && v.len() >= 16 {
                let oid = u64_at(&k, 0)?;
                let xid = u64_at(&k, 8)?;
                let flags = u32_at(&v, 0)?;
                if flags & 0x1 != 0 {
                    continue; // OMAP_VAL_DELETED
                }
                m.entry(oid).or_default().push((xid, u64_at(&v, 8)?));
            }
        }
        Ok(m)
    }

    /// Collect every (key, value) of a B-tree. `resolve` maps child oids to physical addresses.
    fn collect(
        &self,
        root: u64,
        resolve: &dyn Fn(u64) -> Option<u64>,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        let paddr =
            resolve(root).ok_or_else(|| FsError::NotFound(format!("B-tree root oid {root}")))?;
        let rb = self.read_block(paddr)?;
        let (ks, vs) = if u16_at(&rb, 0x20)? & 0x4 != 0 {
            let info = rb.len() - 0x28;
            (
                u32_at(&rb, info + 8)? as usize,
                u32_at(&rb, info + 12)? as usize,
            )
        } else {
            (0, 0)
        };
        let mut nodes = 0usize;
        let mut seen = BTreeSet::new();
        self.collect_node(rb, paddr, 0, ks, vs, resolve, out, &mut nodes, &mut seen)
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_node(
        &self,
        b: Vec<u8>,
        paddr: u64,
        depth: usize,
        ks: usize,
        vs: usize,
        resolve: &dyn Fn(u64) -> Option<u64>,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
        nodes: &mut usize,
        seen: &mut BTreeSet<u64>,
    ) -> Result<()> {
        *nodes += 1;
        if depth > MAX_BTREE_DEPTH || *nodes > MAX_BTREE_NODES || !seen.insert(paddr) {
            return Err(FsError::Limit(
                "B-tree too deep, too large or cyclic".into(),
            ));
        }
        let t = u32_at(&b, 0x18)? & 0xFFFF;
        if t != OT_BTREE && t != OT_BTREE_NODE {
            return Err(FsError::invalid(
                paddr,
                format!("not a B-tree node (type {t:#x})"),
            ));
        }
        if !checksum_ok(&b) {
            return Err(FsError::invalid(
                paddr,
                "B-tree node checksum mismatch (encrypted or corrupt)",
            ));
        }
        let flags = u16_at(&b, 0x20)?;
        let level = u16_at(&b, 0x22)?;
        let nkeys = u32_at(&b, 0x24)? as usize;
        let toc_off = u16_at(&b, 0x28)? as usize;
        let toc_len = u16_at(&b, 0x2A)? as usize;
        let toc_start = 0x38 + toc_off;
        let key_start = toc_start + toc_len;
        let val_end = if flags & 0x1 != 0 {
            b.len() - 0x28
        } else {
            b.len()
        };
        let fixed = flags & 0x4 != 0;
        let leaf = flags & 0x2 != 0;
        for i in 0..nkeys.min(65536) {
            let (k_off, k_len, v_off, v_len) = if fixed {
                let e = toc_start + i * 4;
                (
                    u16_at(&b, e)? as usize,
                    ks,
                    u16_at(&b, e + 2)? as usize,
                    if leaf { vs } else { 8 },
                )
            } else {
                let e = toc_start + i * 8;
                (
                    u16_at(&b, e)? as usize,
                    u16_at(&b, e + 2)? as usize,
                    u16_at(&b, e + 4)? as usize,
                    u16_at(&b, e + 6)? as usize,
                )
            };
            let key = need(&b, key_start + k_off, k_len)?.to_vec();
            if v_off == 0xFFFF {
                continue;
            }
            let vstart = val_end
                .checked_sub(v_off)
                .ok_or_else(|| FsError::invalid(paddr, "value offset"))?;
            let val = need(&b, vstart, v_len)?.to_vec();
            if leaf || level == 0 {
                if out.len() >= MAX_RECORDS {
                    return Err(FsError::Limit("too many B-tree records".into()));
                }
                out.push((key, val));
            } else {
                let child = u64_at(&val, 0)?;
                let Some(cp) = resolve(child) else { continue };
                let cb = self.read_block(cp)?;
                self.collect_node(cb, cp, depth + 1, ks, vs, resolve, out, nodes, seen)?;
            }
        }
        Ok(())
    }

    fn volume(&self, vol: usize) -> Result<&VolumeInfo> {
        self.volumes
            .get(vol)
            .ok_or_else(|| FsError::NotFound(format!("APFS volume {vol}")))
    }

    fn load_tree(&self, vol: usize) -> Result<Arc<FsTree>> {
        if let Some(t) = self
            .trees
            .lock()
            .map_err(|_| FsError::Io("tree cache poisoned".into()))?
            .get(&vol)
        {
            return Ok(t.clone());
        }
        let t = Arc::new(self.parse_tree(vol)?);
        self.trees
            .lock()
            .map_err(|_| FsError::Io("tree cache poisoned".into()))?
            .insert(vol, t.clone());
        Ok(t)
    }

    fn parse_tree(&self, vol: usize) -> Result<FsTree> {
        let v = self.volume(vol)?;
        let vomap = self.load_omap(v.omap_oid)?;
        let xid = self.container.xid;
        let physical = v.root_tree_type & OBJ_PHYSICAL != 0;
        let resolve = |o: u64| {
            if physical {
                Some(o)
            } else {
                Self::omap_lookup(&vomap, o, xid)
            }
        };
        let mut recs = Vec::new();
        if let Err(e) = self.collect(v.root_tree_oid, &resolve, &mut recs) {
            if v.encrypted {
                return Err(FsError::Unsupported(format!(
                    "encrypted APFS volume '{}': unlock with the Python decrypt adapter ({e})",
                    v.name
                )));
            }
            return Err(e);
        }
        let mut t = FsTree::default();
        for (k, val) in recs {
            if k.len() < 8 {
                continue;
            }
            let hdr = u64_at(&k, 0)?;
            let oid = hdr & 0x0FFF_FFFF_FFFF_FFFF;
            let typ = (hdr >> 60) as u8;
            match typ {
                T_INODE if val.len() >= 0x5C => {
                    let mut r = InodeRec {
                        parent_id: u64_at(&val, 0)?,
                        private_id: u64_at(&val, 8)?,
                        crtime: u64_at(&val, 0x10)?,
                        mtime: u64_at(&val, 0x18)?,
                        ctime: u64_at(&val, 0x20)?,
                        atime: u64_at(&val, 0x28)?,
                        nlink: u32_at(&val, 0x38)? as i32,
                        bsd_flags: u32_at(&val, 0x44)?,
                        uid: u32_at(&val, 0x48)?,
                        gid: u32_at(&val, 0x4C)?,
                        mode: u16_at(&val, 0x50)?,
                        size: 0,
                    };
                    if let Some(sz) = xfield_dstream_size(&val[0x5C..]) {
                        r.size = sz;
                    }
                    t.inodes.insert(oid, r);
                }
                T_DIR_REC if val.len() >= 18 => {
                    // Hashed key (name_len_and_hash u32) or plain key (name_len u16).
                    let nlh = u32_at(&k, 8).unwrap_or(0);
                    let hashed_len = (nlh & 0x3FF) as usize;
                    let name = if 12 + hashed_len == k.len() {
                        utf8z(&k[12..])
                    } else {
                        let l = u16_at(&k, 8)? as usize;
                        utf8z(need(&k, 10, l.min(k.len().saturating_sub(10)))?)
                    };
                    t.drecs.entry(oid).or_default().push((
                        name,
                        u64_at(&val, 0)?,
                        u64_at(&val, 8)?,
                        u16_at(&val, 16)?,
                    ));
                }
                T_FILE_EXTENT if k.len() >= 16 && val.len() >= 24 => {
                    let logical = u64_at(&k, 8)?;
                    let len = u64_at(&val, 0)? & 0x00FF_FFFF_FFFF_FFFF;
                    t.extents
                        .entry(oid)
                        .or_default()
                        .insert(logical, (len, u64_at(&val, 8)?));
                }
                T_XATTR if k.len() >= 10 && val.len() >= 4 => {
                    let l = u16_at(&k, 8)? as usize;
                    let name = utf8z(need(&k, 10, l.min(k.len().saturating_sub(10)))?);
                    let flags = u16_at(&val, 0)?;
                    let dl = u16_at(&val, 2)? as usize;
                    let data = need(&val, 4, dl.min(val.len() - 4))?.to_vec();
                    t.xattrs
                        .entry(oid)
                        .or_default()
                        .push(XattrRec { name, flags, data });
                }
                _ => {}
            }
        }
        Ok(t)
    }

    /// All files and directories of volume `vol`, sorted by path.
    pub fn walk(&self, vol: usize) -> Result<Vec<ApfsEntry>> {
        let t = self.load_tree(vol)?;
        let mut out = Vec::new();
        let mut stack: Vec<(u64, String, usize)> = vec![(2, String::new(), 0)];
        let mut visited = BTreeSet::new();
        visited.insert(2u64);
        while let Some((dir, prefix, depth)) = stack.pop() {
            for (name, fid, added, flags) in t.drecs.get(&dir).cloned().unwrap_or_default() {
                let path = format!("{prefix}/{name}");
                let e = make_entry(&t, &path, &name, fid, added);
                let is_dir = flags & 0xF == 4 || e.kind == "dir";
                if is_dir && depth < MAX_DIR_DEPTH && visited.insert(fid) {
                    stack.push((fid, path.clone(), depth + 1));
                }
                out.push(e);
            }
        }
        out.sort_by(|a, b| (&a.path, a.id).cmp(&(&b.path, b.id)));
        Ok(out)
    }

    /// Read the data fork of inode `id`.
    pub fn read_inode(&self, vol: usize, id: u64) -> Result<Vec<u8>> {
        let t = self.load_tree(vol)?;
        self.read_with_tree(&t, id)
    }

    fn read_with_tree(&self, t: &FsTree, id: u64) -> Result<Vec<u8>> {
        let ino = t
            .inodes
            .get(&id)
            .ok_or_else(|| FsError::NotFound(format!("inode {id}")))?;
        if ino.bsd_flags & 0x20 != 0 {
            return Err(FsError::Unsupported(
                "APFS transparent compression (decmpfs)".into(),
            ));
        }
        if ino.size > MAX_FILE_READ {
            return Err(FsError::Limit("file too large".into()));
        }
        let mut out = vec![0u8; ino.size as usize];
        let bs = self.container.block_size as u64;
        if let Some(ext) = t.extents.get(&ino.private_id) {
            for (&logical, &(len, phys)) in ext {
                if logical >= ino.size || phys == 0 {
                    continue;
                }
                let n = len.min(ino.size - logical);
                let d = read_vec_padded(self.src.as_ref(), phys.saturating_mul(bs), n)?;
                out[logical as usize..logical as usize + d.len()].copy_from_slice(&d);
            }
        }
        Ok(out)
    }

    pub fn lookup(&self, vol: usize, path: &str) -> Result<u64> {
        let t = self.load_tree(vol)?;
        lookup_in(&t, path)
    }

    pub fn read_file(&self, vol: usize, path: &str) -> Result<Vec<u8>> {
        let t = self.load_tree(vol)?;
        let id = lookup_in(&t, path)?;
        self.read_with_tree(&t, id)
    }

    /// Snapshots of volume `vol` from the snapshot metadata tree.
    pub fn snapshots(&self, vol: usize) -> Result<Vec<Snapshot>> {
        let v = self.volume(vol)?;
        if v.snap_meta_tree_oid == 0 {
            return Ok(vec![]);
        }
        let physical = v.snap_meta_tree_type & OBJ_PHYSICAL != 0;
        let vomap = if physical {
            BTreeMap::new()
        } else {
            self.load_omap(v.omap_oid)?
        };
        let xid = self.container.xid;
        let resolve = |o: u64| {
            if physical {
                Some(o)
            } else {
                Self::omap_lookup(&vomap, o, xid)
            }
        };
        let mut recs = Vec::new();
        self.collect(v.snap_meta_tree_oid, &resolve, &mut recs)?;
        let mut out = Vec::new();
        for (k, val) in recs {
            let hdr = u64_at(&k, 0)?;
            if (hdr >> 60) as u8 != T_SNAP_METADATA || val.len() < 0x32 {
                continue;
            }
            let nl = u16_at(&val, 0x30)? as usize;
            out.push(Snapshot {
                xid: hdr & 0x0FFF_FFFF_FFFF_FFFF,
                name: utf8z(need(&val, 0x32, nl.min(val.len() - 0x32))?),
                create_time: ns(u64_at(&val, 0x10)?),
                change_time: ns(u64_at(&val, 0x18)?),
                sblock_oid: u64_at(&val, 0x08)?,
                inum: u64_at(&val, 0x20)?,
                flags: u32_at(&val, 0x2C)?,
            });
        }
        out.sort_by_key(|s| s.xid);
        Ok(out)
    }
}

fn lookup_in(t: &FsTree, path: &str) -> Result<u64> {
    let mut cur = 2u64;
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        cur = t
            .drecs
            .get(&cur)
            .and_then(|v| v.iter().find(|(n, ..)| n == comp))
            .map(|(_, id, ..)| *id)
            .ok_or_else(|| FsError::NotFound(path.to_string()))?;
    }
    Ok(cur)
}

fn make_entry(t: &FsTree, path: &str, name: &str, id: u64, added: u64) -> ApfsEntry {
    let ino = t.inodes.get(&id).cloned().unwrap_or_default();
    let xs = t.xattrs.get(&id).cloned().unwrap_or_default();
    let kind = match ino.mode & 0xF000 {
        0x4000 => "dir",
        0x8000 => "file",
        0xA000 => "symlink",
        0x1000 => "fifo",
        0x2000 => "char",
        0x6000 => "block",
        0xC000 => "socket",
        _ => "unknown",
    };
    let symlink_target = xs
        .iter()
        .find(|x| x.name == "com.apple.fs.symlink" && x.flags & 0x2 != 0)
        .map(|x| utf8z(&x.data));
    let mut xnames: Vec<String> = xs.iter().map(|x| x.name.clone()).collect();
    xnames.sort();
    ApfsEntry {
        path: path.to_string(),
        name: name.to_string(),
        id,
        parent_id: ino.parent_id,
        private_id: ino.private_id,
        kind: kind.into(),
        mode: ino.mode,
        size: ino.size,
        uid: ino.uid,
        gid: ino.gid,
        nlink: ino.nlink,
        bsd_flags: ino.bsd_flags,
        crtime: ns(ino.crtime),
        mtime: ns(ino.mtime),
        ctime: ns(ino.ctime),
        atime: ns(ino.atime),
        added: ns(added),
        compressed: ino.bsd_flags & 0x20 != 0 || xnames.iter().any(|n| n == "com.apple.decmpfs"),
        xattrs: xnames,
        symlink_target,
    }
}

/// Parse an inode's extended-field blob and return the dstream size (INO_EXT_TYPE_DSTREAM = 8).
fn xfield_dstream_size(x: &[u8]) -> Option<u64> {
    let n = u16_at(x, 0).ok()? as usize;
    let mut data = 4 + n * 4;
    for i in 0..n.min(64) {
        let t = *x.get(4 + i * 4)?;
        let size = u16_at(x, 4 + i * 4 + 2).ok()? as usize;
        if t == 8 {
            return u64_at(x, data).ok();
        }
        data += (size + 7) & !7;
    }
    None
}

/// True when the block looks like an APFS container superblock.
pub fn probe(b: &[u8]) -> bool {
    b.len() >= 36 && &b[32..36] == b"NXSB"
}
