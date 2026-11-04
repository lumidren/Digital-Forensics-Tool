mod common;
use common::*;
use veritas_fs::carve::{self, CHUNK_SIZE};
use veritas_fs::io::MemSource;
use veritas_fs::ntfs::Ntfs;
use veritas_fs::recover;
use veritas_fs::volume::gpt::crc32;

fn png(corrupt: bool) -> Vec<u8> {
    let chunk = |t: &[u8], d: &[u8]| {
        let mut v = (d.len() as u32).to_be_bytes().to_vec();
        let mut td = t.to_vec();
        td.extend_from_slice(d);
        v.extend_from_slice(&td);
        v.extend_from_slice(&crc32(&td).to_be_bytes());
        v
    };
    let mut p = b"\x89PNG\r\n\x1a\n".to_vec();
    p.extend(chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]));
    let mut idat = chunk(b"IDAT", &[0x78, 0x9c, 0x63, 0x60, 0, 0, 0, 2, 0, 1]);
    if corrupt {
        let n = idat.len();
        idat[n - 1] ^= 0xFF;
    }
    p.extend(idat);
    p.extend(chunk(b"IEND", &[]));
    p
}

fn jpeg() -> Vec<u8> {
    let mut j = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    j.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
    j.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 1, 1, 0, 0, 0x3F, 0]);
    j.extend_from_slice(&[0x12, 0x34, 0xFF, 0x00, 0x56, 0xFF, 0xD0, 0x78]);
    j.extend_from_slice(&[0xFF, 0xD9]);
    j
}

fn gif() -> Vec<u8> {
    let mut g = b"GIF89a".to_vec();
    g.extend_from_slice(&[1, 0, 1, 0, 0x80, 0, 0]); // global colour table of 2 entries
    g.extend_from_slice(&[0, 0, 0, 255, 255, 255]);
    g.extend_from_slice(&[0x21, 0xF9, 4, 0, 0, 0, 0, 0]); // graphic control extension
    g.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 0x4C, 0x01, 0, 0x3B]);
    g
}

const PDF: &[u8] = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n";

#[test]
fn carve_synthetic_stream() {
    // Deterministic filler (LCG) with embedded files; one PNG straddles the scan chunk boundary.
    let mut buf = Vec::with_capacity(CHUNK_SIZE as usize + (2 << 20));
    let mut x: u32 = 12345;
    while buf.len() < CHUNK_SIZE as usize + (2 << 20) {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        buf.push(((x >> 16) as u8) & 0x3F | 0x40); // printable, never a signature start byte pattern
    }
    let docx = bytes("plaso/Document.docx");
    let pe = bytes("plaso/test_pe.exe");
    let evtx = bytes("plaso/evtx/System.evtx");
    assert_eq!(evtx.len(), 4096 + 33 * 65536);
    let sqlite = bytes("plaso/chrome/History");
    let mut place = |off: usize, d: &[u8]| buf[off..off + d.len()].copy_from_slice(d);
    place(1000, &jpeg());
    place(5000, &png(false));
    place(6000, &png(true));
    place(7000, &gif());
    place(8000, PDF);
    place(10_000, &docx);
    place(40_000, &pe);
    place(100_000, &sqlite);
    place(300_000, &evtx);
    let straddle = CHUNK_SIZE as usize - 3;
    place(straddle, &png(false));
    let hits = carve::carve(MemSource::source(buf.clone()).as_ref()).unwrap();
    let got: Vec<(u64, &str, u64, bool)> = hits
        .iter()
        .map(|h| (h.offset, h.file_type.as_str(), h.size, h.validated))
        .collect();
    assert_eq!(
        got,
        vec![
            (1000, "jpeg", jpeg().len() as u64, true),
            (5000, "png", png(false).len() as u64, true),
            (6000, "png", 55, false),
            (7000, "gif", gif().len() as u64, true),
            (8000, "pdf", PDF.len() as u64, true),
            (10_000, "docx", docx.len() as u64, true),
            (40_000, "pe", pe.len() as u64, true),
            (100_000, "sqlite", sqlite.len() as u64, false), // legacy header: size estimated
            // 27 chunks carry an ElfChnk signature; the 6 trailing preallocated chunks are empty.
            (300_000, "evtx", 4096 + 27 * 65536, true),
            (straddle as u64, "png", png(false).len() as u64, true),
        ]
    );
    assert_eq!(
        carve::extract(MemSource::source(buf).as_ref(), &hits[9]).unwrap(),
        png(false)
    );
}

#[test]
fn recover_ntfs_resident_file() {
    let mut d = bytes("dfvfs/ntfs.raw");
    let flags = 4 * 4096 + 66 * 1024 + 0x16;
    d[flags] &= !1; // passwords.txt -> unallocated record
    let fs = Ntfs::open(MemSource::source(d)).unwrap();
    let r = recover::recover_ntfs(&fs).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(
        (
            r[0].id,
            r[0].name.as_str(),
            r[0].size,
            r[0].recovered_confidence,
            r[0].method.as_str()
        ),
        (66, "passwords.txt", 116, recover::CONF_RESIDENT, "resident")
    );
    let dir = tempfile::tempdir().unwrap();
    let written = recover::write_recovered(dir.path(), &r).unwrap();
    assert_eq!(std::fs::read(&written[0]).unwrap().len(), 116);
}

#[test]
fn recover_ntfs_nonresident_with_reused_clusters() {
    let live = Ntfs::open(src("dfvfs/vss.raw")).unwrap();
    let want = live.read_entry_data(43, "").unwrap();
    assert_eq!(want.len(), 425984);
    let mut d = bytes("dfvfs/vss.raw");
    let rec = (live.boot.mft_lcn * live.boot.cluster_size + 43 * 1024) as usize;
    d[rec + 0x16] &= !1;
    let fs = Ntfs::open(MemSource::source(d)).unwrap();
    let r = recover::recover_ntfs(&fs).unwrap();
    let x = r.iter().find(|x| x.id == 43).unwrap();
    assert_eq!(x.data, want);
    assert_eq!(x.method, "data_runs");
    // $Bitmap still marks every cluster as allocated: confidence drops to the floor.
    assert_eq!(x.total_clusters, x.reused_clusters);
    assert_eq!(x.recovered_confidence, recover::CONF_REUSED_FLOOR);
}

#[test]
fn recover_fat_deleted_entry() {
    let mut d = bytes("dfvfs/fat12.raw");
    d[6784] = 0xE5;
    d[6752] = 0xE5;
    let fs = veritas_fs::fat::FatFs::open(MemSource::source(d.clone())).unwrap();
    let r = recover::recover_fat(&fs).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].size, 116);
    assert_eq!(r[0].recovered_confidence, recover::CONF_REUSED_FLOOR); // cluster still allocated in the FAT
                                                                       // Free the cluster (FAT12 entry 5 is the high 12 bits at FAT+7) -> full confidence.
    let fat = fs.fat_offset as usize;
    let v = u16::from_le_bytes([d[fat + 7], d[fat + 8]]) & 0x000F;
    d[fat + 7..fat + 9].copy_from_slice(&v.to_le_bytes());
    let fs = veritas_fs::fat::FatFs::open(MemSource::source(d)).unwrap();
    let r = recover::recover_fat(&fs).unwrap();
    assert_eq!(r[0].recovered_confidence, recover::CONF_CLUSTERS);
    assert_eq!(r[0].sha256, veritas_hash::sha256_hex(&r[0].data));
}
