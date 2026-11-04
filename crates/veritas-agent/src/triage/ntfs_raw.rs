//! Minimal raw NTFS reader used to copy `$MFT`, `$LogFile` and `$UsnJrnl:$J` from a live volume
//! (`\\.\C:`, administrator only) or from a volume image.
//!
//! Implemented: boot sector parsing, MFT record fixups, resident and non-resident attribute
//! parsing, data-run decoding (including sparse runs), `$ATTRIBUTE_LIST` resolution (resident or
//! non-resident) so that fragmented `$MFT` and `$J` streams spread over extension records are
//! followed, and a scan of the MFT for `$Extend\$UsnJrnl`. Sparse regions of `$J` are not
//! materialised: only allocated extents are copied, with an extent map giving each extent's
//! logical offset. Copying arbitrary locked files by path (Amcache.hve, NTUSER.DAT of logged-on
//! users) through the directory index is out of scope.
//!
//! Every length and offset read from disk is bounds-checked; malformed structures produce errors.

use std::io::{self, Read, Seek, SeekFrom, Write};

const ALIGN: u64 = 4096;
const MAX_RUNS: usize = 1_000_000;
const MAX_RECORD_SIZE: u64 = 64 * 1024;
const MAX_ATTRIBUTE_LIST: u64 = 16 * 1024 * 1024;

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn u16_at(b: &[u8], o: usize) -> io::Result<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or_else(|| err("u16 out of range"))
}
fn u32_at(b: &[u8], o: usize) -> io::Result<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or_else(|| err("u32 out of range"))
}
fn u64_at(b: &[u8], o: usize) -> io::Result<u64> {
    b.get(o..o + 8).map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])).ok_or_else(|| err("u64 out of range"))
}

/// Reader that only issues 4096-byte-aligned reads, as Windows volume handles require.
pub struct AlignedReader<R: Read + Seek> {
    inner: R,
    block: Vec<u8>,
    block_offset: Option<u64>,
    block_len: usize,
}

impl<R: Read + Seek> AlignedReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, block: vec![0u8; ALIGN as usize * 16], block_offset: None, block_len: 0 }
    }

    /// Read exactly `buf.len()` bytes at `offset`.
    pub fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let bsize = self.block.len() as u64;
            let start = pos - pos % bsize;
            if self.block_offset != Some(start) {
                self.inner.seek(SeekFrom::Start(start))?;
                let mut got = 0usize;
                while got < self.block.len() {
                    match self.inner.read(&mut self.block[got..]) {
                        Ok(0) => break,
                        Ok(n) => got += n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    }
                }
                self.block_offset = Some(start);
                self.block_len = got;
            }
            let within = (pos - start) as usize;
            if within >= self.block_len {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read beyond end of volume"));
            }
            let n = (self.block_len - within).min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&self.block[within..within + n]);
            done += n;
        }
        Ok(())
    }
}

/// One data run: `length` clusters at `lcn` (`None` for a sparse run), starting at `vcn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub vcn: u64,
    pub lcn: Option<u64>,
    pub length: u64,
}

/// Decode an NTFS mapping-pairs array.
pub fn decode_runs(data: &[u8], start_vcn: u64) -> io::Result<Vec<Run>> {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    let mut lcn: i64 = 0;
    let mut vcn = start_vcn;
    while pos < data.len() {
        let header = data[pos];
        if header == 0 {
            break;
        }
        let len_size = (header & 0x0f) as usize;
        let off_size = (header >> 4) as usize;
        if len_size == 0 || len_size > 8 || off_size > 8 {
            return Err(err("bad run header"));
        }
        pos += 1;
        let len_bytes = data.get(pos..pos + len_size).ok_or_else(|| err("run length truncated"))?;
        let mut length: u64 = 0;
        for (i, b) in len_bytes.iter().enumerate() {
            length |= (*b as u64) << (8 * i);
        }
        pos += len_size;
        let run_lcn = if off_size == 0 {
            None
        } else {
            let off_bytes = data.get(pos..pos + off_size).ok_or_else(|| err("run offset truncated"))?;
            let mut delta: i64 = 0;
            for (i, b) in off_bytes.iter().enumerate() {
                delta |= (*b as i64) << (8 * i);
            }
            let shift = 64 - 8 * off_size as u32;
            if shift < 64 {
                delta = (delta << shift) >> shift;
            }
            pos += off_size;
            lcn = lcn.checked_add(delta).ok_or_else(|| err("run offset overflow"))?;
            if lcn < 0 {
                return Err(err("negative LCN"));
            }
            Some(lcn as u64)
        };
        if length == 0 {
            return Err(err("zero-length run"));
        }
        runs.push(Run { vcn, lcn: run_lcn, length });
        vcn = vcn.checked_add(length).ok_or_else(|| err("VCN overflow"))?;
        if runs.len() > MAX_RUNS {
            return Err(err("too many runs"));
        }
    }
    Ok(runs)
}

/// Volume geometry from the boot sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootSector {
    pub bytes_per_sector: u64,
    pub cluster_size: u64,
    pub mft_lcn: u64,
    pub record_size: u64,
    pub total_sectors: u64,
}

impl BootSector {
    pub fn parse(b: &[u8]) -> io::Result<Self> {
        if b.len() < 512 || &b[3..11] != b"NTFS    " {
            return Err(err("not an NTFS boot sector"));
        }
        let bps = u16_at(b, 0x0b)? as u64;
        if !(256..=4096).contains(&bps) || !bps.is_power_of_two() {
            return Err(err("bad bytes per sector"));
        }
        let spc_raw = b[0x0d];
        let spc: u64 = if spc_raw > 0x80 { 1u64 << (256 - spc_raw as u32).min(31) } else { spc_raw as u64 };
        if spc == 0 {
            return Err(err("bad sectors per cluster"));
        }
        let cluster_size = bps * spc;
        if cluster_size > 2 * 1024 * 1024 {
            return Err(err("cluster size too large"));
        }
        let cpr = b[0x40] as i8;
        let record_size = if cpr < 0 { 1u64 << (-(cpr as i32)).min(31) } else { cpr as u64 * cluster_size };
        if !(256..=MAX_RECORD_SIZE).contains(&record_size) {
            return Err(err("bad MFT record size"));
        }
        Ok(Self { bytes_per_sector: bps, cluster_size, mft_lcn: u64_at(b, 0x30)?, record_size, total_sectors: u64_at(b, 0x28)? })
    }
}

/// A parsed attribute (only what the copier needs).
#[derive(Debug, Clone)]
pub struct Attribute {
    pub type_code: u32,
    pub name: String,
    pub resident_value: Option<Vec<u8>>,
    pub runs: Vec<Run>,
    pub start_vcn: u64,
    pub real_size: u64,
}

/// Apply the update-sequence fixups of a FILE record in place.
pub fn apply_fixups(rec: &mut [u8], bytes_per_sector: usize) -> io::Result<()> {
    if rec.len() < 48 || &rec[..4] != b"FILE" {
        return Err(err("not a FILE record"));
    }
    let usa_off = u16_at(rec, 4)? as usize;
    let usa_count = u16_at(rec, 6)? as usize;
    if usa_count == 0 || usa_off + usa_count * 2 > rec.len() || (usa_count - 1) * bytes_per_sector > rec.len() {
        return Err(err("bad update sequence array"));
    }
    let usn = [rec[usa_off], rec[usa_off + 1]];
    for i in 1..usa_count {
        let end = i * bytes_per_sector;
        if end < 2 || end > rec.len() {
            return Err(err("fixup outside record"));
        }
        if rec[end - 2..end] != usn {
            return Err(err("fixup mismatch (torn record)"));
        }
        rec[end - 2] = rec[usa_off + 2 * i];
        rec[end - 1] = rec[usa_off + 2 * i + 1];
    }
    Ok(())
}

/// Parse the attributes of a fixed-up FILE record.
pub fn parse_attributes(rec: &[u8]) -> io::Result<Vec<Attribute>> {
    let mut out = Vec::new();
    let mut off = u16_at(rec, 0x14)? as usize;
    let used = (u32_at(rec, 0x18)? as usize).min(rec.len());
    while off + 8 <= used {
        let type_code = u32_at(rec, off)?;
        if type_code == 0xffff_ffff {
            break;
        }
        let len = u32_at(rec, off + 4)? as usize;
        if len < 16 || off + len > used {
            return Err(err("attribute length out of range"));
        }
        let a = &rec[off..off + len];
        let non_resident = a[8] != 0;
        let name_len = a[9] as usize;
        let name_off = u16_at(a, 10)? as usize;
        let name = if name_len > 0 {
            let raw = a.get(name_off..name_off + name_len * 2).ok_or_else(|| err("attribute name out of range"))?;
            String::from_utf16_lossy(&raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>())
        } else {
            String::new()
        };
        if non_resident {
            let start_vcn = u64_at(a, 16)?;
            let runs_off = u16_at(a, 32)? as usize;
            let real_size = u64_at(a, 48)?;
            let run_bytes = a.get(runs_off..).ok_or_else(|| err("runlist out of range"))?;
            let runs = decode_runs(run_bytes, start_vcn)?;
            out.push(Attribute { type_code, name, resident_value: None, runs, start_vcn, real_size });
        } else {
            let vlen = u32_at(a, 16)? as usize;
            let voff = u16_at(a, 20)? as usize;
            let value = a.get(voff..voff + vlen).ok_or_else(|| err("resident value out of range"))?.to_vec();
            out.push(Attribute { type_code, name, real_size: vlen as u64, resident_value: Some(value), runs: Vec::new(), start_vcn: 0 });
        }
        off += len;
    }
    Ok(out)
}

/// A non-resident stream assembled from one or more attribute fragments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stream {
    pub runs: Vec<Run>,
    pub real_size: u64,
}

/// Raw NTFS volume reader.
pub struct NtfsVolume<R: Read + Seek> {
    reader: AlignedReader<R>,
    pub boot: BootSector,
    mft: Stream,
}

impl<R: Read + Seek> NtfsVolume<R> {
    pub fn open(inner: R) -> io::Result<Self> {
        let mut reader = AlignedReader::new(inner);
        let mut bs = vec![0u8; 512];
        reader.read_exact_at(0, &mut bs)?;
        let boot = BootSector::parse(&bs)?;
        // Bootstrap: record 0 sits at mft_lcn; its $DATA (and attribute list) describe the rest.
        let off = boot.mft_lcn.checked_mul(boot.cluster_size).ok_or_else(|| err("MFT offset overflow"))?;
        let mut rec = vec![0u8; boot.record_size as usize];
        reader.read_exact_at(off, &mut rec)?;
        apply_fixups(&mut rec, boot.bytes_per_sector as usize)?;
        let attrs = parse_attributes(&rec)?;
        let base = attrs
            .iter()
            .find(|a| a.type_code == 0x80 && a.name.is_empty() && a.resident_value.is_none())
            .ok_or_else(|| err("$MFT has no non-resident $DATA"))?;
        let mut vol = Self { reader, boot, mft: Stream { runs: base.runs.clone(), real_size: base.real_size } };
        // With a bootstrap mapping in place, follow an attribute list if record 0 has one.
        vol.mft = vol.stream_from_attrs(0, &attrs, 0x80, "")?;
        Ok(vol)
    }

    pub fn mft_stream(&self) -> &Stream {
        &self.mft
    }

    pub fn record_count(&self) -> u64 {
        self.mft.real_size / self.boot.record_size
    }

    /// Map a byte offset in a stream to a volume offset (`None` when sparse).
    fn map(&self, runs: &[Run], offset: u64) -> io::Result<Option<u64>> {
        let vcn = offset / self.boot.cluster_size;
        for r in runs {
            if vcn >= r.vcn && vcn < r.vcn + r.length {
                return Ok(r.lcn.map(|l| (l + (vcn - r.vcn)) * self.boot.cluster_size + offset % self.boot.cluster_size));
            }
        }
        Err(err(format!("offset {} not mapped", offset)))
    }

    /// Read MFT record `n` with fixups applied.
    pub fn read_record(&mut self, n: u64) -> io::Result<Vec<u8>> {
        let rs = self.boot.record_size;
        let off = n.checked_mul(rs).ok_or_else(|| err("record offset overflow"))?;
        if off + rs > self.mft.real_size {
            return Err(err("record beyond $MFT"));
        }
        let mut rec = vec![0u8; rs as usize];
        // A record may straddle clusters only when record size > cluster size; read in pieces.
        let mut done = 0u64;
        while done < rs {
            let piece = (self.boot.cluster_size - (off + done) % self.boot.cluster_size).min(rs - done);
            let vol_off = self.map(&self.mft.runs.clone(), off + done)?.ok_or_else(|| err("MFT record in sparse run"))?;
            self.reader.read_exact_at(vol_off, &mut rec[done as usize..(done + piece) as usize])?;
            done += piece;
        }
        apply_fixups(&mut rec, self.boot.bytes_per_sector as usize)?;
        Ok(rec)
    }

    /// Read a non-resident attribute's bytes fully (bounded by `cap`).
    fn read_small_stream(&mut self, s: &Stream, cap: u64) -> io::Result<Vec<u8>> {
        if s.real_size > cap {
            return Err(err("stream too large"));
        }
        let mut out = Vec::with_capacity(s.real_size as usize);
        self.copy_stream(s, &mut out, false, &mut |_| {})?;
        Ok(out)
    }

    /// Assemble the stream (`type_code`, `name`) of base record `record` from its attributes,
    /// following `$ATTRIBUTE_LIST` into extension records when present.
    fn stream_from_attrs(&mut self, record: u64, attrs: &[Attribute], type_code: u32, name: &str) -> io::Result<Stream> {
        let mut fragments: Vec<Attribute> = attrs.iter().filter(|a| a.type_code == type_code && a.name == name && a.resident_value.is_none()).cloned().collect();
        if let Some(list) = attrs.iter().find(|a| a.type_code == 0x20) {
            let data = match &list.resident_value {
                Some(v) => v.clone(),
                None => self.read_small_stream(&Stream { runs: list.runs.clone(), real_size: list.real_size }, MAX_ATTRIBUTE_LIST)?,
            };
            let mut pos = 0usize;
            let mut ext_records = Vec::new();
            while pos + 26 <= data.len() {
                let t = u32_at(&data, pos)?;
                let len = u16_at(&data, pos + 4)? as usize;
                if len < 26 || pos + len > data.len() {
                    break;
                }
                let nlen = data[pos + 6] as usize;
                let noff = data[pos + 7] as usize;
                let aname = if nlen > 0 {
                    let raw = data.get(pos + noff..pos + noff + nlen * 2).ok_or_else(|| err("list name out of range"))?;
                    String::from_utf16_lossy(&raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>())
                } else {
                    String::new()
                };
                let rec_no = u64_at(&data, pos + 16)? & 0x0000_ffff_ffff_ffff;
                if t == type_code && aname == name && rec_no != record && !ext_records.contains(&rec_no) {
                    ext_records.push(rec_no);
                }
                pos += len;
            }
            for r in ext_records {
                let rec = self.read_record(r)?;
                for a in parse_attributes(&rec)? {
                    if a.type_code == type_code && a.name == name && a.resident_value.is_none() {
                        fragments.push(a);
                    }
                }
            }
        }
        if fragments.is_empty() {
            return Err(err(format!("record {} has no non-resident stream {:#x}:{}", record, type_code, name)));
        }
        fragments.sort_by_key(|a| a.start_vcn);
        let real_size = fragments.iter().find(|a| a.start_vcn == 0).map(|a| a.real_size).unwrap_or(fragments[0].real_size);
        let runs: Vec<Run> = fragments.into_iter().flat_map(|a| a.runs).collect();
        Ok(Stream { runs, real_size })
    }

    /// Stream (`type_code`, `name`) of MFT record `record`.
    pub fn stream(&mut self, record: u64, type_code: u32, name: &str) -> io::Result<Stream> {
        let rec = self.read_record(record)?;
        let attrs = parse_attributes(&rec)?;
        self.stream_from_attrs(record, &attrs, type_code, name)
    }

    /// Copy a stream to `out`. With `skip_sparse`, sparse runs are omitted and `extent` is
    /// called with (logical offset, length) for each allocated extent written; otherwise sparse
    /// runs are written as zeros. Returns the number of bytes written.
    pub fn copy_stream(&mut self, s: &Stream, out: &mut dyn Write, skip_sparse: bool, extent: &mut dyn FnMut((u64, u64))) -> io::Result<u64> {
        let cs = self.boot.cluster_size;
        let mut written = 0u64;
        let mut buf = vec![0u8; 1 << 20];
        for r in &s.runs {
            let run_start = r.vcn.checked_mul(cs).ok_or_else(|| err("run offset overflow"))?;
            if run_start >= s.real_size {
                break;
            }
            let run_len = (r.length.checked_mul(cs).ok_or_else(|| err("run length overflow"))?).min(s.real_size - run_start);
            match r.lcn {
                None if skip_sparse => continue,
                None => {
                    buf.iter_mut().for_each(|b| *b = 0);
                    let mut left = run_len;
                    while left > 0 {
                        let n = left.min(buf.len() as u64) as usize;
                        out.write_all(&buf[..n])?;
                        left -= n as u64;
                    }
                }
                Some(lcn) => {
                    let base = lcn.checked_mul(cs).ok_or_else(|| err("LCN overflow"))?;
                    let mut done = 0u64;
                    while done < run_len {
                        let n = (run_len - done).min(buf.len() as u64) as usize;
                        self.reader.read_exact_at(base + done, &mut buf[..n])?;
                        out.write_all(&buf[..n])?;
                        done += n as u64;
                    }
                    if skip_sparse {
                        extent((run_start, run_len));
                    }
                }
            }
            written += run_len;
        }
        Ok(written)
    }

    /// Find `$Extend\$UsnJrnl` by scanning `$FILE_NAME` attributes (parent record 11).
    pub fn find_usnjrnl(&mut self, max_records: u64) -> io::Result<Option<u64>> {
        let n = self.record_count().min(max_records);
        for rec_no in 11..n {
            let rec = match self.read_record(rec_no) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let flags = u16_at(&rec, 0x16)?;
            if flags & 0x01 == 0 {
                continue;
            }
            let attrs = match parse_attributes(&rec) {
                Ok(a) => a,
                Err(_) => continue,
            };
            for a in attrs.iter().filter(|a| a.type_code == 0x30) {
                if let Some(v) = &a.resident_value {
                    if v.len() < 66 {
                        continue;
                    }
                    let parent = u64_at(v, 0)? & 0x0000_ffff_ffff_ffff;
                    let nlen = v[64] as usize;
                    let raw = match v.get(66..66 + nlen * 2) {
                        Some(r) => r,
                        None => continue,
                    };
                    let name = String::from_utf16_lossy(&raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>());
                    if parent == 11 && name == "$UsnJrnl" {
                        return Ok(Some(rec_no));
                    }
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::PathBuf;

    fn ntfs_image() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/dfvfs/ntfs.raw")
    }

    #[test]
    fn decode_runs_handles_sparse_and_negative() {
        // 0x21: 1-byte length, 2-byte offset; 0x01: sparse; 0x11 with negative delta.
        let data = [0x21, 0x10, 0x00, 0x01, 0x01, 0x05, 0x11, 0x02, 0xff, 0x00];
        let runs = decode_runs(&data, 0).unwrap();
        assert_eq!(runs, vec![
            Run { vcn: 0, lcn: Some(0x100), length: 0x10 },
            Run { vcn: 0x10, lcn: None, length: 5 },
            Run { vcn: 0x15, lcn: Some(0xff), length: 2 },
        ]);
        assert!(decode_runs(&[0x21, 0x10], 0).is_err());
    }

    #[test]
    fn extracts_mft_and_logfile_from_image() {
        let mut vol = NtfsVolume::open(File::open(ntfs_image()).unwrap()).unwrap();
        assert!(vol.record_count() > 16);
        let mft = vol.mft_stream().clone();
        let mut out = Vec::new();
        let n = vol.copy_stream(&mft, &mut out, false, &mut |_| {}).unwrap();
        assert_eq!(n, mft.real_size);
        assert_eq!(&out[..4], b"FILE");
        // Record 1 is $MFTMirr, record 2 $LogFile; both carry FILE signatures.
        let rs = vol.boot.record_size as usize;
        assert_eq!(&out[rs..rs + 4], b"FILE");
        let log = vol.stream(2, 0x80, "").unwrap();
        let mut logbytes = Vec::new();
        assert_eq!(vol.copy_stream(&log, &mut logbytes, false, &mut |_| {}).unwrap(), log.real_size);
        // Reference values from The Sleuth Kit (pytsk3) reading the same image.
        assert_eq!(out.len(), 70656);
        assert_eq!(veritas_hash::sha256_hex(&out), "ef643dc219fbea7eeca9790faa56b400b6427491e1250db9191ce836f42b9930");
        assert_eq!(logbytes.len(), 1_048_576);
        assert_eq!(veritas_hash::sha256_hex(&logbytes), "f5fb04aa5b882706b9309e885f19477261336ef76a150c3b4d3489dfac3953ec");
        // This image has no $Extend\$UsnJrnl (TSK agrees); the scan must say so, not fail.
        assert_eq!(vol.find_usnjrnl(10_000).unwrap(), None);
    }

    #[test]
    fn garbage_is_rejected() {
        let data = vec![0u8; 8192];
        assert!(NtfsVolume::open(std::io::Cursor::new(data)).is_err());
        let mut rec = vec![0u8; 1024];
        rec[..4].copy_from_slice(b"FILE");
        rec[4] = 0xff;
        rec[5] = 0x03;
        rec[6] = 3;
        assert!(apply_fixups(&mut rec, 512).is_err());
    }
}
