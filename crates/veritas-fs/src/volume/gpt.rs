//! GUID Partition Table: header, CRC32 validation of header and entry array, partition entries.
use super::{Partition, VolumeSystem, MAX_PARTITIONS};
use crate::error::{FsError, Result};
use crate::io::{read_vec, ReadAt};
use crate::util::{guid_le, need, u32_at, u64_at, utf16le};

/// Upper bound on the GPT entry array size accepted (entries * entry_size).
pub const MAX_ENTRY_ARRAY: u64 = 4 * 1024 * 1024;

pub fn type_name(guid: &str) -> &'static str {
    match guid {
        "0fc63daf-8483-4772-8e79-3d69d8477de4" => "Linux filesystem",
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => "EFI System",
        "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" => "Microsoft basic data",
        "e3c9e316-0b5c-4db8-817d-f92df00215ae" => "Microsoft reserved",
        "de94bba4-06d1-4d40-a16a-bfd50179d6ac" => "Windows recovery environment",
        "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3" => "Windows LDM metadata",
        "af9b60a0-1431-4f62-bc68-3311714a69ad" => "Windows LDM data",
        "7c3457ef-0000-11aa-aa11-00306543ecac" => "Apple APFS",
        "48465300-0000-11aa-aa11-00306543ecac" => "Apple HFS+",
        "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => "Linux swap",
        "e6d6d379-f507-44c2-a23c-238f2a3df928" => "Linux LVM",
        "a19d880f-05fc-4d3b-a006-743f0f84911e" => "Linux RAID",
        "21686148-6449-6e6f-744e-656564454649" => "BIOS boot",
        _ => "Unknown",
    }
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}

/// Parse the primary GPT, trying 512- and 4096-byte logical sectors.
pub fn parse(src: &dyn ReadAt) -> Result<VolumeSystem> {
    let mut last_err = FsError::NotFound("GPT header".into());
    for ss in [512u64, 4096] {
        match parse_with_sector(src, ss) {
            Ok(v) => return Ok(v),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn parse_with_sector(src: &dyn ReadAt, ss: u64) -> Result<VolumeSystem> {
    let hdr = read_vec(src, ss, ss)?;
    if need(&hdr, 0, 8)? != b"EFI PART" {
        return Err(FsError::sig(ss, "EFI PART", &hdr[..8]));
    }
    let header_size = u32_at(&hdr, 12)? as usize;
    if !(92..=ss as usize).contains(&header_size) {
        return Err(FsError::invalid(ss + 12, "GPT header size out of range"));
    }
    let stored_crc = u32_at(&hdr, 16)?;
    let mut h = need(&hdr, 0, header_size)?.to_vec();
    h[16..20].copy_from_slice(&[0, 0, 0, 0]);
    let header_ok = crc32(&h) == stored_crc;
    let disk_guid = guid_le(need(&hdr, 56, 16)?)?;
    let entries_lba = u64_at(&hdr, 72)?;
    let num_entries = u32_at(&hdr, 80)? as u64;
    let entry_size = u32_at(&hdr, 84)? as u64;
    let entries_crc = u32_at(&hdr, 88)?;
    if !(128..=4096).contains(&entry_size) || entry_size % 8 != 0 {
        return Err(FsError::invalid(ss + 84, "GPT entry size out of range"));
    }
    let total = num_entries
        .checked_mul(entry_size)
        .ok_or_else(|| FsError::invalid(ss + 80, "entry array overflow"))?;
    if total > MAX_ENTRY_ARRAY {
        return Err(FsError::Limit("GPT entry array too large".into()));
    }
    let arr_off = entries_lba
        .checked_mul(ss)
        .ok_or_else(|| FsError::invalid(ss + 72, "entry LBA overflow"))?;
    let arr = read_vec(src, arr_off, total)?;
    let entries_ok = crc32(&arr) == entries_crc;
    let mut parts = Vec::new();
    for i in 0..num_entries as usize {
        let e = need(&arr, i * entry_size as usize, entry_size as usize)?;
        let type_guid = guid_le(&e[0..16])?;
        if type_guid == "00000000-0000-0000-0000-000000000000" {
            continue;
        }
        let first = u64_at(e, 32)?;
        let last = u64_at(e, 40)?;
        if last < first {
            continue;
        }
        let n = last - first + 1;
        let name = utf16le(&e[56..128], true);
        if parts.len() >= MAX_PARTITIONS {
            break;
        }
        parts.push(Partition {
            index: parts.len(),
            scheme: "gpt".into(),
            start_lba: first,
            num_sectors: n,
            sector_size: ss,
            offset: first.saturating_mul(ss),
            length: n.saturating_mul(ss),
            type_name: type_name(&type_guid).to_string(),
            description: if name.is_empty() {
                type_name(&type_guid).to_string()
            } else {
                name
            },
            type_id: type_guid,
            guid: guid_le(&e[16..32])?,
            bootable: u64_at(e, 48)? & 0x4 != 0,
            logical: false,
        });
    }
    Ok(VolumeSystem {
        scheme: "gpt".into(),
        sector_size: ss,
        partitions: parts,
        gpt_header_crc_ok: Some(header_ok),
        gpt_entries_crc_ok: Some(entries_ok),
        disk_guid,
    })
}
