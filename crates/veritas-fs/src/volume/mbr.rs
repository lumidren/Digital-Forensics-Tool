//! Master Boot Record with extended-partition (EBR) chain walking.
use super::{Partition, VolumeSystem, MAX_PARTITIONS};
use crate::error::{FsError, Result};
use crate::io::{read_vec, ReadAt};
use crate::util::{u16_at, u32_at, u8_at};
use std::collections::BTreeSet;

/// Maximum number of EBRs followed in one extended partition chain.
pub const MAX_EBR_CHAIN: usize = 128;
const SECTOR: u64 = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbrEntry {
    pub bootable: bool,
    pub type_byte: u8,
    pub start_lba: u32,
    pub num_sectors: u32,
}

#[derive(Debug, Clone)]
pub struct Mbr {
    pub entries: Vec<MbrEntry>,
    pub disk_signature: u32,
    pub looks_like_boot_sector: bool,
}

pub fn is_extended(t: u8) -> bool {
    matches!(t, 0x05 | 0x0F | 0x85)
}

/// Sleuth Kit compatible description of an MBR partition type.
pub fn type_description(t: u8) -> String {
    let name = match t {
        0x00 => "Empty",
        0x01 => "DOS FAT12",
        0x04 => "DOS FAT16",
        0x05 => "DOS Extended",
        0x06 => "DOS FAT16",
        0x07 => "NTFS / exFAT",
        0x0b => "Win95 FAT32",
        0x0c => "Win95 FAT32",
        0x0e => "Win95 FAT16",
        0x0f => "Win95 Extended",
        0x11 => "Hidden FAT12",
        0x12 => "Hibernation",
        0x14 => "Hidden FAT16",
        0x16 => "Hidden FAT16",
        0x17 => "Hidden NTFS",
        0x1b => "Hidden Win95 FAT32",
        0x1c => "Hidden Win95 FAT32",
        0x1e => "Hidden Win95 FAT16",
        0x27 => "Windows Recovery Environment",
        0x42 => "Microsoft Dynamic",
        0x82 => "Linux Swap / Solaris x86",
        0x83 => "Linux",
        0x84 => "Hibernation",
        0x85 => "Linux Extended",
        0x86 => "NTFS Volume Set",
        0x87 => "NTFS Volume Set",
        0x8e => "Linux Logical Volume Manager",
        0xa5 => "FreeBSD",
        0xa6 => "OpenBSD",
        0xa8 => "Mac OS X",
        0xa9 => "NetBSD",
        0xab => "Mac OS X Boot",
        0xaf => "Mac OS X HFS",
        0xee => "GPT Safety Partition",
        0xef => "EFI File System",
        0xfb => "VMware File System",
        0xfd => "Linux RAID",
        _ => "Unknown Type",
    };
    format!("{name} (0x{t:02x})")
}

fn parse_entries(sector: &[u8]) -> Result<Vec<MbrEntry>> {
    let mut v = Vec::with_capacity(4);
    for i in 0..4 {
        let o = 446 + i * 16;
        let status = u8_at(sector, o)?;
        v.push(MbrEntry {
            bootable: status == 0x80,
            type_byte: u8_at(sector, o + 4)?,
            start_lba: u32_at(sector, o + 8)?,
            num_sectors: u32_at(sector, o + 12)?,
        });
    }
    Ok(v)
}

impl Mbr {
    pub fn parse(src: &dyn ReadAt) -> Result<Self> {
        let s = read_vec(src, 0, SECTOR)?;
        if u16_at(&s, 510)? != 0xAA55 {
            return Err(FsError::sig(510, "55AA", &s[510..512]));
        }
        let entries = parse_entries(&s)?;
        // FAT/NTFS boot sectors carry a jump instruction and OEM name; their "partition table" bytes are
        // code. Treat as boot sector when status bytes are not 0x00/0x80 or an OEM file-system name exists.
        let bad_status = (0..4).any(|i| !matches!(s[446 + i * 16], 0x00 | 0x80));
        let oem = &s[3..11];
        let fs_oem = oem == b"NTFS    "
            || oem == b"EXFAT   "
            || &s[0x36..0x3B] == b"FAT12"
            || &s[0x36..0x3B] == b"FAT16"
            || &s[0x52..0x57] == b"FAT32"
            || oem == b"-FVE-FS-";
        Ok(Self {
            entries,
            disk_signature: u32_at(&s, 440)?,
            looks_like_boot_sector: bad_status || fs_oem,
        })
    }
}

pub fn to_volume_system(src: &dyn ReadAt, mbr: &Mbr) -> Result<VolumeSystem> {
    let mut parts = Vec::new();
    let push = |parts: &mut Vec<Partition>, e: &MbrEntry, start: u64, logical: bool| {
        if parts.len() >= MAX_PARTITIONS {
            return;
        }
        parts.push(Partition {
            index: parts.len(),
            scheme: "mbr".into(),
            start_lba: start,
            num_sectors: e.num_sectors as u64,
            sector_size: SECTOR,
            offset: start.saturating_mul(SECTOR),
            length: (e.num_sectors as u64).saturating_mul(SECTOR),
            type_id: format!("0x{:02x}", e.type_byte),
            description: type_description(e.type_byte),
            type_name: String::new(),
            guid: String::new(),
            bootable: e.bootable,
            logical,
        });
    };
    let mut extended_base: Option<u64> = None;
    for e in &mbr.entries {
        if e.type_byte == 0 || e.num_sectors == 0 {
            continue;
        }
        if is_extended(e.type_byte) {
            if extended_base.is_none() {
                extended_base = Some(e.start_lba as u64);
            }
            continue;
        }
        push(&mut parts, e, e.start_lba as u64, false);
    }
    if let Some(base) = extended_base {
        let mut ebr = base;
        let mut seen = BTreeSet::new();
        for _ in 0..MAX_EBR_CHAIN {
            if !seen.insert(ebr) {
                break; // loop in the chain
            }
            let Some(off) = ebr.checked_mul(SECTOR) else {
                break;
            };
            let Ok(s) = read_vec(src, off, SECTOR) else {
                break;
            };
            if u16_at(&s, 510)? != 0xAA55 {
                break;
            }
            let es = parse_entries(&s)?;
            let mut next = None;
            for e in &es {
                if e.type_byte == 0 || e.num_sectors == 0 {
                    continue;
                }
                if is_extended(e.type_byte) {
                    next = base.checked_add(e.start_lba as u64);
                } else if let Some(start) = ebr.checked_add(e.start_lba as u64) {
                    push(&mut parts, e, start, true);
                }
            }
            match next {
                Some(n) => ebr = n,
                None => break,
            }
        }
    }
    Ok(VolumeSystem {
        scheme: "mbr".into(),
        sector_size: SECTOR,
        partitions: parts,
        gpt_header_crc_ok: None,
        gpt_entries_crc_ok: None,
        disk_guid: format!("{:08x}", mbr.disk_signature),
    })
}
