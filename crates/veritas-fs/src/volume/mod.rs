//! Partition tables: MBR (with extended/logical partitions) and GPT (with CRC32 validation).
pub mod gpt;
pub mod mbr;

use crate::error::Result;
use crate::io::{ReadAt, Source, SubSource};
use serde::Serialize;

/// Upper bound on partitions reported from one table (GPT allows 128 by default; MBR chains are capped).
pub const MAX_PARTITIONS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Partition {
    /// 0-based position in the reported list (primary entries first, then logical, in disk order).
    pub index: usize,
    /// "mbr" or "gpt".
    pub scheme: String,
    pub start_lba: u64,
    pub num_sectors: u64,
    pub sector_size: u64,
    /// Byte offset of the partition in the image.
    pub offset: u64,
    /// Byte length of the partition.
    pub length: u64,
    /// MBR type byte as `0x83`, or the GPT type GUID.
    pub type_id: String,
    /// The Sleuth Kit style description: `Linux (0x83)` for MBR, the partition name for GPT.
    pub description: String,
    /// Human readable type name (GPT) or empty.
    pub type_name: String,
    /// GPT unique partition GUID, empty for MBR.
    pub guid: String,
    pub bootable: bool,
    pub logical: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VolumeSystem {
    pub scheme: String,
    pub sector_size: u64,
    pub partitions: Vec<Partition>,
    /// GPT only: whether the primary header and entry array CRC32s validated.
    pub gpt_header_crc_ok: Option<bool>,
    pub gpt_entries_crc_ok: Option<bool>,
    pub disk_guid: String,
}

/// Detect and parse a partition table. Returns `Ok(None)` when no table is present (bare file system).
pub fn detect(src: &dyn ReadAt) -> Result<Option<VolumeSystem>> {
    let mbr = match mbr::Mbr::parse(src) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    if mbr.entries.iter().any(|e| e.type_byte == 0xEE) {
        if let Ok(g) = gpt::parse(src) {
            return Ok(Some(g));
        }
    }
    // A boot sector of a file system also ends in 0x55AA; reject tables with implausible entries.
    if mbr.looks_like_boot_sector || mbr.entries.iter().all(|e| e.type_byte == 0) {
        return Ok(None);
    }
    Ok(Some(mbr::to_volume_system(src, &mbr)?))
}

/// Open partition `index` as a byte source.
pub fn partition_source(src: Source, p: &Partition) -> Result<Source> {
    SubSource::source(src, p.offset, p.length)
}
