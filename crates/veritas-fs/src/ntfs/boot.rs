//! NTFS volume boot record.
use crate::error::{FsError, Result};
use crate::util::{i64_at, need, u16_at, u64_at, u8_at};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootSector {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub cluster_size: u64,
    pub total_sectors: u64,
    pub mft_lcn: u64,
    pub mftmirr_lcn: u64,
    pub mft_record_size: u32,
    pub index_record_size: u32,
    pub serial_number: u64,
}

fn size_from_clusters(v: u8, cluster: u64) -> Result<u32> {
    let s = v as i8;
    let bytes = if s < 0 {
        let shift = (-(s as i32)) as u32;
        if shift > 31 {
            return Err(FsError::invalid(0x40, "record size shift too large"));
        }
        1u64 << shift
    } else {
        (s as u64).saturating_mul(cluster)
    };
    if !(256..=65536).contains(&bytes) || !bytes.is_power_of_two() {
        return Err(FsError::invalid(0x40, format!("implausible record size {bytes}")));
    }
    Ok(bytes as u32)
}

impl BootSector {
    pub fn parse(b: &[u8]) -> Result<Self> {
        if need(b, 3, 8)? != b"NTFS    " {
            return Err(FsError::sig(3, "NTFS    ", &b[3..11]));
        }
        let bps = u16_at(b, 0x0B)? as u32;
        if !(256..=4096).contains(&bps) || !bps.is_power_of_two() {
            return Err(FsError::invalid(0x0B, "bytes per sector"));
        }
        let spc_raw = u8_at(b, 0x0D)?;
        let spc: u32 = if spc_raw > 0x80 {
            let shift = 256 - spc_raw as u32;
            if shift > 20 {
                return Err(FsError::invalid(0x0D, "sectors per cluster"));
            }
            1 << shift
        } else {
            spc_raw as u32
        };
        if spc == 0 || !spc.is_power_of_two() {
            return Err(FsError::invalid(0x0D, "sectors per cluster"));
        }
        let cluster = bps as u64 * spc as u64;
        Ok(Self {
            bytes_per_sector: bps,
            sectors_per_cluster: spc,
            cluster_size: cluster,
            total_sectors: u64_at(b, 0x28)?,
            mft_lcn: u64_at(b, 0x30)?,
            mftmirr_lcn: u64_at(b, 0x38)?,
            mft_record_size: size_from_clusters(u8_at(b, 0x40)?, cluster)?,
            index_record_size: size_from_clusters(u8_at(b, 0x44)?, cluster)?,
            serial_number: i64_at(b, 0x48)? as u64,
        })
    }
}
