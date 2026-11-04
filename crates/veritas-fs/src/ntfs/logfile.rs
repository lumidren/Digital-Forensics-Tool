//! `$LogFile`: restart pages (RSTR), restart area and client records, record pages (RCRD) and
//! log record headers with redo/undo operation names. Transactions are NOT replayed.
use super::record::apply_fixups;
use crate::error::{FsError, Result};
use crate::util::{need, u16_at, u32_at, u64_at, utf16le};
use serde::Serialize;

/// Maximum log records returned.
pub const MAX_LOG_RECORDS: usize = 2_000_000;
/// Maximum log size processed.
pub const MAX_LOGFILE_SIZE: usize = 512 * 1024 * 1024;
const LOG_RECORD_HEADER: usize = 0x30;

pub fn op_name(op: u16) -> &'static str {
    match op {
        0x00 => "Noop",
        0x01 => "CompensationLogRecord",
        0x02 => "InitializeFileRecordSegment",
        0x03 => "DeallocateFileRecordSegment",
        0x04 => "WriteEndOfFileRecordSegment",
        0x05 => "CreateAttribute",
        0x06 => "DeleteAttribute",
        0x07 => "UpdateResidentValue",
        0x08 => "UpdateNonresidentValue",
        0x09 => "UpdateMappingPairs",
        0x0A => "DeleteDirtyClusters",
        0x0B => "SetNewAttributeSizes",
        0x0C => "AddIndexEntryRoot",
        0x0D => "DeleteIndexEntryRoot",
        0x0E => "AddIndexEntryAllocation",
        0x0F => "DeleteIndexEntryAllocation",
        0x10 => "WriteEndOfIndexBuffer",
        0x11 => "SetIndexEntryVcnRoot",
        0x12 => "SetIndexEntryVcnAllocation",
        0x13 => "UpdateFileNameRoot",
        0x14 => "UpdateFileNameAllocation",
        0x15 => "SetBitsInNonresidentBitMap",
        0x16 => "ClearBitsInNonresidentBitMap",
        0x17 => "HotFix",
        0x18 => "EndTopLevelAction",
        0x19 => "PrepareTransaction",
        0x1A => "CommitTransaction",
        0x1B => "ForgetTransaction",
        0x1C => "OpenNonresidentAttribute",
        0x1D => "OpenAttributeTableDump",
        0x1E => "AttributeNamesDump",
        0x1F => "DirtyPageTableDump",
        0x20 => "TransactionTableDump",
        0x21 => "UpdateRecordDataRoot",
        0x22 => "UpdateRecordDataAllocation",
        0x23 => "UpdateRelativeDataInIndex",
        0x24 => "UpdateRelativeDataInIndex2",
        0x25 => "ZeroEndOfFileRecord",
        _ => "Unknown",
    }
}

/// Operations whose target is an MFT FILE record (the affected entry can be derived from the target VCN).
fn targets_mft_record(op: u16) -> bool {
    matches!(op, 0x02..=0x07 | 0x09 | 0x0B | 0x0C | 0x0D | 0x11 | 0x13 | 0x21 | 0x25)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientRecord {
    pub oldest_lsn: u64,
    pub client_restart_lsn: u64,
    pub seq_number: u16,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RestartArea {
    pub page_offset: u64,
    pub chkdsk_lsn: u64,
    pub system_page_size: u32,
    pub log_page_size: u32,
    pub major_version: i16,
    pub minor_version: i16,
    pub current_lsn: u64,
    pub log_clients: u16,
    pub flags: u16,
    pub seq_number_bits: u32,
    pub file_size: u64,
    pub log_page_data_offset: u16,
    pub clients: Vec<ClientRecord>,
    pub fixup_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogRecord {
    /// File offset of the record header inside $LogFile.
    pub offset: u64,
    pub lsn: u64,
    pub client_previous_lsn: u64,
    pub client_undo_next_lsn: u64,
    pub client_data_length: u32,
    pub record_type: u32,
    pub transaction_id: u32,
    pub flags: u16,
    pub redo_op: u16,
    pub redo_op_name: String,
    pub undo_op: u16,
    pub undo_op_name: String,
    pub redo_length: u16,
    pub undo_length: u16,
    pub target_attribute: u16,
    pub lcns_to_follow: u16,
    pub record_offset: u16,
    pub attribute_offset: u16,
    pub cluster_block_offset: u16,
    pub target_vcn: u64,
    pub target_lcn: Option<u64>,
    /// MFT entry derived from target VCN for record-targeting operations (assumes target attribute is $MFT:$DATA).
    pub mft_entry: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogFile {
    pub restart_areas: Vec<RestartArea>,
    pub page_size: u32,
    pub record_pages: u64,
    pub records: Vec<LogRecord>,
}

fn parse_restart(page: &[u8], off: u64) -> Result<RestartArea> {
    let mut p = page.to_vec();
    let fixup_ok = apply_fixups(&mut p, 512)?;
    let ra = u16_at(&p, 0x18)? as usize;
    let mut r = RestartArea {
        page_offset: off,
        chkdsk_lsn: u64_at(&p, 0x08)?,
        system_page_size: u32_at(&p, 0x10)?,
        log_page_size: u32_at(&p, 0x14)?,
        minor_version: u16_at(&p, 0x1A)? as i16,
        major_version: u16_at(&p, 0x1C)? as i16,
        current_lsn: u64_at(&p, ra)?,
        log_clients: u16_at(&p, ra + 0x08)?,
        flags: u16_at(&p, ra + 0x0E)?,
        seq_number_bits: u32_at(&p, ra + 0x10)?,
        file_size: u64_at(&p, ra + 0x18)?,
        log_page_data_offset: u16_at(&p, ra + 0x26)?,
        clients: vec![],
        fixup_ok,
    };
    let ca = ra + u16_at(&p, ra + 0x16)? as usize;
    for i in 0..(r.log_clients as usize).min(16) {
        let c = ca + i * 0xA0;
        let nl = (u32_at(&p, c + 0x1C)? as usize).min(64);
        r.clients.push(ClientRecord { oldest_lsn: u64_at(&p, c)?, client_restart_lsn: u64_at(&p, c + 8)?, seq_number: u16_at(&p, c + 0x14)?, name: utf16le(need(&p, c + 0x20, nl)?, false) });
    }
    Ok(r)
}

/// Parse a `$LogFile` byte stream. `cluster_size` / `record_size` are used to derive affected MFT entries.
pub fn parse_logfile(data: &[u8], cluster_size: u64, record_size: u64) -> Result<LogFile> {
    if data.len() > MAX_LOGFILE_SIZE {
        return Err(FsError::Limit("$LogFile too large".into()));
    }
    if need(data, 0, 4)? != b"RSTR" && need(data, 0, 4)? != b"CHKD" {
        return Err(FsError::sig(0, "RSTR", &data[..4]));
    }
    let page_size = u32_at(data, 0x10)? as usize;
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(FsError::invalid(0x10, "log page size"));
    }
    let mut restart_areas = Vec::new();
    for i in 0..2usize {
        let off = i * page_size;
        if let Ok(pg) = need(data, off, page_size) {
            if &pg[0..4] == b"RSTR" {
                if let Ok(r) = parse_restart(pg, off as u64) {
                    restart_areas.push(r);
                }
            }
        }
    }
    let best = restart_areas.iter().max_by_key(|r| r.current_lsn).cloned();
    let seq_bits = best.as_ref().map(|r| r.seq_number_bits).unwrap_or(0);
    let data_off = best.as_ref().map(|r| r.log_page_data_offset as usize).filter(|&d| d >= 0x28 && d < page_size).unwrap_or(0x40);
    let offset_bits = 64u32.saturating_sub(seq_bits);
    let lsn_to_off = |lsn: u64| -> Option<u64> {
        if seq_bits == 0 || offset_bits == 0 || offset_bits >= 64 {
            return None;
        }
        (lsn & ((1u64 << offset_bits) - 1)).checked_mul(8)
    };
    let mut records = Vec::new();
    let mut record_pages = 0u64;
    let mut page_idx = 2usize;
    while (page_idx + 1) * page_size <= data.len() && records.len() < MAX_LOG_RECORDS {
        let off = page_idx * page_size;
        page_idx += 1;
        let raw = &data[off..off + page_size];
        if &raw[0..4] != b"RCRD" {
            continue;
        }
        record_pages += 1;
        let mut pg = raw.to_vec();
        let _ = apply_fixups(&mut pg, 512);
        let mut p = data_off;
        while p + LOG_RECORD_HEADER + 0x20 <= page_size && records.len() < MAX_LOG_RECORDS {
            let lsn = u64_at(&pg, p)?;
            let valid = lsn != 0 && lsn_to_off(lsn) == Some((off + p) as u64);
            if !valid {
                p += 8;
                continue;
            }
            let dlen = u32_at(&pg, p + 0x18)?;
            let redo = u16_at(&pg, p + 0x30)?;
            let undo = u16_at(&pg, p + 0x32)?;
            let lcns = u16_at(&pg, p + 0x3E)?;
            let cbo = u16_at(&pg, p + 0x44)?;
            let tvcn = if p + 0x50 <= page_size { u64_at(&pg, p + 0x48)? } else { 0 };
            let tlcn = if lcns > 0 && p + 0x58 <= page_size { Some(u64_at(&pg, p + 0x50)?) } else { None };
            let mft_entry = if targets_mft_record(redo) && record_size > 0 {
                tvcn.checked_mul(cluster_size).and_then(|v| v.checked_add(cbo as u64 * 512)).map(|v| v / record_size)
            } else {
                None
            };
            records.push(LogRecord {
                offset: (off + p) as u64,
                lsn,
                client_previous_lsn: u64_at(&pg, p + 0x08)?,
                client_undo_next_lsn: u64_at(&pg, p + 0x10)?,
                client_data_length: dlen,
                record_type: u32_at(&pg, p + 0x20)?,
                transaction_id: u32_at(&pg, p + 0x24)?,
                flags: u16_at(&pg, p + 0x28)?,
                redo_op: redo,
                redo_op_name: op_name(redo).into(),
                undo_op: undo,
                undo_op_name: op_name(undo).into(),
                redo_length: u16_at(&pg, p + 0x36)?,
                undo_length: u16_at(&pg, p + 0x3A)?,
                target_attribute: u16_at(&pg, p + 0x3C)?,
                lcns_to_follow: lcns,
                record_offset: u16_at(&pg, p + 0x40)?,
                attribute_offset: u16_at(&pg, p + 0x42)?,
                cluster_block_offset: cbo,
                target_vcn: tvcn,
                target_lcn: tlcn,
                mft_entry,
            });
            let adv = (LOG_RECORD_HEADER + dlen as usize + 7) & !7;
            p = p.saturating_add(adv.max(8));
        }
    }
    records.sort_by_key(|r| (r.lsn, r.offset));
    records.dedup_by_key(|r| r.lsn);
    Ok(LogFile { restart_areas, page_size: page_size as u32, record_pages, records })
}
