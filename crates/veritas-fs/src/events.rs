//! Conversion of file-system metadata into `veritas_timeline::Event`s (Plaso data types
//! `fs:stat:ntfs`, `fs:ntfs:usn_change`, `fs:ntfs:logfile`, `fs:stat`, `fs:apfs:snapshot`,
//! `fs:vss:snapshot`).
use crate::apfs::{ApfsEntry, Snapshot};
use crate::ext4::ExtEntry;
use crate::fat::FatEntry;
use crate::image::{AnyFs, ImageVolume};
use crate::ntfs::logfile::LogRecord;
use crate::ntfs::usn::UsnRecord;
use crate::ntfs::FileEntry;
use crate::vss::StoreInfo;
use crate::PARSER_VERSION;
use std::sync::Arc;
use veritas_timeline::{desc, filetime_to_ns, Event};

/// Evidence context stamped on every event.
#[derive(Debug, Clone, Default)]
pub struct Ctx {
    pub evidence_sha256: String,
    /// Prefix for `evidence_path` (e.g. `p1` for partition 1); empty for a bare file system.
    pub volume_prefix: String,
}

impl Ctx {
    fn path(&self, p: &str) -> String {
        if self.volume_prefix.is_empty() {
            p.to_string()
        } else {
            format!("{}:{}", self.volume_prefix, p)
        }
    }
}

fn ev(
    ctx: &Ctx,
    data_type: &str,
    tdesc: &str,
    ts: Option<i64>,
    msg: String,
    path: &str,
    offset: i64,
    parser: &str,
) -> Event {
    Event::new(data_type, tdesc, msg).with_time(ts).provenance(
        &ctx.evidence_sha256,
        &ctx.path(path),
        offset,
        parser,
        PARSER_VERSION,
    )
}

fn four_times(crtime: u64, mtime: u64, atime: u64, ctime: u64) -> [(&'static str, Option<i64>); 4] {
    [
        (desc::CREATION, filetime_to_ns(crtime)),
        (desc::MODIFICATION, filetime_to_ns(mtime)),
        (desc::ACCESS, filetime_to_ns(atime)),
        (desc::METADATA_MODIFICATION, filetime_to_ns(ctime)),
    ]
}

/// `fs:stat:ntfs` events: one per non-zero timestamp of $STANDARD_INFORMATION and of each $FILE_NAME.
pub fn ntfs_entry_events(ctx: &Ctx, entries: &[FileEntry]) -> Vec<Event> {
    let mut out = Vec::new();
    // Timestomp indicators per MFT entry ($SI vs $FN only; USN-based checks run in analytics).
    let mut stomp: std::collections::BTreeMap<u64, std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();
    for f in crate::ntfs::timestomp::detect(entries, &[]) {
        stomp.entry(f.entry).or_default().insert(f.rule);
    }
    for e in entries {
        if !e.is_base() {
            continue;
        }
        let path = e.path.clone().unwrap_or_default();
        let name = e.name().unwrap_or_default().to_string();
        let display = format!("NTFS:{path}");
        let pref = e
            .best_name()
            .map(|f| format!("{}-{}", f.parent_entry, f.parent_sequence))
            .unwrap_or_default();
        // $SI and primary $FN times on every event of the entry, so analytics can compare them
        // without re-reading the MFT.
        let mut entry_times: Vec<(String, serde_json::Value)> = Vec::new();
        if let Some(si) = &e.si {
            for (k, v) in [
                ("si_crtime_ns", si.crtime),
                ("si_mtime_ns", si.mtime),
                ("si_atime_ns", si.atime),
                ("si_ctime_ns", si.ctime),
            ] {
                if let Some(ns) = filetime_to_ns(v) {
                    entry_times.push((k.to_string(), ns.into()));
                }
            }
        }
        if let Some(f) = e.best_name() {
            for (k, v) in [
                ("fn_crtime_ns", f.crtime),
                ("fn_mtime_ns", f.mtime),
                ("fn_atime_ns", f.atime),
                ("fn_ctime_ns", f.ctime),
            ] {
                if let Some(ns) = filetime_to_ns(v) {
                    entry_times.push((k.to_string(), ns.into()));
                }
            }
        }
        let indicators: Vec<String> = stomp
            .get(&e.entry)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        let mut push = |attr_type: u32,
                        aname: &str,
                        parent: &str,
                        times: [(&'static str, Option<i64>); 4],
                        source: &str| {
            for (d, t) in times {
                if t.is_none() {
                    continue;
                }
                let msg = format!(
                    "{display} File reference: {} Attribute name: {source}{}",
                    e.file_reference(),
                    if e.in_use { "" } else { " (unallocated)" }
                );
                out.push(
                    ev(
                        ctx,
                        "fs:stat:ntfs",
                        d,
                        t,
                        msg,
                        &path,
                        e.entry as i64,
                        "veritas-fs/ntfs",
                    )
                    .attr("file_reference", e.file_reference())
                    .attr("parent_file_reference", parent.to_string())
                    .attr("is_allocated", e.in_use)
                    .attr("attribute_type", attr_type)
                    .attr("name", aname.to_string())
                    .attr("path", path.clone())
                    .attr("file_size", e.size())
                    .attr("display_name", display.clone()),
                );
                if let Some(last) = out.last_mut() {
                    for (k, v) in &entry_times {
                        last.attrs.insert(k.clone(), v.clone());
                    }
                    if !indicators.is_empty() {
                        last.attrs
                            .insert("timestomp_indicators".into(), indicators.clone().into());
                    }
                    last.source_short = "FILE".into();
                    last.source_long = format!("NTFS {source}");
                }
            }
        };
        if let Some(si) = &e.si {
            push(
                0x10,
                &name,
                &pref,
                four_times(si.crtime, si.mtime, si.atime, si.ctime),
                "$STANDARD_INFORMATION",
            );
        }
        for f in &e.file_names {
            let p = format!("{}-{}", f.parent_entry, f.parent_sequence);
            push(
                0x30,
                &f.name,
                &p,
                four_times(f.crtime, f.mtime, f.atime, f.ctime),
                "$FILE_NAME",
            );
        }
    }
    out
}

/// `fs:ntfs:usn_change` events.
pub fn usn_events(ctx: &Ctx, recs: &[UsnRecord], journal_path: &str) -> Vec<Event> {
    recs.iter()
        .map(|r| {
            let msg = format!(
                "{} File reference: {}-{} Parent file reference: {}-{} Update reason: {}",
                r.name,
                r.file_entry,
                r.file_sequence,
                r.parent_entry,
                r.parent_sequence,
                r.reasons.join(", ")
            );
            let mut e = ev(
                ctx,
                "fs:ntfs:usn_change",
                desc::ENTRY_MODIFICATION,
                r.timestamp,
                msg,
                journal_path,
                r.offset as i64,
                "veritas-fs/usnjrnl",
            )
            .attr("filename", r.name.clone())
            .attr(
                "file_reference",
                format!("{}-{}", r.file_entry, r.file_sequence),
            )
            .attr(
                "parent_file_reference",
                format!("{}-{}", r.parent_entry, r.parent_sequence),
            )
            .attr("update_reason_flags", r.reason)
            .attr("update_reason", r.reasons.join(", "))
            .attr("update_sequence_number", r.usn)
            .attr("update_source_flags", r.source_info)
            .attr("file_attribute_flags", r.file_attributes)
            .attr("major_version", r.major_version);
            e.source_short = "FILE".into();
            e.source_long = "NTFS USN change".into();
            e
        })
        .collect()
}

/// `fs:ntfs:logfile` events (log records carry no timestamp; `timestamp` is `None`).
pub fn logfile_events(ctx: &Ctx, recs: &[LogRecord]) -> Vec<Event> {
    recs.iter()
        .map(|r| {
            let msg = format!(
                "LSN {} redo: {} undo: {} transaction: {}{}",
                r.lsn,
                r.redo_op_name,
                r.undo_op_name,
                r.transaction_id,
                r.mft_entry
                    .map(|m| format!(" MFT entry: {m}"))
                    .unwrap_or_default()
            );
            let mut e = ev(
                ctx,
                "fs:ntfs:logfile",
                desc::NOT_A_TIME,
                None,
                msg,
                "/$LogFile",
                r.offset as i64,
                "veritas-fs/logfile",
            )
            .attr("lsn", r.lsn)
            .attr("redo_operation", r.redo_op_name.clone())
            .attr("undo_operation", r.undo_op_name.clone())
            .attr("transaction_id", r.transaction_id)
            .attr("record_type", r.record_type)
            .attr("target_vcn", r.target_vcn);
            if let Some(m) = r.mft_entry {
                e = e.attr("mft_entry", m);
            }
            e.source_short = "FILE".into();
            e.source_long = "NTFS $LogFile".into();
            e
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn stat_events(
    ctx: &Ctx,
    fs_type: &str,
    path: &str,
    name: &str,
    kind: &str,
    size: u64,
    inode: u64,
    allocated: bool,
    times: [(&'static str, Option<i64>); 4],
    parser: &str,
) -> Vec<Event> {
    let display = format!("{fs_type}:{path}");
    times
        .into_iter()
        .filter(|(_, t)| t.is_some())
        .map(|(d, t)| {
            let mut e = ev(
                ctx,
                "fs:stat",
                d,
                t,
                format!(
                    "{display} Type: {kind}{}",
                    if allocated { "" } else { " (unallocated)" }
                ),
                path,
                inode as i64,
                parser,
            )
            .attr("file_system_type", fs_type.to_string())
            .attr("file_entry_type", kind.to_string())
            .attr("filename", name.to_string())
            .attr("path", path.to_string())
            .attr("file_size", size)
            .attr("inode", inode)
            .attr("is_allocated", allocated)
            .attr("display_name", display.clone());
            e.source_short = "FILE".into();
            e.source_long = format!("{fs_type} stat");
            e
        })
        .collect()
}

pub fn fat_events(ctx: &Ctx, fs_type: &str, entries: &[FatEntry]) -> Vec<Event> {
    entries
        .iter()
        .flat_map(|e| {
            stat_events(
                ctx,
                fs_type,
                &e.path,
                &e.name,
                if e.is_dir { "directory" } else { "file" },
                e.size,
                e.dir_entry_offset,
                !e.deleted,
                [
                    (desc::CREATION, e.crtime),
                    (desc::MODIFICATION, e.mtime),
                    (desc::ACCESS, e.atime),
                    (desc::METADATA_MODIFICATION, None),
                ],
                "veritas-fs/fat",
            )
        })
        .collect()
}

pub fn ext_events(ctx: &Ctx, fs_type: &str, entries: &[ExtEntry]) -> Vec<Event> {
    entries
        .iter()
        .flat_map(|e| {
            stat_events(
                ctx,
                fs_type,
                &e.path,
                &e.name,
                &e.kind,
                e.size,
                e.inode,
                e.allocated && !e.deleted_name,
                [
                    (desc::CREATION, e.crtime),
                    (desc::MODIFICATION, e.mtime),
                    (desc::ACCESS, e.atime),
                    (desc::METADATA_MODIFICATION, e.ctime),
                ],
                "veritas-fs/ext",
            )
        })
        .collect()
}

pub fn apfs_events(ctx: &Ctx, entries: &[ApfsEntry]) -> Vec<Event> {
    entries
        .iter()
        .flat_map(|e| {
            let mut v = stat_events(
                ctx,
                "APFS",
                &e.path,
                &e.name,
                &e.kind,
                e.size,
                e.id,
                true,
                [
                    (desc::CREATION, e.crtime),
                    (desc::MODIFICATION, e.mtime),
                    (desc::ACCESS, e.atime),
                    (desc::METADATA_MODIFICATION, e.ctime),
                ],
                "veritas-fs/apfs",
            );
            if e.added.is_some() {
                v.extend(stat_events(
                    ctx,
                    "APFS",
                    &e.path,
                    &e.name,
                    &e.kind,
                    e.size,
                    e.id,
                    true,
                    [
                        ("Added Time", e.added),
                        (desc::NOT_A_TIME, None),
                        (desc::NOT_A_TIME, None),
                        (desc::NOT_A_TIME, None),
                    ],
                    "veritas-fs/apfs",
                ));
            }
            v
        })
        .collect()
}

pub fn apfs_snapshot_events(ctx: &Ctx, volume: &str, snaps: &[Snapshot]) -> Vec<Event> {
    snaps
        .iter()
        .map(|s| {
            let mut e = ev(
                ctx,
                "fs:apfs:snapshot",
                desc::CREATION,
                s.create_time,
                format!(
                    "APFS snapshot '{}' of volume '{}' (xid {})",
                    s.name, volume, s.xid
                ),
                &format!("/{volume}"),
                s.xid as i64,
                "veritas-fs/apfs",
            )
            .attr("name", s.name.clone())
            .attr("xid", s.xid)
            .attr("volume", volume.to_string());
            e.source_short = "FILE".into();
            e.source_long = "APFS snapshot".into();
            e
        })
        .collect()
}

pub fn vss_events(ctx: &Ctx, stores: &[StoreInfo]) -> Vec<Event> {
    stores
        .iter()
        .map(|s| {
            let mut e = ev(
                ctx,
                "fs:vss:snapshot",
                desc::CREATION,
                s.creation_time,
                format!("Volume shadow copy {} (store {})", s.identifier, s.index),
                "/",
                s.index as i64,
                "veritas-fs/vss",
            )
            .attr("identifier", s.identifier.clone())
            .attr("copy_identifier", s.copy_identifier.clone())
            .attr("copy_set_identifier", s.copy_set_identifier.clone())
            .attr("store_index", s.index)
            .attr("volume_size", s.volume_size)
            .attr("store_size", s.store_size)
            .attr("operating_machine", s.operating_machine.clone());
            e.source_short = "FILE".into();
            e.source_long = "VSS store".into();
            e
        })
        .collect()
}

/// All file-system events of one volume. Errors in optional sources (USN, $LogFile, VSS) are skipped.
pub fn volume_events(ctx: &Ctx, v: &ImageVolume) -> crate::Result<Vec<Event>> {
    let fs = AnyFs::open(v)?;
    let mut out = Vec::new();
    match &fs {
        AnyFs::Ntfs(n) => {
            out.extend(ntfs_entry_events(ctx, &n.entries()?));
            if let Ok(u) = n.usn_records() {
                out.extend(usn_events(ctx, &u, "/$Extend/$UsnJrnl:$J"));
            }
            if let Ok(l) = n.logfile() {
                out.extend(logfile_events(ctx, &l.records));
            }
            if crate::vss::probe(v.src.as_ref()) {
                if let Ok(vs) = crate::vss::Vss::open(v.src.clone()) {
                    let vs = Arc::new(vs);
                    out.extend(vss_events(ctx, &vs.stores));
                }
            }
        }
        AnyFs::Fat(f) => out.extend(fat_events(ctx, f.kind.name(), &f.walk(true)?)),
        AnyFs::Ext(x) => out.extend(ext_events(ctx, &fs.type_name(), &x.walk(true)?)),
        AnyFs::Apfs(a) => {
            for (i, vol) in a.volumes.iter().enumerate() {
                if let Ok(w) = a.walk(i) {
                    out.extend(apfs_events(ctx, &w));
                }
                if let Ok(s) = a.snapshots(i) {
                    out.extend(apfs_snapshot_events(ctx, &vol.name, &s));
                }
            }
        }
    }
    Ok(out)
}
