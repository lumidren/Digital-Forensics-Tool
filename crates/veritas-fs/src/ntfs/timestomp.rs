//! Timestomping heuristics over $STANDARD_INFORMATION, $FILE_NAME and USN records.
//! THREAT:T9.1 Timestomping detection compares $STANDARD_INFORMATION with $FILE_NAME and USN records.
use super::usn::{UsnRecord, DATA_CHANGE_MASK};
use super::FileEntry;
use serde::Serialize;
use std::collections::BTreeMap;

/// FILETIME ticks per second.
const TICKS_PER_SEC: u64 = 10_000_000;
/// Tolerance applied before a USN data change is considered "after" the $SI modification time (2 s).
pub const USN_TOLERANCE_TICKS: u64 = 2 * TICKS_PER_SEC;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Finding {
    pub entry: u64,
    pub sequence: u16,
    pub path: String,
    /// `si_before_fn`, `si_zero_subsecond` or `usn_after_si_mtime`.
    pub rule: String,
    /// Which timestamp: crtime / mtime / ctime / atime.
    pub field: String,
    pub si_value: u64,
    pub other_value: u64,
    pub detail: String,
}

fn fields(si: &super::record::StdInfo) -> [(&'static str, u64); 4] {
    [
        ("crtime", si.crtime),
        ("mtime", si.mtime),
        ("ctime", si.ctime),
        ("atime", si.atime),
    ]
}

/// Evaluate all rules. `usn` may be empty when no journal is available.
pub fn detect(entries: &[FileEntry], usn: &[UsnRecord]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut by_ref: BTreeMap<(u64, u16), u64> = BTreeMap::new();
    for r in usn {
        if r.reason & DATA_CHANGE_MASK != 0 {
            let e = by_ref.entry((r.file_entry, r.file_sequence)).or_insert(0);
            *e = (*e).max(r.timestamp_raw);
        }
    }
    for e in entries {
        if !e.is_base() {
            continue;
        }
        let Some(si) = &e.si else { continue };
        let path = e.path.clone().unwrap_or_default();
        let fname = e.best_name();
        if let Some(f) = fname {
            let fnf = [
                ("crtime", f.crtime),
                ("mtime", f.mtime),
                ("ctime", f.ctime),
                ("atime", f.atime),
            ];
            for ((name, s), (_, fv)) in fields(si).iter().zip(fnf.iter()) {
                // Rule 1: $SI earlier than $FN for creation/modification. $FN is only set by the kernel.
                if (*name == "crtime" || *name == "mtime") && *s != 0 && *fv != 0 && s < fv {
                    out.push(Finding {
                        entry: e.entry,
                        sequence: e.sequence,
                        path: path.clone(),
                        rule: "si_before_fn".into(),
                        field: name.to_string(),
                        si_value: *s,
                        other_value: *fv,
                        detail: format!("$SI {name} precedes $FN {name} by {} ticks", fv - s),
                    });
                }
                // Rule 2: $SI has whole-second precision while $FN does not (typical of SetFileTime tools).
                if (*name == "crtime" || *name == "mtime")
                    && *s != 0
                    && s % TICKS_PER_SEC == 0
                    && fv % TICKS_PER_SEC != 0
                {
                    out.push(Finding {
                        entry: e.entry,
                        sequence: e.sequence,
                        path: path.clone(),
                        rule: "si_zero_subsecond".into(),
                        field: name.to_string(),
                        si_value: *s,
                        other_value: *fv,
                        detail: format!("$SI {name} has zero sub-second precision, $FN does not"),
                    });
                }
            }
        }
        // Rule 3: the journal records a content change after the $SI modification time.
        if let Some(&t) = by_ref.get(&(e.entry, e.sequence)) {
            if t > si.mtime.saturating_add(USN_TOLERANCE_TICKS) {
                out.push(Finding {
                    entry: e.entry,
                    sequence: e.sequence,
                    path: path.clone(),
                    rule: "usn_after_si_mtime".into(),
                    field: "mtime".into(),
                    si_value: si.mtime,
                    other_value: t,
                    detail: "USN data change recorded after $SI modification time".into(),
                });
            }
        }
    }
    out.sort();
    out
}
