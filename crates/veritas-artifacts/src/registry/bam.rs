//! Background / Desktop Activity Moderator (`windows:registry:bam`).
//!
//! `SYSTEM\<CCS>\Services\{bam,dam}\State\UserSettings\{SID}` (Windows 10 1809+) and
//! `SYSTEM\<CCS>\Services\{bam,dam}\UserSettings\{SID}` (1709 / 1803). Each value name is an
//! executable path; the first 8 bytes of its binary data are the last-execution FILETIME.
//! `Version` and `SequenceNumber` values are bookkeeping and skipped.
use super::{current_control_set, join, Ctx};
use crate::regf::Hive;
use veritas_timeline::{desc, filetime_to_ns, Event};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BamEntry {
    pub service: &'static str,
    pub sid: String,
    pub path: String,
    pub last_executed_ns: Option<i64>,
    pub key_rel_path: String,
    pub key_offset: u32,
}

pub fn entries(hive: &Hive) -> Vec<BamEntry> {
    let mut out = Vec::new();
    let Some(ccs) = current_control_set(hive) else {
        return out;
    };
    for svc in ["bam", "dam"] {
        for sub in ["State\\UserSettings", "UserSettings"] {
            let rel = format!("{ccs}\\Services\\{svc}\\{sub}");
            let Some(k) = hive.key(&rel) else { continue };
            for sid in k.subkeys() {
                for v in sid.values() {
                    if v.name.eq_ignore_ascii_case("Version")
                        || v.name.eq_ignore_ascii_case("SequenceNumber")
                        || v.raw.len() < 8
                    {
                        continue;
                    }
                    let ft = crate::util::u64_at(&v.raw, 0).unwrap_or(0);
                    out.push(BamEntry {
                        service: svc,
                        sid: sid.name.clone(),
                        path: v.name.clone(),
                        last_executed_ns: filetime_to_ns(ft),
                        key_rel_path: join(&rel, &sid.name),
                        key_offset: sid.offset,
                    });
                }
            }
        }
    }
    out
}

pub fn events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    entries(hive)
        .into_iter()
        .map(|e| {
            ctx.event(
                "bam",
                "windows:registry:bam",
                desc::LAST_RUN,
                e.last_executed_ns,
                format!("{} {} (SID {})", e.service.to_uppercase(), e.path, e.sid),
                &e.key_rel_path,
                e.key_offset,
            )
            .attr("service", e.service)
            .attr("user_sid", e.sid)
            .attr("path", e.path)
        })
        .collect()
}
