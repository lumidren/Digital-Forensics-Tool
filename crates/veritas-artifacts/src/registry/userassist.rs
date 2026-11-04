//! UserAssist (`windows:registry:userassist`).
//!
//! `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`.
//! Value names are ROT13 encoded. Data layouts:
//! - Windows XP / 2003 (16 bytes): session u32, execution count u32 (stored +5 when > 5),
//!   last execution FILETIME at 8.
//! - Windows 7 and later (72 bytes): u32 unknown, count u32 at 4, focus count u32 at 8,
//!   focus time (ms) u32 at 12, last execution FILETIME at 60.
//!
//! Other sizes (e.g. `UEME_CTLSESSION` blobs) are not execution records and are skipped.
use super::{join, Ctx};
use crate::regf::Hive;
use crate::util::{u32_at, u64_at};
use veritas_timeline::{desc, filetime_to_ns, Event};

pub const USERASSIST_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";

/// ROT13 for ASCII letters; everything else unchanged.
pub fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            _ => c,
        })
        .collect()
}

/// Known-folder GUIDs commonly seen as UserAssist path prefixes.
pub const KNOWN_FOLDERS: &[(&str, &str)] = &[
    ("{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}", "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs"),
    ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", "%SystemRoot%\\System32"),
    ("{374DE290-123F-4565-9164-39C4925E467B}", "%USERPROFILE%\\Downloads"),
    ("{5E6C858F-0E22-4760-9AFE-EA3317B67173}", "%USERPROFILE%"),
    ("{6D809377-6AF0-444B-8957-A3773F02200E}", "%ProgramFiles%"),
    ("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", "%ProgramFiles(x86)%"),
    ("{905E63B6-C1BF-494E-B29C-65B732D3D21A}", "%ProgramFiles%"),
    ("{9E3995AB-1F9C-4F13-B827-48B24B6C7174}", "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned"),
    ("{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}", "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs"),
    ("{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "%USERPROFILE%\\Desktop"),
    ("{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", "%SystemRoot%\\SysWOW64"),
    ("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", "%SystemRoot%"),
    ("{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}", "%ProgramFiles%\\Common Files"),
    ("{FDD39AD0-238F-46AF-ADB4-6C85480369C7}", "%USERPROFILE%\\Documents"),
];

/// Replace a leading known-folder GUID with its environment path.
pub fn expand_known_folder(name: &str) -> String {
    if name.starts_with('{') {
        if let Some(end) = name.find('}') {
            let guid = &name[..=end];
            if let Some((_, p)) = KNOWN_FOLDERS.iter().find(|(g, _)| g.eq_ignore_ascii_case(guid)) {
                return format!("{p}{}", &name[end + 1..]);
            }
        }
    }
    name.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAssistEntry {
    pub guid: String,
    /// ROT13-decoded value name.
    pub value_name: String,
    /// Value name with a known-folder GUID prefix expanded.
    pub path: String,
    pub format: &'static str,
    pub count: u32,
    pub focus_count: Option<u32>,
    pub focus_duration_ms: Option<u32>,
    pub last_executed_raw: u64,
    pub last_executed_ns: Option<i64>,
    pub key_rel_path: String,
    pub key_offset: u32,
    /// Position of the value in the key's value list.
    pub index: usize,
}

pub fn entries(hive: &Hive) -> Vec<UserAssistEntry> {
    let mut out = Vec::new();
    let Some(ua) = hive.key(USERASSIST_PATH) else { return out };
    for g in ua.subkeys() {
        let Some(count_key) = g.subkey("Count") else { continue };
        let rel = join(&join(USERASSIST_PATH, &g.name), &count_key.name);
        for (index, v) in count_key.values().into_iter().enumerate() {
            let decoded = rot13(&v.name);
            let raw = &v.raw;
            let (format, count, focus_count, focus_ms, ft) = match raw.len() {
                16 => {
                    let mut c = u32_at(raw, 4).unwrap_or(0);
                    if c > 5 {
                        c -= 5;
                    }
                    ("xp", c, None, None, u64_at(raw, 8).unwrap_or(0))
                }
                72 => (
                    "win7",
                    u32_at(raw, 4).unwrap_or(0),
                    u32_at(raw, 8).ok(),
                    u32_at(raw, 12).ok(),
                    u64_at(raw, 60).unwrap_or(0),
                ),
                _ => continue,
            };
            out.push(UserAssistEntry {
                guid: g.name.clone(),
                path: expand_known_folder(&decoded),
                value_name: decoded,
                format,
                count,
                focus_count,
                focus_duration_ms: focus_ms,
                last_executed_raw: ft,
                last_executed_ns: filetime_to_ns(ft),
                key_rel_path: rel.clone(),
                key_offset: count_key.offset,
                index,
            });
        }
    }
    out
}

pub fn events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    entries(hive)
        .into_iter()
        .map(|e| {
            let mut msg = format!("[{}] UserAssist entry: {} Value name: {} Count: {}", ctx.full_path(&e.key_rel_path), e.index, e.value_name, e.count);
            if let (Some(fc), Some(fd)) = (e.focus_count, e.focus_duration_ms) {
                msg.push_str(&format!(" Application focus count: {fc} Application focus duration: {fd}"));
            }
            let mut ev = ctx
                .event("userassist", "windows:registry:userassist", desc::LAST_RUN, e.last_executed_ns, msg, &e.key_rel_path, e.key_offset)
                .attr("guid", e.guid)
                .attr("value_name", e.value_name)
                .attr("path", e.path)
                .attr("format", e.format)
                .attr("number_of_executions", e.count)
                .attr("entry_index", e.index as u64);
            if let Some(fc) = e.focus_count {
                ev = ev.attr("application_focus_count", fc);
            }
            if let Some(fd) = e.focus_duration_ms {
                ev = ev.attr("application_focus_duration", fd);
            }
            ev
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_userassist_rot13() {
        assert_eq!(rot13("HRZR_EHACVQY:%pfvqy2%\\ZFA.yax"), "UEME_RUNPIDL:%csidl2%\\MSN.lnk");
        assert_eq!(expand_known_folder("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\calc.exe"), "%SystemRoot%\\System32\\calc.exe");
    }
}
