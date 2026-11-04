//! System information.
//!
//! SYSTEM: `windows:registry:sysinfo` (ComputerName, TimeZoneInformation, current control set),
//! `windows:registry:shutdown` (`Control\Windows\ShutdownTime`).
//! SOFTWARE: `windows:registry:sysinfo` (ProductName, CurrentVersion, CurrentBuild,
//! RegisteredOwner/Organization, ...), `windows:registry:installation` (InstallDate, Unix
//! seconds), `windows:registry:profile` (ProfileList SID -> profile path).
use super::{current_control_set, join, Ctx};
use crate::regf::Hive;
use std::collections::BTreeMap;
use veritas_timeline::{desc, filetime_to_ns, unix_secs_to_ns, Event};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemInfo {
    pub control_set: Option<String>,
    pub computer_name: Option<String>,
    /// TimeZoneKeyName when present, otherwise StandardName.
    pub timezone: Option<String>,
    pub timezone_bias_minutes: Option<i32>,
    pub active_time_bias_minutes: Option<i32>,
    pub standard_name: Option<String>,
    pub daylight_name: Option<String>,
    pub shutdown_ns: Option<i64>,
}

pub fn system_info(hive: &Hive) -> SystemInfo {
    let mut s = SystemInfo { control_set: current_control_set(hive), ..Default::default() };
    let Some(ccs) = s.control_set.clone() else { return s };
    if let Some(k) = hive.key(&format!("{ccs}\\Control\\ComputerName\\ComputerName")) {
        s.computer_name = k.value_string("ComputerName");
    }
    if let Some(k) = hive.key(&format!("{ccs}\\Control\\TimeZoneInformation")) {
        s.standard_name = k.value_string("StandardName");
        s.daylight_name = k.value_string("DaylightName");
        s.timezone = k.value_string("TimeZoneKeyName").filter(|t| !t.is_empty()).or(s.standard_name.clone());
        s.timezone_bias_minutes = k.value_u32("Bias").map(|b| b as i32);
        s.active_time_bias_minutes = k.value_u32("ActiveTimeBias").map(|b| b as i32);
    }
    if let Some(k) = hive.key(&format!("{ccs}\\Control\\Windows")) {
        s.shutdown_ns = k.value_u64("ShutdownTime").and_then(filetime_to_ns);
    }
    s
}

pub fn system_events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    let mut out = Vec::new();
    let si = system_info(hive);
    let Some(ccs) = si.control_set.clone() else { return out };
    let rel = format!("{ccs}\\Control\\ComputerName\\ComputerName");
    if let Some(k) = hive.key(&rel) {
        let mut e = ctx
            .event("sysinfo", "windows:registry:sysinfo", desc::WRITTEN, k.last_written_ns, format!("Computer name: {} Time zone: {}", si.computer_name.clone().unwrap_or_default(), si.timezone.clone().unwrap_or_default()), &rel, k.offset)
            .attr("control_set", ccs.clone());
        for (n, v) in [("computer_name", &si.computer_name), ("timezone", &si.timezone), ("standard_name", &si.standard_name), ("daylight_name", &si.daylight_name)] {
            if let Some(v) = v {
                e = e.attr(n, v.clone());
            }
        }
        if let Some(b) = si.timezone_bias_minutes {
            e = e.attr("timezone_bias_minutes", b);
        }
        if let Some(b) = si.active_time_bias_minutes {
            e = e.attr("active_time_bias_minutes", b);
        }
        out.push(e);
    }
    let rel = format!("{ccs}\\Control\\Windows");
    if let (Some(k), Some(t)) = (hive.key(&rel), si.shutdown_ns) {
        out.push(ctx.event("shutdown", "windows:registry:shutdown", "Last Shutdown Time", Some(t), format!("[{}] ShutdownTime", ctx.full_path(&rel)), &rel, k.offset).attr("value_name", "ShutdownTime"));
    }
    out
}

pub const CURRENT_VERSION: &str = "Microsoft\\Windows NT\\CurrentVersion";
const CV_FIELDS: &[&str] = &[
    "ProductName", "CurrentVersion", "CurrentMajorVersionNumber", "CurrentMinorVersionNumber", "CurrentBuild", "CurrentBuildNumber", "DisplayVersion", "ReleaseId",
    "EditionID", "CSDVersion", "BuildLab", "RegisteredOwner", "RegisteredOrganization", "ProductId", "SystemRoot", "InstallationType",
];

/// Selected `Windows NT\CurrentVersion` values as strings.
pub fn current_version(hive: &Hive) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Some(k) = hive.key(CURRENT_VERSION) {
        for f in CV_FIELDS {
            if let Some(s) = k.value_string(f).filter(|s| !s.is_empty()) {
                m.insert(f.to_string(), s);
            }
        }
        if let Some(t) = k.value_u32("InstallDate") {
            m.insert("InstallDate".into(), t.to_string());
        }
    }
    m
}

/// ProfileList: (SID, ProfileImagePath, key last-written ns, key rel path, offset).
pub fn profiles(hive: &Hive) -> Vec<(String, String, Option<i64>, String, u32)> {
    let rel = format!("{CURRENT_VERSION}\\ProfileList");
    let Some(k) = hive.key(&rel) else { return vec![] };
    k.subkeys().into_iter().map(|p| (p.name.clone(), p.value_string("ProfileImagePath").unwrap_or_default(), p.last_written_ns, join(&rel, &p.name), p.offset)).collect()
}

pub fn software_events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    let mut out = Vec::new();
    if let Some(k) = hive.key(CURRENT_VERSION) {
        let cv = current_version(hive);
        let mut e = ctx.event(
            "sysinfo",
            "windows:registry:sysinfo",
            desc::WRITTEN,
            k.last_written_ns,
            format!("Product: {} Version: {} Build: {} Owner: {}", cv.get("ProductName").cloned().unwrap_or_default(), cv.get("CurrentVersion").cloned().unwrap_or_default(), cv.get("CurrentBuild").cloned().unwrap_or_default(), cv.get("RegisteredOwner").cloned().unwrap_or_default()),
            CURRENT_VERSION,
            k.offset,
        );
        for (n, v) in &cv {
            e = e.attr(&n.to_ascii_lowercase(), v.clone());
        }
        out.push(e);
        if let Some(t) = k.value_u32("InstallDate").filter(|&t| t != 0).and_then(|t| unix_secs_to_ns(t as i64)) {
            out.push(
                ctx.event("windows_version", "windows:registry:installation", desc::INSTALLATION, Some(t), format!("{} {} installed", cv.get("ProductName").cloned().unwrap_or_default(), cv.get("CSDVersion").cloned().unwrap_or_default()).trim_end().to_string(), CURRENT_VERSION, k.offset)
                    .attr("product_name", cv.get("ProductName").cloned().unwrap_or_default())
                    .attr("owner", cv.get("RegisteredOwner").cloned().unwrap_or_default()),
            );
        }
    }
    for (sid, path, ts, rel, off) in profiles(hive) {
        out.push(ctx.event("profile_list", "windows:registry:profile", desc::WRITTEN, ts, format!("SID: {sid} Profile path: {path}"), &rel, off).attr("sid", sid).attr("profile_path", path));
    }
    out
}
