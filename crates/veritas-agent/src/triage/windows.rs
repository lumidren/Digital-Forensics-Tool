//! Windows collectors. Compiled on every platform (paths are data); only run on Windows.
//!
//! Privilege notes, recorded per item at run time when they bite:
//! - `reg save` (every hive, including HKCU), Prefetch, Security.evtx, `C:\Windows\System32\Tasks`
//!   and `\\.\C:` raw reads need an elevated token. Unprivileged, the user's own NTUSER and
//!   UsrClass are taken as `reg export` text files instead of binary hives.
//! - NTUSER.DAT / UsrClass.dat of other logged-on users and Amcache.hve are held open by the
//!   kernel; without a path-based raw NTFS read (out of scope) they are reported as errors.

use super::ntfs_raw::NtfsVolume;
use super::{profile_label, user_profiles, CollectorFn, Ctx};
use crate::{cmd, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub fn collectors() -> Vec<(&'static str, CollectorFn)> {
    vec![
        ("scheduled_tasks", scheduled_tasks),
        ("services", services),
        ("autoruns", autoruns),
        ("event_logs", event_logs),
        ("registry_hives", registry_hives),
        ("prefetch", prefetch),
        ("amcache", amcache),
        ("ntfs_metadata", ntfs_metadata),
    ]
}

fn system_root() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
}

fn system_drive() -> String {
    std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())
}

fn scheduled_tasks(ctx: &mut Ctx) -> Result<()> {
    let dir = system_root().join(r"System32\Tasks");
    ctx.bundle.add_tree("scheduled_tasks", "scheduled_tasks/Tasks", &dir, true, 20_000, &|_| true)?;
    ctx.command("scheduled_tasks", "scheduled_tasks/schtasks_query.xml", "schtasks", &["/query", "/xml", "ONE"])?;
    ctx.command("scheduled_tasks", "scheduled_tasks/schtasks_query_verbose.csv", "schtasks", &["/query", "/v", "/fo", "csv"])?;
    Ok(())
}

/// One service from `sc query`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub name: String,
    pub display_name: Option<String>,
    pub service_type: Option<String>,
    pub state: Option<String>,
}

/// Parse `sc query type= service state= all` output.
pub fn parse_sc_query(text: &str) -> Vec<ServiceRecord> {
    let mut out: Vec<ServiceRecord> = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        let Some((k, v)) = l.split_once(':') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "SERVICE_NAME" => out.push(ServiceRecord { name: v.to_string(), display_name: None, service_type: None, state: None }),
            "DISPLAY_NAME" => {
                if let Some(s) = out.last_mut() {
                    s.display_name = Some(v.to_string());
                }
            }
            "TYPE" => {
                if let Some(s) = out.last_mut() {
                    s.service_type = v.split_whitespace().nth(1).map(String::from);
                }
            }
            "STATE" => {
                if let Some(s) = out.last_mut() {
                    s.state = v.split_whitespace().nth(1).map(String::from);
                }
            }
            _ => {}
        }
    }
    out
}

fn services(ctx: &mut Ctx) -> Result<()> {
    if let Some(out) = ctx.command("services", "services/sc_query.txt", "sc", &["query", "type=", "service", "state=", "all"])? {
        ctx.bundle.add_json("services", "services/services.json", &parse_sc_query(&out.stdout_lossy()))?;
    }
    let reg = ctx.tmp.join("services.reg");
    let reg_s = reg.display().to_string();
    match cmd::run("reg", &["export", r"HKLM\SYSTEM\CurrentControlSet\Services", reg_s.as_str(), "/y"], ctx.opts.command_timeout) {
        Ok(o) if o.success() => {
            ctx.bundle.add_file("services", "services/Services.reg", &reg)?;
        }
        Ok(o) => ctx.bundle.error("services", r"reg export HKLM\SYSTEM\CurrentControlSet\Services", o.failure_text()),
        Err(e) => ctx.bundle.error("services", "reg export", e),
    }
    Ok(())
}

/// One value from `reg query`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegValue {
    pub key: String,
    pub name: String,
    pub value_type: String,
    pub data: String,
}

/// Parse `reg query <key> [/s]` output.
pub fn parse_reg_query(text: &str) -> Vec<RegValue> {
    let mut out = Vec::new();
    let mut key = String::new();
    for line in text.lines() {
        if line.starts_with("HKEY_") {
            key = line.trim().to_string();
            continue;
        }
        let Some(rest) = line.strip_prefix("    ") else { continue };
        let parts: Vec<&str> = rest.splitn(3, "    ").collect();
        if parts.len() >= 2 && parts[1].starts_with("REG_") {
            out.push(RegValue {
                key: key.clone(),
                name: parts[0].to_string(),
                value_type: parts[1].to_string(),
                data: parts.get(2).map(|s| s.to_string()).unwrap_or_default(),
            });
        }
    }
    out
}

#[derive(Serialize)]
struct Autoruns {
    registry: Vec<RegValue>,
    startup_folders: Vec<String>,
    wmi_subscriptions: Option<serde_json::Value>,
    see_also: Vec<&'static str>,
}

fn autoruns(ctx: &mut Ctx) -> Result<()> {
    let keys = [
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows",
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"HKLM\System\CurrentControlSet\Control\Session Manager",
    ];
    let mut values = Vec::new();
    let mut raw = String::new();
    for k in keys {
        let args: Vec<&str> = if k.ends_with("Image File Execution Options") { vec!["query", k, "/s", "/v", "Debugger"] } else { vec!["query", k] };
        match cmd::run("reg", &args, ctx.opts.command_timeout) {
            Ok(o) => {
                let text = o.stdout_lossy();
                raw.push_str(&text);
                values.extend(parse_reg_query(&text));
                let benign = o.stderr_lossy().contains("unable to find") || text.contains("0 match(es) found");
                if !o.success() && !benign {
                    ctx.bundle.error("autoruns", k, o.failure_text());
                }
            }
            Err(e) => ctx.bundle.error("autoruns", k, e),
        }
    }
    ctx.bundle.add_bytes("autoruns", "autoruns/reg_query.txt", raw.as_bytes(), None)?;

    let mut startup = Vec::new();
    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    let mut dirs = vec![("all_users".to_string(), PathBuf::from(program_data).join(r"Microsoft\Windows\Start Menu\Programs\StartUp"))];
    for p in user_profiles() {
        dirs.push((profile_label(&p), p.join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")));
    }
    for (label, d) in dirs {
        if d.is_dir() {
            let n = ctx.bundle.add_tree("autoruns", &format!("autoruns/startup/{}", label), &d, true, 1000, &|p| {
                !p.file_name().map(|n| n.eq_ignore_ascii_case("desktop.ini")).unwrap_or(false)
            })?;
            startup.push(format!("{} ({} files)", d.display(), n));
        }
    }

    let script = r"$ErrorActionPreference='Stop'; $r=[ordered]@{}; foreach($c in '__EventFilter','__EventConsumer','__FilterToConsumerBinding'){ $r[$c]=@(Get-WmiObject -Namespace root\subscription -Class $c | Select-Object -Property * -ExcludeProperty Scope,Options,ClassPath,Properties,SystemProperties,Qualifiers,Site,Container) }; $r | ConvertTo-Json -Depth 4 -Compress";
    let wmi = match cmd::powershell(script, ctx.opts.command_timeout) {
        Ok(o) if o.success() => {
            ctx.bundle.add_bytes("autoruns", "autoruns/wmi_subscriptions.json", &o.stdout, Some(r"Get-WmiObject -Namespace root\subscription"))?;
            serde_json::from_slice(&o.stdout).ok()
        }
        Ok(o) => {
            ctx.bundle.error("autoruns", r"WMI root\subscription", o.failure_text());
            None
        }
        Err(e) => {
            ctx.bundle.error("autoruns", r"WMI root\subscription", e);
            None
        }
    };
    let summary = Autoruns {
        registry: values,
        startup_folders: startup,
        wmi_subscriptions: wmi,
        see_also: vec!["services/services.json", "services/Services.reg", "scheduled_tasks/"],
    };
    ctx.bundle.add_json("autoruns", "autoruns/autoruns.json", &summary)?;
    Ok(())
}

const QUICK_LOGS: &[&str] = &[
    "Application.evtx",
    "System.evtx",
    "Security.evtx",
    "Windows PowerShell.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    "Microsoft-Windows-Windows Defender%4Operational.evtx",
    "Microsoft-Windows-WMI-Activity%4Operational.evtx",
    "Microsoft-Windows-Bits-Client%4Operational.evtx",
];

fn event_logs(ctx: &mut Ctx) -> Result<()> {
    let dir = system_root().join(r"System32\winevt\Logs");
    let entries = match std::fs::read_dir(&dir) {
        Ok(rd) => {
            let mut v: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().map(|e| e.eq_ignore_ascii_case("evtx")).unwrap_or(false)).collect();
            v.sort();
            v
        }
        Err(e) => {
            ctx.bundle.error("event_logs", &dir.display().to_string(), e);
            QUICK_LOGS.iter().map(|n| dir.join(n)).collect()
        }
    };
    for p in entries {
        let fname = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if ctx.opts.profile == super::Profile::Quick && !QUICK_LOGS.iter().any(|q| q.eq_ignore_ascii_case(&fname)) {
            continue;
        }
        let name = format!("event_logs/{}", fname);
        // Direct copy first (works elevated); fall back to exporting the channel with wevtutil,
        // which the event log service performs on our behalf where the channel ACL allows it.
        match std::fs::File::open(&p) {
            Ok(_) => {
                ctx.bundle.add_file("event_logs", &name, &p)?;
            }
            Err(open_err) => {
                let channel = fname.trim_end_matches(".evtx").replace("%4", "/");
                let out = ctx.tmp.join(format!("export_{}", fname.replace(' ', "_")));
                let out_s = out.display().to_string();
                match cmd::run("wevtutil", &["epl", channel.as_str(), out_s.as_str()], ctx.opts.command_timeout) {
                    Ok(o) if o.success() && out.is_file() => {
                        ctx.bundle.add_file("event_logs", &name, &out)?;
                        let _ = std::fs::remove_file(&out);
                    }
                    Ok(o) => ctx.bundle.error("event_logs", &p.display().to_string(), format!("copy: {}; wevtutil: {}", open_err, o.failure_text())),
                    Err(e) => ctx.bundle.error("event_logs", &p.display().to_string(), format!("copy: {}; wevtutil: {}", open_err, e)),
                }
            }
        }
    }
    Ok(())
}

/// `reg save` the key as a binary hive (needs SeBackupPrivilege, i.e. elevation). Returns whether
/// the hive was stored.
fn reg_save(ctx: &mut Ctx, key: &str, name: &str) -> Result<bool> {
    let out = ctx.tmp.join(name.replace('/', "_"));
    let out_s = out.display().to_string();
    match cmd::run("reg", &["save", key, out_s.as_str(), "/y"], ctx.opts.command_timeout) {
        Ok(o) if o.success() && out.is_file() => {
            ctx.bundle.add_file("registry_hives", name, &out)?;
            let _ = std::fs::remove_file(&out);
            return Ok(true);
        }
        Ok(o) => ctx.bundle.error("registry_hives", &format!("reg save {}", key), o.failure_text()),
        Err(e) => ctx.bundle.error("registry_hives", &format!("reg save {}", key), e),
    }
    Ok(false)
}

/// Unprivileged fallback for the user's own hives: `reg export` writes a text `.reg` file with
/// every value (shellbags, MRUs, UserAssist) but without key timestamps or slack, so it is
/// labelled as an export rather than a hive.
fn reg_export(ctx: &mut Ctx, key: &str, name: &str) -> Result<()> {
    let out = ctx.tmp.join(name.replace('/', "_"));
    let out_s = out.display().to_string();
    match cmd::run("reg", &["export", key, out_s.as_str(), "/y"], ctx.opts.command_timeout) {
        Ok(o) if o.success() && out.is_file() => {
            ctx.bundle.add_file("registry_hives", name, &out)?;
            let _ = std::fs::remove_file(&out);
        }
        Ok(o) => ctx.bundle.error("registry_hives", &format!("reg export {}", key), o.failure_text()),
        Err(e) => ctx.bundle.error("registry_hives", &format!("reg export {}", key), e),
    }
    Ok(())
}

fn current_user_sid() -> Option<String> {
    let out = cmd::run("whoami", &["/user", "/fo", "csv", "/nh"], std::time::Duration::from_secs(30)).ok()?;
    let line = out.stdout_lossy();
    line.trim().rsplit(',').next().map(|s| s.trim_matches('"').to_string()).filter(|s| s.starts_with("S-1-"))
}

fn registry_hives(ctx: &mut Ctx) -> Result<()> {
    // SYSTEM carries the shimcache (AppCompatCache); SAM and SECURITY need SYSTEM-level access
    // and usually fail even elevated, which is recorded.
    for hive in ["SYSTEM", "SOFTWARE", "SAM", "SECURITY"] {
        reg_save(ctx, &format!(r"HKLM\{}", hive), &format!("registry/HKLM/{}", hive))?;
    }
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "current".into());
    if !reg_save(ctx, "HKCU", &format!("registry/users/{}/NTUSER.DAT", user))? {
        reg_export(ctx, "HKCU", &format!("registry/users/{}/NTUSER.export.reg", user))?;
    }
    match current_user_sid() {
        Some(sid) => {
            let key = format!(r"HKU\{}_Classes", sid);
            if !reg_save(ctx, &key, &format!("registry/users/{}/UsrClass.dat", user))? {
                reg_export(ctx, &key, &format!("registry/users/{}/UsrClass.export.reg", user))?;
            }
        }
        None => ctx.bundle.error("registry_hives", "UsrClass.dat", "could not determine current user SID"),
    }
    // Other profiles: copy works only for users who are not logged on (hive not loaded).
    for p in user_profiles() {
        let label = profile_label(&p);
        if label.eq_ignore_ascii_case(&user) {
            continue;
        }
        ctx.copy_if_exists("registry_hives", &format!("registry/users/{}/NTUSER.DAT", label), &p.join("NTUSER.DAT"))?;
        ctx.copy_if_exists("registry_hives", &format!("registry/users/{}/UsrClass.dat", label), &p.join(r"AppData\Local\Microsoft\Windows\UsrClass.dat"))?;
    }
    Ok(())
}

fn prefetch(ctx: &mut Ctx) -> Result<()> {
    let dir = system_root().join("Prefetch");
    ctx.bundle.add_tree("prefetch", "prefetch", &dir, false, 5000, &|p: &Path| p.extension().map(|e| e.eq_ignore_ascii_case("pf")).unwrap_or(false))?;
    Ok(())
}

fn amcache(ctx: &mut Ctx) -> Result<()> {
    let dir = system_root().join(r"appcompat\Programs");
    for f in ["Amcache.hve", "Amcache.hve.LOG1", "Amcache.hve.LOG2"] {
        let p = dir.join(f);
        // Amcache.hve is held open by the system; a plain copy fails with a sharing violation.
        // Reading it through the raw volume by path is out of scope; the error is recorded.
        if p.exists() || f == "Amcache.hve" {
            ctx.bundle.add_file("amcache", &format!("amcache/{}", f), &p)?;
        }
    }
    Ok(())
}

/// Copy `$MFT`, `$LogFile` and `$UsnJrnl:$J` from the system volume through `\\.\C:`
/// (administrator only). Full profile only.
fn ntfs_metadata(ctx: &mut Ctx) -> Result<()> {
    if ctx.opts.profile != super::Profile::Full {
        return Ok(());
    }
    let drive = system_drive();
    let device = format!(r"\\.\{}", drive);
    let label = drive.trim_end_matches(':').to_string();
    let file = match std::fs::File::open(&device) {
        Ok(f) => f,
        Err(e) => {
            ctx.bundle.error("ntfs_metadata", &device, format!("raw volume open failed (needs administrator): {}", e));
            return Ok(());
        }
    };
    let mut vol = match NtfsVolume::open(file) {
        Ok(v) => v,
        Err(e) => {
            ctx.bundle.error("ntfs_metadata", &device, e);
            return Ok(());
        }
    };
    let mft = vol.mft_stream().clone();
    let large = mft.real_size > u32::MAX as u64;
    ctx.bundle.add_stream("ntfs_metadata", &format!("ntfs/{}/$MFT", label), Some(&format!("{}\\$MFT", device)), large, |w| {
        vol.copy_stream(&mft, w, false, &mut |_| {}).map(|_| ()).map_err(|e| e.to_string())
    })?;
    match vol.stream(2, 0x80, "") {
        Ok(log) => {
            ctx.bundle.add_stream("ntfs_metadata", &format!("ntfs/{}/$LogFile", label), Some(&format!("{}\\$LogFile", device)), false, |w| {
                vol.copy_stream(&log, w, false, &mut |_| {}).map(|_| ()).map_err(|e| e.to_string())
            })?;
        }
        Err(e) => ctx.bundle.error("ntfs_metadata", "$LogFile", e),
    }
    match vol.find_usnjrnl(4_000_000) {
        Ok(Some(rec)) => match vol.stream(rec, 0x80, "$J") {
            Ok(j) => {
                let mut extents = Vec::new();
                let large = j.real_size > u32::MAX as u64;
                ctx.bundle.add_stream("ntfs_metadata", &format!("ntfs/{}/$UsnJrnl_$J.allocated", label), Some(&format!("{}\\$Extend\\$UsnJrnl:$J", device)), large, |w| {
                    vol.copy_stream(&j, w, true, &mut |e| extents.push(e)).map(|_| ()).map_err(|e| e.to_string())
                })?;
                let map = serde_json::json!({
                    "stream": "$UsnJrnl:$J",
                    "mft_record": rec,
                    "logical_size": j.real_size,
                    "note": "sparse regions omitted; extents are (logical_offset, length) in order of the .allocated file",
                    "extents": extents,
                });
                ctx.bundle.add_json("ntfs_metadata", &format!("ntfs/{}/$UsnJrnl_$J.extents.json", label), &map)?;
            }
            Err(e) => ctx.bundle.error("ntfs_metadata", "$UsnJrnl:$J", e),
        },
        Ok(None) => ctx.bundle.error("ntfs_metadata", "$UsnJrnl", "no $Extend\\$UsnJrnl record found"),
        Err(e) => ctx.bundle.error("ntfs_metadata", "$UsnJrnl", e),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sc_query_parse() {
        let t = "\nSERVICE_NAME: AarSvc_1\nDISPLAY_NAME: Agent Activation Runtime\n        TYPE               : 60  USER_SHARE_PROCESS INSTANCE\n        STATE              : 1  STOPPED\n\nSERVICE_NAME: Appinfo\nDISPLAY_NAME: Application Information\n        TYPE               : 30  WIN32\n        STATE              : 4  RUNNING\n";
        let s = parse_sc_query(t);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].state.as_deref(), Some("STOPPED"));
        assert_eq!(s[1].display_name.as_deref(), Some("Application Information"));
        assert_eq!(s[1].service_type.as_deref(), Some("WIN32"));
    }

    #[test]
    fn reg_query_parse() {
        let t = "\r\nHKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\r\n    SecurityHealth    REG_EXPAND_SZ    %windir%\\system32\\SecurityHealthSystray.exe\r\n    Empty    REG_SZ    \r\n\r\n";
        let v = parse_reg_query(t);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "SecurityHealth");
        assert_eq!(v[0].value_type, "REG_EXPAND_SZ");
        assert!(v[0].data.ends_with("SecurityHealthSystray.exe"));
        assert_eq!(v[0].key, "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    }
}
