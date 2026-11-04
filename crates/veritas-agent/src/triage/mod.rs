//! Live triage: collectors that write structured JSON and copied artifact files into a ZIP
//! bundle whose `manifest.json` lists every file with its SHA-256 and collection time.
//!
//! Every collector runs unprivileged without failing: anything it cannot read is recorded in
//! `manifest.errors` with the reason, and collection continues. Collectors are chosen at run time
//! for the host OS (`windows`, `linux`, `macos`).

pub mod bundle;
pub mod network;
pub mod ntfs_raw;
mod unix;
mod windows;

use crate::cmd;
use crate::Result;
use bundle::{BundleWriter, Manifest};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Collection depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// Volatile state, persistence, key logs and hives; minutes.
    Quick,
    /// Everything, including raw `$MFT`, `$LogFile`, `$UsnJrnl:$J` and all event logs.
    Full,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Quick => "quick",
            Profile::Full => "full",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TriageOptions {
    pub profile: Profile,
    /// Per-file size cap for copied artifacts (larger files are truncated and flagged).
    pub max_file_bytes: u64,
    /// Hash each process executable.
    pub hash_executables: bool,
    /// Run only these collectors (by name) when set.
    pub only: Option<Vec<String>>,
    /// Timeout for each external command.
    pub command_timeout: Duration,
}

impl Default for TriageOptions {
    fn default() -> Self {
        Self { profile: Profile::Quick, max_file_bytes: 512 * 1024 * 1024, hash_executables: true, only: None, command_timeout: Duration::from_secs(180) }
    }
}

/// Collection context handed to every collector.
pub struct Ctx<'a> {
    pub bundle: &'a mut BundleWriter,
    pub opts: &'a TriageOptions,
    /// Scratch directory for command outputs (`reg save`, `wevtutil epl`, `log collect`).
    pub tmp: PathBuf,
}

impl Ctx<'_> {
    /// Run a command and store its stdout as `name`; failures are recorded, never fatal.
    pub fn command(&mut self, collector: &str, name: &str, program: &str, args: &[&str]) -> Result<Option<cmd::CmdOutput>> {
        match cmd::run(program, args, self.opts.command_timeout) {
            Ok(out) => {
                if !out.stdout.is_empty() {
                    self.bundle.add_bytes(collector, name, &out.stdout, Some(&format!("{} {}", program, args.join(" "))))?;
                }
                if !out.success() {
                    self.bundle.error(collector, &format!("{} {}", program, args.join(" ")), out.failure_text());
                }
                Ok(Some(out))
            }
            Err(e) => {
                self.bundle.error(collector, &format!("{} {}", program, args.join(" ")), e);
                Ok(None)
            }
        }
    }

    /// Copy a file if it exists; a missing file is silently skipped, other failures recorded.
    pub fn copy_if_exists(&mut self, collector: &str, name: &str, path: &Path) -> Result<()> {
        if path.exists() {
            self.bundle.add_file(collector, name, path)?;
        }
        Ok(())
    }
}

type CollectorFn = fn(&mut Ctx) -> Result<()>;

/// Collectors for the current OS, in run order.
pub fn collectors_for_os(os: &str) -> Vec<(&'static str, CollectorFn)> {
    let mut v: Vec<(&'static str, CollectorFn)> = vec![("system", collect_system), ("processes", collect_processes), ("network", collect_network)];
    match os {
        "windows" => v.extend(windows::collectors()),
        "linux" => v.extend(unix::linux_collectors()),
        "macos" => v.extend(unix::macos_collectors()),
        _ => {}
    }
    v.push(("browsers", collect_browsers));
    v
}

/// Run every collector and write the bundle to `out`.
pub fn run_triage(out: &Path, opts: &TriageOptions, progress: &mut dyn FnMut(&str, usize, usize)) -> Result<Manifest> {
    let mut bundle = BundleWriter::create(out, opts.profile.as_str(), opts.max_file_bytes)?;
    bundle.set_elevated(is_elevated());
    let tmp = tempfile::tempdir()?;
    let list: Vec<_> = collectors_for_os(std::env::consts::OS)
        .into_iter()
        .filter(|(n, _)| opts.only.as_ref().map(|o| o.iter().any(|x| x == n)).unwrap_or(true))
        .collect();
    let total = list.len();
    for (i, (name, f)) in list.into_iter().enumerate() {
        progress(name, i, total);
        let mut ctx = Ctx { bundle: &mut bundle, opts, tmp: tmp.path().to_path_buf() };
        f(&mut ctx)?;
    }
    progress("done", total, total);
    bundle.finish()
}

/// Whether the agent runs with administrative rights (`None` when undeterminable).
pub fn is_elevated() -> Option<bool> {
    let t = Duration::from_secs(30);
    if cfg!(windows) {
        // High (S-1-16-12288) or System (S-1-16-16384) mandatory level means elevated.
        let out = cmd::run("whoami", &["/groups"], t).ok()?;
        let s = out.stdout_lossy();
        Some(s.contains("S-1-16-12288") || s.contains("S-1-16-16384"))
    } else {
        let out = cmd::run("id", &["-u"], t).ok()?;
        Some(out.stdout_lossy().trim() == "0")
    }
}

/// User profile directories on this host.
pub fn user_profiles() -> Vec<PathBuf> {
    let mut v = Vec::new();
    let skip = ["public", "default", "default user", "all users", "shared", "desktop.ini"];
    let roots: Vec<PathBuf> = match std::env::consts::OS {
        "windows" => vec![PathBuf::from(format!("{}\\Users", std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())))],
        "macos" => vec![PathBuf::from("/Users")],
        _ => {
            v.push(PathBuf::from("/root"));
            vec![PathBuf::from("/home")]
        }
    };
    for r in roots {
        if let Ok(rd) = std::fs::read_dir(&r) {
            let mut ps: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
            ps.sort();
            for p in ps {
                let n = p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
                if !skip.contains(&n.as_str()) {
                    v.push(p);
                }
            }
        }
    }
    v
}

fn profile_label(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "unknown".into())
}

#[derive(Serialize)]
struct SystemInfo {
    host: Option<String>,
    os: &'static str,
    os_version: Option<String>,
    kernel_version: Option<String>,
    boot_time: Option<String>,
    uptime_seconds: u64,
    collected_at: String,
    elevated: Option<bool>,
    agent: String,
    users: Vec<BTreeMap<String, String>>,
    timezone_offset_seconds: i32,
}

fn collect_system(ctx: &mut Ctx) -> Result<()> {
    let users = sysinfo::Users::new_with_refreshed_list();
    let users = users
        .list()
        .iter()
        .map(|u| {
            let mut m = BTreeMap::new();
            m.insert("name".to_string(), u.name().to_string());
            m.insert("id".to_string(), u.id().to_string());
            m
        })
        .collect();
    let info = SystemInfo {
        host: sysinfo::System::host_name(),
        os: std::env::consts::OS,
        os_version: sysinfo::System::long_os_version(),
        kernel_version: sysinfo::System::kernel_version(),
        boot_time: Utc.timestamp_opt(sysinfo::System::boot_time() as i64, 0).single().map(|d| d.to_rfc3339()),
        uptime_seconds: sysinfo::System::uptime(),
        collected_at: Utc::now().to_rfc3339(),
        elevated: ctx.bundle.manifest().elevated,
        agent: format!("{} {}", crate::AGENT_NAME, crate::AGENT_VERSION),
        users,
        timezone_offset_seconds: chrono::Local::now().offset().local_minus_utc(),
    };
    ctx.bundle.add_json("system", "system/system_info.json", &info)?;
    Ok(())
}

/// One running process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRecord {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe: Option<String>,
    pub cmdline: Vec<String>,
    pub user: Option<String>,
    pub user_id: Option<String>,
    pub start_time: Option<String>,
    pub exe_sha256: Option<String>,
    pub error: Option<String>,
}

fn collect_processes(ctx: &mut Ctx) -> Result<()> {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(sysinfo::ProcessesToUpdate::All, true, sysinfo::ProcessRefreshKind::everything());
    let users = sysinfo::Users::new_with_refreshed_list();
    let mut cache: BTreeMap<PathBuf, std::result::Result<String, String>> = BTreeMap::new();
    let mut records = Vec::new();
    let mut pids: Vec<_> = sys.processes().keys().copied().collect();
    pids.sort();
    for pid in pids {
        let Some(p) = sys.process(pid) else { continue };
        let exe = p.exe().map(|e| e.to_path_buf());
        let mut error = None;
        let exe_sha256 = match (&exe, ctx.opts.hash_executables) {
            (Some(path), true) if !path.as_os_str().is_empty() => {
                let r = cache.entry(path.clone()).or_insert_with(|| {
                    let len = std::fs::metadata(path).map(|m| m.len()).map_err(|e| e.to_string())?;
                    if len > ctx.opts.max_file_bytes {
                        return Err(format!("executable larger than {} bytes, not hashed", ctx.opts.max_file_bytes));
                    }
                    crate::sha256_file(path).map_err(|e| e.to_string())
                });
                match r {
                    Ok(h) => Some(h.clone()),
                    Err(e) => {
                        error = Some(format!("exe hash: {}", e));
                        None
                    }
                }
            }
            (None, _) => {
                error = Some("executable path not readable (insufficient privilege or kernel process)".into());
                None
            }
            _ => None,
        };
        let user_id = p.user_id().map(|u| u.to_string());
        let user = p.user_id().and_then(|u| users.get_user_by_id(u)).map(|u| u.name().to_string());
        records.push(ProcessRecord {
            pid: pid.as_u32(),
            ppid: p.parent().map(|x| x.as_u32()),
            name: p.name().to_string_lossy().into_owned(),
            exe: exe.map(|e| e.display().to_string()),
            cmdline: p.cmd().iter().map(|c| c.to_string_lossy().into_owned()).collect(),
            user,
            user_id,
            start_time: if p.start_time() > 0 { Utc.timestamp_opt(p.start_time() as i64, 0).single().map(|d| d.to_rfc3339()) } else { None },
            exe_sha256,
            error,
        });
    }
    ctx.bundle.add_json("processes", "processes/processes.json", &records)?;
    Ok(())
}

fn collect_network(ctx: &mut Ctx) -> Result<()> {
    let t = ctx.opts.command_timeout;
    let mut conns = Vec::new();
    match std::env::consts::OS {
        "windows" => {
            if let Some(out) = ctx.command("network", "network/netstat_ano.txt", "netstat", &["-ano"])? {
                conns = network::parse_netstat_windows(&out.stdout_lossy());
            }
        }
        "linux" => {
            let owners = network::linux_socket_owners();
            for proto in ["tcp", "tcp6", "udp", "udp6"] {
                let p = PathBuf::from(format!("/proc/net/{}", proto));
                match std::fs::read_to_string(&p) {
                    Ok(text) => {
                        ctx.bundle.add_bytes("network", &format!("network/proc_net_{}.txt", proto), text.as_bytes(), Some(&p.display().to_string()))?;
                        for mut c in network::parse_proc_net(&text, proto) {
                            if let Some((pid, comm)) = c.inode.and_then(|i| owners.get(&i)) {
                                c.pid = Some(*pid);
                                c.process = Some(comm.clone());
                            }
                            conns.push(c);
                        }
                    }
                    Err(e) => ctx.bundle.error("network", &p.display().to_string(), e),
                }
            }
        }
        _ => {
            ctx.command("network", "network/netstat_anv_tcp.txt", "netstat", &["-anv", "-p", "tcp"])?;
            ctx.command("network", "network/netstat_anv_udp.txt", "netstat", &["-anv", "-p", "udp"])?;
            match cmd::run("lsof", &["-i", "-n", "-P"], t) {
                Ok(out) => {
                    ctx.bundle.add_bytes("network", "network/lsof_i.txt", &out.stdout, Some("lsof -i -n -P"))?;
                    conns = network::parse_lsof(&out.stdout_lossy());
                }
                Err(e) => ctx.bundle.error("network", "lsof -i -n -P", e),
            }
        }
    }
    ctx.bundle.add_json("network", "network/connections.json", &conns)?;
    Ok(())
}

/// Chromium-family and Firefox history databases for every user profile.
fn collect_browsers(ctx: &mut Ctx) -> Result<()> {
    let (chromium, firefox): (Vec<&str>, Vec<&str>) = match std::env::consts::OS {
        "windows" => (
            vec![r"AppData\Local\Google\Chrome\User Data", r"AppData\Local\Microsoft\Edge\User Data", r"AppData\Local\BraveSoftware\Brave-Browser\User Data", r"AppData\Local\Chromium\User Data"],
            vec![r"AppData\Roaming\Mozilla\Firefox\Profiles"],
        ),
        "macos" => (
            vec!["Library/Application Support/Google/Chrome", "Library/Application Support/Microsoft Edge", "Library/Application Support/BraveSoftware/Brave-Browser", "Library/Application Support/Chromium"],
            vec!["Library/Application Support/Firefox/Profiles"],
        ),
        _ => (
            vec![".config/google-chrome", ".config/microsoft-edge", ".config/BraveSoftware/Brave-Browser", ".config/chromium"],
            vec![".mozilla/firefox", "snap/firefox/common/.mozilla/firefox"],
        ),
    };
    let mut found = Vec::new();
    for profile in user_profiles() {
        let user = profile_label(&profile);
        for base in &chromium {
            let dir = profile.join(base);
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            let browser = base.replace(['\\', '/'], "_");
            for e in rd.flatten() {
                let p = e.path();
                if p.join("History").is_file() {
                    let label = format!("browsers/{}/{}/{}", user, browser, profile_label(&p));
                    for f in ["History", "History-journal", "History-wal"] {
                        ctx.copy_if_exists("browsers", &format!("{}/{}", label, f), &p.join(f))?;
                    }
                    found.push(p.display().to_string());
                }
            }
        }
        for base in &firefox {
            let dir = profile.join(base);
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                if p.join("places.sqlite").is_file() {
                    let label = format!("browsers/{}/firefox/{}", user, profile_label(&p));
                    for f in ["places.sqlite", "places.sqlite-wal"] {
                        ctx.copy_if_exists("browsers", &format!("{}/{}", label, f), &p.join(f))?;
                    }
                    found.push(p.display().to_string());
                }
            }
        }
    }
    ctx.bundle.add_json("browsers", "browsers/profiles_found.json", &found)?;
    Ok(())
}
