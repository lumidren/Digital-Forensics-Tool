//! Artifact harvesting: walk every supported file system of an image, match paths against known
//! forensic artifact patterns (case-insensitive globs with `*`, `?`, `**` and `{a,b}`), extract the
//! files below an output directory with escaped, contained paths, and write a sorted
//! `manifest.jsonl`. Unreadable files are logged and skipped.
use crate::error::{FsError, Result};
use crate::image::{self, AnyFs, ImageVolume};
use crate::io::Source;
use serde::Serialize;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

/// Default per-file size cap (4 GiB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 4 << 30;
/// Maximum patterns produced by brace expansion of one pattern.
pub const MAX_BRACE_EXPANSIONS: usize = 4096;
/// Maximum path components considered by the matcher.
pub const MAX_COMPONENTS: usize = 256;
/// Streaming chunk for NTFS extraction.
const CHUNK: u64 = 16 << 20;

/// (kind, pattern) table. Patterns are relative to the file-system root.
pub const PATTERNS: &[(&str, &str)] = &[
    ("evtx", "Windows/System32/winevt/Logs/*.evtx"),
    ("registry", "Windows/System32/config/{SYSTEM,SOFTWARE,SAM,SECURITY,DEFAULT}{,.LOG1,.LOG2}"),
    ("registry", "Users/*/{NTUSER.DAT,NTUSER.DAT.LOG1,NTUSER.DAT.LOG2}"),
    ("registry", "Users/*/AppData/Local/Microsoft/Windows/{UsrClass.dat,UsrClass.dat.LOG1,UsrClass.dat.LOG2}"),
    ("registry", "Windows/AppCompat/Programs/{Amcache.hve,Amcache.hve.LOG1,Amcache.hve.LOG2}"),
    ("prefetch", "Windows/Prefetch/*.pf"),
    ("lnk", "Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk"),
    ("jumplist", "Users/*/AppData/Roaming/Microsoft/Windows/Recent/{AutomaticDestinations,CustomDestinations}/*"),
    ("srum", "Windows/System32/sru/SRUDB.dat"),
    ("tasks", "Windows/System32/Tasks/**"),
    ("tasks", "Windows/Tasks/*.job"),
    ("browser", "Users/*/AppData/Local/{Google/Chrome,Microsoft/Edge,BraveSoftware/Brave-Browser}/User Data/*/{History,Cookies,Web Data,Login Data}"),
    ("browser", "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/{places.sqlite,cookies.sqlite,downloads.sqlite}"),
    ("powershell", "Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"),
    ("recyclebin", "$Recycle.Bin/*/$I*"),
    ("wmi", "Windows/System32/wbem/Repository/OBJECTS.DATA"),
    ("timeline", "Users/*/AppData/Local/ConnectedDevicesPlatform/*/ActivitiesCache.db"),
    // Windows XP / Server 2003 layouts (Documents and Settings, legacy EVT logs, IE5 index.dat).
    ("evt", "Windows/System32/config/{AppEvent.Evt,SecEvent.Evt,SysEvent.Evt,Internet.evt,*.evt}"),
    ("registry", "Documents and Settings/*/{NTUSER.DAT,ntuser.dat.LOG}"),
    ("registry", "Documents and Settings/*/Local Settings/Application Data/Microsoft/Windows/{UsrClass.dat,UsrClass.dat.LOG}"),
    ("lnk", "Documents and Settings/*/Recent/*.lnk"),
    ("lnk", "Documents and Settings/*/{Desktop,Start Menu/Programs/Startup}/*.lnk"),
    ("browser", "Documents and Settings/*/Local Settings/History/History.IE5/index.dat"),
    ("browser", "Documents and Settings/*/Local Settings/History/History.IE5/*/index.dat"),
    ("browser", "Documents and Settings/*/Local Settings/Temporary Internet Files/Content.IE5/index.dat"),
    ("browser", "Documents and Settings/*/Cookies/index.dat"),
    ("browser", "Documents and Settings/*/Application Data/Mozilla/Firefox/Profiles/*/{places.sqlite,cookies.sqlite,downloads.sqlite,history.dat}"),
    ("browser", "Documents and Settings/*/Local Settings/Application Data/Google/Chrome/User Data/*/{History,Cookies,Web Data}"),
    ("recyclebin", "RECYCLER/*/INFO2"),
    ("email", "Documents and Settings/*/Local Settings/Application Data/Microsoft/Outlook/*.{pst,ost}"),
    ("email", "Documents and Settings/*/Application Data/Thunderbird/Profiles/*/Mail/**/Inbox"),
    ("restore", "System Volume Information/_restore*/RP*/snapshot/_REGISTRY_*"),
    ("ntfs_meta", "{$MFT,$LogFile}"),
    ("ntfs_meta", "$Extend/$UsnJrnl:$J"),
    ("linux", "var/log/{auth.log*,secure*,syslog*,messages*,dpkg.log*,apt/history.log*,audit/audit.log*}"),
    ("linux", "var/log/journal/**/*.journal"),
    ("linux", "etc/{crontab,cron.d/*,passwd,shadow,group,ssh/sshd_config}"),
    ("linux", "etc/systemd/system/**/*.service"),
    ("linux", "home/*/.{bash_history,zsh_history}"),
    ("linux", "root/.bash_history"),
    ("linux", "home/*/.ssh/{authorized_keys,known_hosts}"),
    ("linux", "var/spool/cron/**"),
    ("linux", "var/log/{wtmp,btmp,lastlog}"),
    ("linux", "var/run/utmp"),
    ("macos", "private/var/db/diagnostics/**"),
    ("macos", ".fseventsd/*"),
    ("macos", "Library/Launch{Agents,Daemons}/*.plist"),
    ("macos", "Users/*/Library/LaunchAgents/*.plist"),
    ("macos", "Users/*/Library/Application Support/Knowledge/knowledgeC.db"),
    ("macos", "private/var/db/CoreDuet/Knowledge/knowledgeC.db"),
    ("macos", "Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"),
    ("macos", "Library/Application Support/com.apple.TCC/TCC.db"),
    ("macos", "Users/*/.zsh_history"),
];

/// Expand `{a,b}` alternatives (nested braces supported).
pub fn expand_braces(p: &str) -> Vec<String> {
    let mut out = Vec::new();
    expand_into(p, &mut out);
    out
}

fn expand_into(p: &str, out: &mut Vec<String>) {
    if out.len() >= MAX_BRACE_EXPANSIONS {
        return;
    }
    let b = p.as_bytes();
    let Some(open) = p.find('{') else {
        out.push(p.to_string());
        return;
    };
    let mut depth = 0usize;
    let mut close = None;
    let mut commas = Vec::new();
    for (i, &c) in b.iter().enumerate().skip(open) {
        match c {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            b',' if depth == 1 => commas.push(i),
            _ => {}
        }
    }
    let Some(close) = close else {
        out.push(p.to_string());
        return;
    };
    let (pre, post) = (&p[..open], &p[close + 1..]);
    let mut start = open + 1;
    let mut alts = Vec::new();
    for c in commas.into_iter().chain(std::iter::once(close)) {
        alts.push(&p[start..c]);
        start = c + 1;
    }
    for a in alts {
        expand_into(&format!("{pre}{a}{post}"), out);
    }
}

/// Case-insensitive glob match of one path component (`*`, `?`).
pub fn glob_component(pat: &str, name: &str) -> bool {
    let p: Vec<char> = pat.to_lowercase().chars().collect();
    let n: Vec<char> = name.to_lowercase().chars().collect();
    let (mut pi, mut ni) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Match component lists, `**` matching zero or more components.
pub fn match_components(pat: &[&str], path: &[&str]) -> bool {
    // Iterative DP over (pattern index, path index); sizes are bounded by MAX_COMPONENTS.
    let (pl, nl) = (pat.len(), path.len());
    if pl > MAX_COMPONENTS || nl > MAX_COMPONENTS {
        return false;
    }
    let mut dp = vec![vec![false; nl + 1]; pl + 1];
    dp[pl][nl] = true;
    for i in (0..pl).rev() {
        for j in (0..=nl).rev() {
            dp[i][j] = if pat[i] == "**" {
                dp[i + 1][j] || (j < nl && dp[i][j + 1])
            } else {
                j < nl && glob_component(pat[i], path[j]) && dp[i + 1][j + 1]
            };
        }
    }
    dp[0][0]
}

/// Pre-expanded pattern table.
pub struct Matcher {
    rules: Vec<(&'static str, Vec<String>)>,
}

impl Default for Matcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Matcher {
    pub fn new() -> Self {
        let mut rules = Vec::new();
        for (kind, p) in PATTERNS {
            for e in expand_braces(p) {
                rules.push((*kind, e.split('/').map(|s| s.to_string()).collect()));
            }
        }
        Matcher { rules }
    }

    /// Artifact kind of a file-system path (leading `/` optional), or `None`.
    pub fn classify(&self, path: &str) -> Option<&'static str> {
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        if comps.is_empty() {
            return None;
        }
        self.rules
            .iter()
            .find(|(_, pat)| {
                let p: Vec<&str> = pat.iter().map(|s| s.as_str()).collect();
                match_components(&p, &comps)
            })
            .map(|(k, _)| *k)
    }
}

/// Escape a single path component so it is safe on Windows and POSIX hosts and cannot traverse.
pub fn sanitize_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let bad = (c as u32) < 0x20
            || matches!(
                c,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '%'
            )
            || c as u32 == 0x7F;
        if bad {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        } else {
            out.push(c);
        }
    }
    // Trailing dots and spaces are stripped by Windows; "." / ".." would traverse.
    if out.ends_with('.') || out.ends_with(' ') {
        let c = out.pop().unwrap_or('.');
        out.push_str(if c == '.' { "%2E" } else { "%20" });
    }
    if out.is_empty() {
        out = "%00".into();
    }
    let stem = out.split('.').next().unwrap_or("").to_ascii_uppercase();
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED.contains(&stem.as_str()) {
        out.insert(0, '_');
    }
    out
}

/// Map a file-system path to a contained output path `<out>/<partition>/<escaped components>`.
pub fn output_path(out: &Path, partition: usize, fs_path: &str) -> Result<PathBuf> {
    let mut p = out.join(partition.to_string());
    for c in fs_path.split('/').filter(|c| !c.is_empty()) {
        p.push(sanitize_component(c));
    }
    // Defence in depth: every component must be a normal name below `out`.
    let rel = p
        .strip_prefix(out)
        .map_err(|_| FsError::invalid(0, "output path escapes target"))?;
    if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(FsError::invalid(0, "output path escapes target"));
    }
    Ok(p)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ManifestEntry {
    pub path: String,
    pub partition: usize,
    pub fs_type: String,
    pub size: u64,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mft_entry: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inode: Option<u64>,
    pub kind: String,
    /// Output file relative to the harvest directory (forward slashes).
    pub output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct HarvestError {
    pub partition: usize,
    pub path: String,
    pub error: String,
}

#[derive(Debug, Default, Serialize)]
pub struct HarvestReport {
    pub manifest: Vec<ManifestEntry>,
    pub errors: Vec<HarvestError>,
}

struct Sink {
    file: std::fs::File,
    hasher: veritas_hash::MultiHasher,
    size: u64,
}

impl Sink {
    fn create(p: &Path) -> Result<Self> {
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        Ok(Sink {
            file: std::fs::File::create(p)?,
            hasher: veritas_hash::MultiHasher::new(),
            size: 0,
        })
    }
    fn write(&mut self, b: &[u8]) -> Result<()> {
        self.file.write_all(b)?;
        self.hasher.update(b);
        self.size += b.len() as u64;
        Ok(())
    }
    fn finish(self) -> String {
        self.hasher.finalize().sha256
    }
}

fn unique_target(p: PathBuf, id: u64) -> PathBuf {
    if !p.exists() {
        return p;
    }
    let mut s = p.clone().into_os_string();
    s.push(format!("~{id}"));
    PathBuf::from(s)
}

fn rel_string(out: &Path, p: &Path) -> String {
    p.strip_prefix(out)
        .map(|r| {
            r.components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
        })
        .unwrap_or_default()
}

fn harvest_volume(
    v: &ImageVolume,
    out: &Path,
    max_size: u64,
    m: &Matcher,
    rep: &mut HarvestReport,
) -> Result<()> {
    let fs = AnyFs::open(v)?;
    let fs_type = fs.type_name();
    let entries = fs.entries(false)?;
    let mut jobs: Vec<(String, u64, u64, &'static str)> = Vec::new(); // (path, id, size, kind)
    for e in &entries {
        if e.is_dir {
            continue;
        }
        if let Some(kind) = m.classify(&e.path) {
            jobs.push((e.path.clone(), e.id, e.size, kind));
        }
    }
    if let AnyFs::Ntfs(n) = &fs {
        if let Ok(id) = n.lookup("/$Extend/$UsnJrnl") {
            if let Ok(en) = n.entry(id) {
                if let Some(j) = en.stream("$J") {
                    jobs.push(("/$Extend/$UsnJrnl:$J".into(), id, j.size, "ntfs_meta"));
                }
            }
        }
    }
    jobs.sort();
    for (path, id, size, kind) in jobs {
        let err = |e: String, rep: &mut HarvestReport| {
            rep.errors.push(HarvestError {
                partition: v.index,
                path: path.clone(),
                error: e,
            })
        };
        if size > max_size {
            err(format!("size {size} exceeds cap {max_size}"), rep);
            continue;
        }
        let target = match output_path(out, v.index, &path) {
            Ok(t) => unique_target(t, id),
            Err(e) => {
                err(e.to_string(), rep);
                continue;
            }
        };
        let result: Result<(u64, String)> = (|| {
            let mut sink = Sink::create(&target)?;
            match &fs {
                AnyFs::Ntfs(n) => {
                    let (p, stream) = match path.rsplit_once(':') {
                        Some((p, s)) => (p.to_string(), s.to_string()),
                        None => (path.clone(), String::new()),
                    };
                    let e = n.entry(n.lookup(&p).unwrap_or(id))?;
                    let s = e
                        .stream(&stream)
                        .ok_or_else(|| FsError::NotFound(format!("stream '{stream}'")))?
                        .clone();
                    let mut off = 0u64;
                    while off < s.size {
                        let len = CHUNK.min(s.size - off);
                        sink.write(&n.read_stream_at(&s, off, len)?)?;
                        off += len;
                    }
                }
                other => sink.write(&other.read_path(&path)?)?,
            }
            let sz = sink.size;
            Ok((sz, sink.finish()))
        })();
        match result {
            Ok((sz, sha)) => rep.manifest.push(ManifestEntry {
                path: path.clone(),
                partition: v.index,
                fs_type: fs_type.clone(),
                size: sz,
                sha256: sha,
                mft_entry: if matches!(fs, AnyFs::Ntfs(_)) {
                    Some(id)
                } else {
                    None
                },
                inode: if matches!(fs, AnyFs::Ext(_) | AnyFs::Apfs(_)) {
                    Some(id)
                } else {
                    None
                },
                kind: kind.to_string(),
                output: rel_string(out, &target),
            }),
            Err(e) => {
                let _ = std::fs::remove_file(&target);
                err(e.to_string(), rep);
            }
        }
    }
    Ok(())
}

/// Harvest artifacts from every supported volume (or only `partition`) into `out`.
/// Writes `<out>/manifest.jsonl` (sorted by path) and `<out>/harvest_errors.jsonl`.
pub fn harvest(
    src: Source,
    out: &Path,
    partition: Option<usize>,
    max_size: u64,
) -> Result<HarvestReport> {
    std::fs::create_dir_all(out)?;
    let m = Matcher::new();
    let mut rep = HarvestReport::default();
    for v in image::volumes(src)? {
        if partition.is_some_and(|p| p != v.index) || v.fs == image::FsKind::Unknown {
            continue;
        }
        if let Err(e) = harvest_volume(&v, out, max_size, &m, &mut rep) {
            rep.errors.push(HarvestError {
                partition: v.index,
                path: "/".into(),
                error: e.to_string(),
            });
        }
    }
    rep.manifest.sort();
    rep.errors.sort();
    let mut mf = std::fs::File::create(out.join("manifest.jsonl"))?;
    for e in &rep.manifest {
        serde_json::to_writer(&mut mf, e).map_err(|e| FsError::Io(e.to_string()))?;
        mf.write_all(b"\n")?;
    }
    let mut ef = std::fs::File::create(out.join("harvest_errors.jsonl"))?;
    for e in &rep.errors {
        serde_json::to_writer(&mut ef, e).map_err(|e| FsError::Io(e.to_string()))?;
        ef.write_all(b"\n")?;
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brace_expansion() {
        let v = expand_braces("a/{b,c/d}/{x,y}.z");
        assert_eq!(v, vec!["a/b/x.z", "a/b/y.z", "a/c/d/x.z", "a/c/d/y.z"]);
        assert_eq!(
            expand_braces("Library/Launch{Agents,Daemons}/*.plist"),
            vec![
                "Library/LaunchAgents/*.plist",
                "Library/LaunchDaemons/*.plist"
            ]
        );
        assert_eq!(expand_braces("x{,.LOG1}"), vec!["x", "x.LOG1"]);
        assert_eq!(expand_braces("unbalanced{a,b"), vec!["unbalanced{a,b"]);
    }

    #[test]
    fn globbing() {
        assert!(glob_component("*.evtx", "Security.EVTX"));
        assert!(glob_component("$I*", "$IABC123.txt"));
        assert!(!glob_component("*.pf", "x.pfx"));
        assert!(glob_component("auth.log*", "auth.log.2.gz"));
        assert!(match_components(
            &["a", "**", "*.journal"],
            &["a", "b", "c", "x.journal"]
        ));
        assert!(match_components(
            &["a", "**", "*.journal"],
            &["a", "x.journal"]
        ));
        assert!(match_components(&["t", "**"], &["t", "x"]));
        assert!(!match_components(&["a", "*"], &["a", "b", "c"]));
    }

    #[test]
    fn synthetic_layout_classification() {
        let m = Matcher::new();
        let cases: &[(&str, Option<&str>)] = &[
            ("/Windows/System32/winevt/Logs/Security.evtx", Some("evtx")),
            ("/WINDOWS/system32/config/SYSTEM", Some("registry")),
            ("/Windows/System32/config/SOFTWARE.LOG1", Some("registry")),
            ("/Windows/System32/config/SYSTEM.sav", None),
            ("/Users/alice/NTUSER.DAT", Some("registry")),
            ("/Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat", Some("registry")),
            ("/Windows/AppCompat/Programs/Amcache.hve", Some("registry")),
            ("/Windows/Prefetch/CMD.EXE-087B4001.pf", Some("prefetch")),
            ("/Users/bob/AppData/Roaming/Microsoft/Windows/Recent/doc.lnk", Some("lnk")),
            ("/Users/bob/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/5f7b5f1e01b83767.automaticDestinations-ms", Some("jumplist")),
            ("/Users/bob/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/x.customDestinations-ms", Some("jumplist")),
            ("/Windows/System32/sru/SRUDB.dat", Some("srum")),
            ("/Windows/System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag", Some("tasks")),
            ("/Windows/Tasks/At1.job", Some("tasks")),
            ("/Users/bob/AppData/Local/Google/Chrome/User Data/Default/History", Some("browser")),
            ("/Users/bob/AppData/Local/Microsoft/Edge/User Data/Profile 1/Login Data", Some("browser")),
            ("/Users/bob/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Web Data", Some("browser")),
            ("/Users/bob/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default/places.sqlite", Some("browser")),
            ("/Users/bob/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt", Some("powershell")),
            ("/$Recycle.Bin/S-1-5-21-1-2-3-1001/$IABCDEF.docx", Some("recyclebin")),
            ("/$Recycle.Bin/S-1-5-21-1-2-3-1001/$RABCDEF.docx", None),
            ("/Windows/System32/wbem/Repository/OBJECTS.DATA", Some("wmi")),
            ("/Users/bob/AppData/Local/ConnectedDevicesPlatform/L.bob/ActivitiesCache.db", Some("timeline")),
            ("/$MFT", Some("ntfs_meta")),
            ("/$LogFile", Some("ntfs_meta")),
            ("/$Extend/$UsnJrnl:$J", Some("ntfs_meta")),
            ("/var/log/auth.log.1", Some("linux")),
            ("/var/log/apt/history.log", Some("linux")),
            ("/var/log/audit/audit.log", Some("linux")),
            ("/var/log/journal/0123abcd/system.journal", Some("linux")),
            ("/etc/cron.d/backup", Some("linux")),
            ("/etc/ssh/sshd_config", Some("linux")),
            ("/etc/systemd/system/multi-user.target.wants/evil.service", Some("linux")),
            ("/home/eve/.bash_history", Some("linux")),
            ("/home/eve/.ssh/authorized_keys", Some("linux")),
            ("/root/.bash_history", Some("linux")),
            ("/var/spool/cron/crontabs/root", Some("linux")),
            ("/var/log/wtmp", Some("linux")),
            ("/var/run/utmp", Some("linux")),
            ("/private/var/db/diagnostics/Persist/0000000000000001.tracev3", Some("macos")),
            ("/.fseventsd/000000001714941a", Some("macos")),
            ("/Library/LaunchDaemons/com.evil.plist", Some("macos")),
            ("/Users/mac/Library/LaunchAgents/com.x.plist", Some("macos")),
            ("/Users/mac/Library/Application Support/Knowledge/knowledgeC.db", Some("macos")),
            ("/Library/Application Support/com.apple.TCC/TCC.db", Some("macos")),
            ("/Users/mac/.zsh_history", Some("macos")),
            ("/passwords.txt", None),
            ("/a_directory/a_file", None),
        ];
        for (p, want) in cases {
            assert_eq!(m.classify(p), *want, "{p}");
        }
    }

    #[test]
    fn sanitizing_never_escapes() {
        assert_eq!(sanitize_component("$UsnJrnl:$J"), "$UsnJrnl%3A$J");
        assert_eq!(sanitize_component(".."), ".%2E");
        assert_eq!(sanitize_component("."), "%2E");
        assert_eq!(sanitize_component("a/b\\c"), "a%2Fb%5Cc");
        assert_eq!(sanitize_component("CON"), "_CON");
        assert_eq!(sanitize_component("nul.txt"), "_nul.txt");
        let out = Path::new("out");
        for evil in [
            "../../etc/passwd",
            "/..",
            "a/../../b",
            "C:\\Windows",
            "..\\..\\x",
        ] {
            let p = output_path(out, 0, evil).unwrap();
            assert!(p.starts_with(out.join("0")), "{evil} -> {p:?}");
            assert!(
                p.components().all(|c| matches!(c, Component::Normal(_))),
                "{evil} -> {p:?}"
            );
        }
    }
}

#[cfg(test)]
mod xp_layout_tests {
    use super::*;

    #[test]
    fn windows_xp_paths_are_harvested() {
        let m = Matcher::new();
        let cases: &[(&str, Option<&str>)] = &[
            ("/WINDOWS/system32/config/SecEvent.Evt", Some("evt")),
            ("/WINDOWS/system32/config/AppEvent.Evt", Some("evt")),
            ("/Documents and Settings/Mr. Evil/NTUSER.DAT", Some("registry")),
            ("/Documents and Settings/Mr. Evil/Local Settings/Application Data/Microsoft/Windows/UsrClass.dat", Some("registry")),
            ("/Documents and Settings/Mr. Evil/Recent/interception.lnk", Some("lnk")),
            ("/Documents and Settings/Mr. Evil/Local Settings/History/History.IE5/index.dat", Some("browser")),
            ("/Documents and Settings/Mr. Evil/Local Settings/History/History.IE5/MSHist012004082020040821/index.dat", Some("browser")),
            ("/Documents and Settings/Mr. Evil/Cookies/index.dat", Some("browser")),
            ("/RECYCLER/S-1-5-21-2000478354-688789844-1708537768-1003/INFO2", Some("recyclebin")),
            ("/System Volume Information/_restore{5D3F13BE}/RP2/snapshot/_REGISTRY_MACHINE_SOFTWARE", Some("restore")),
            ("/Documents and Settings/Mr. Evil/My Documents/notes.txt", None),
        ];
        for (p, want) in cases {
            assert_eq!(m.classify(p), *want, "{p}");
        }
    }
}
