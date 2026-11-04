//! Autostart locations (`windows:registry:run`).
//!
//! One event per autostart key that holds at least one non-empty entry, timestamped with the
//! key's last-written time; for per-subkey locations (Image File Execution Options Debugger,
//! Active Setup StubPath, Winlogon Notify) one event per subkey. `attrs.location` names the
//! autostart category.
use super::{current_control_set, join, Ctx, HiveKind};
use crate::regf::{Hive, Key};
use serde_json::json;
use veritas_timeline::{desc, Event};

#[derive(Debug, Clone, Copy)]
enum Mode {
    Values(&'static [&'static str]),
    SubkeyValues(&'static [&'static str]),
}

struct Loc {
    kind: HiveKind,
    /// `{CCS}` is replaced by the current control set.
    path: &'static str,
    location: &'static str,
    mode: Mode,
}

const RUN_KEYS: &[&str] = &[
    "Run",
    "RunOnce",
    "RunOnceEx",
    "RunServices",
    "RunServicesOnce",
    "Policies\\Explorer\\Run",
];

const LOCS: &[Loc] = &[
    Loc {
        kind: HiveKind::Software,
        path: "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        location: "Winlogon",
        mode: Mode::Values(&[
            "Shell", "Userinit", "Taskman", "AppSetup", "GinaDLL", "System",
        ]),
    },
    Loc {
        kind: HiveKind::Software,
        path: "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        location: "Winlogon",
        mode: Mode::Values(&["Shell", "Userinit"]),
    },
    Loc {
        kind: HiveKind::Software,
        path: "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify",
        location: "Winlogon Notify",
        mode: Mode::SubkeyValues(&["DllName"]),
    },
    Loc {
        kind: HiveKind::Software,
        path: "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        location: "Image File Execution Options",
        mode: Mode::SubkeyValues(&["Debugger"]),
    },
    Loc {
        kind: HiveKind::Software,
        path: "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        location: "Image File Execution Options",
        mode: Mode::SubkeyValues(&["Debugger"]),
    },
    Loc {
        kind: HiveKind::Software,
        path: "Microsoft\\Windows NT\\CurrentVersion\\Windows",
        location: "AppInit_DLLs",
        mode: Mode::Values(&["AppInit_DLLs"]),
    },
    Loc {
        kind: HiveKind::Software,
        path: "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        location: "AppInit_DLLs",
        mode: Mode::Values(&["AppInit_DLLs"]),
    },
    Loc {
        kind: HiveKind::Software,
        path: "Microsoft\\Active Setup\\Installed Components",
        location: "Active Setup",
        mode: Mode::SubkeyValues(&["StubPath"]),
    },
    Loc {
        kind: HiveKind::Software,
        path: "Wow6432Node\\Microsoft\\Active Setup\\Installed Components",
        location: "Active Setup",
        mode: Mode::SubkeyValues(&["StubPath"]),
    },
    Loc {
        kind: HiveKind::Software,
        path: "Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        location: "Startup folder",
        mode: Mode::Values(&["Common Startup"]),
    },
    Loc {
        kind: HiveKind::Software,
        path: "Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
        location: "Startup folder",
        mode: Mode::Values(&["Common Startup"]),
    },
    Loc {
        kind: HiveKind::Software,
        path: "Policies\\Microsoft\\Windows NT\\Terminal Services",
        location: "Terminal Server InitialProgram",
        mode: Mode::Values(&["InitialProgram"]),
    },
    Loc {
        kind: HiveKind::NtUser,
        path: "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        location: "Windows Load/Run",
        mode: Mode::Values(&["Load", "Run"]),
    },
    Loc {
        kind: HiveKind::NtUser,
        path: "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        location: "Winlogon",
        mode: Mode::Values(&["Shell"]),
    },
    Loc {
        kind: HiveKind::NtUser,
        path: "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        location: "Startup folder",
        mode: Mode::Values(&["Startup"]),
    },
    Loc {
        kind: HiveKind::NtUser,
        path: "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
        location: "Startup folder",
        mode: Mode::Values(&["Startup"]),
    },
    Loc {
        kind: HiveKind::NtUser,
        path: "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services",
        location: "Terminal Server InitialProgram",
        mode: Mode::Values(&["InitialProgram"]),
    },
    Loc {
        kind: HiveKind::System,
        path: "{CCS}\\Control\\Session Manager",
        location: "BootExecute",
        mode: Mode::Values(&["BootExecute", "SetupExecute", "Execute", "S0InitialCommand"]),
    },
    Loc {
        kind: HiveKind::System,
        path: "{CCS}\\Control\\Lsa",
        location: "LSA packages",
        mode: Mode::Values(&[
            "Authentication Packages",
            "Notification Packages",
            "Security Packages",
        ]),
    },
    Loc {
        kind: HiveKind::System,
        path: "{CCS}\\Control\\Lsa\\OSConfig",
        location: "LSA packages",
        mode: Mode::Values(&["Security Packages"]),
    },
    Loc {
        kind: HiveKind::System,
        path: "{CCS}\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
        location: "Terminal Server InitialProgram",
        mode: Mode::Values(&["InitialProgram"]),
    },
    Loc {
        kind: HiveKind::System,
        path: "{CCS}\\Control\\Terminal Server\\Wds\\rdpwd",
        location: "Terminal Server StartupPrograms",
        mode: Mode::Values(&["StartupPrograms"]),
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutorunKey {
    pub location: String,
    pub key_rel_path: String,
    pub key_offset: u32,
    pub last_written_ns: Option<i64>,
    /// (value name, data), in on-disk value order.
    pub entries: Vec<(String, String)>,
}

fn collect(k: &Key<'_>, rel: &str, location: &str, names: Option<&[&str]>) -> Option<AutorunKey> {
    let mut entries = Vec::new();
    for v in k.values() {
        if let Some(ns) = names {
            if !ns.iter().any(|n| n.eq_ignore_ascii_case(&v.name)) {
                continue;
            }
        }
        let data = v.as_multi().join(" ");
        let data = if data.is_empty() {
            v.as_string().unwrap_or_default()
        } else {
            data
        };
        if data.trim().is_empty() {
            continue;
        }
        entries.push((
            if v.name.is_empty() {
                "(default)".to_string()
            } else {
                v.name.clone()
            },
            data,
        ));
    }
    if entries.is_empty() {
        return None;
    }
    Some(AutorunKey {
        location: location.to_string(),
        key_rel_path: rel.to_string(),
        key_offset: k.offset,
        last_written_ns: k.last_written_ns,
        entries,
    })
}

pub fn autorun_keys(hive: &Hive, kind: HiveKind) -> Vec<AutorunKey> {
    let mut out = Vec::new();
    let ccs = current_control_set(hive).unwrap_or_else(|| "ControlSet001".into());
    // Run keys.
    let prefixes: &[&str] = match kind {
        HiveKind::Software => &[
            "Microsoft\\Windows\\CurrentVersion",
            "Wow6432Node\\Microsoft\\Windows\\CurrentVersion",
        ],
        HiveKind::NtUser => &[
            "Software\\Microsoft\\Windows\\CurrentVersion",
            "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion",
        ],
        _ => &[],
    };
    for p in prefixes {
        for r in RUN_KEYS {
            let rel = format!("{p}\\{r}");
            if let Some(k) = hive.key(&rel) {
                out.extend(collect(&k, &rel, r, None));
                if *r == "RunOnceEx" {
                    for s in k.subkeys() {
                        out.extend(collect(&s, &join(&rel, &s.name), r, None));
                    }
                }
            }
        }
    }
    for loc in LOCS.iter().filter(|l| l.kind == kind) {
        let rel = loc.path.replace("{CCS}", &ccs);
        let Some(k) = hive.key(&rel) else { continue };
        match loc.mode {
            Mode::Values(names) => out.extend(collect(&k, &rel, loc.location, Some(names))),
            Mode::SubkeyValues(names) => {
                for s in k.subkeys() {
                    out.extend(collect(&s, &join(&rel, &s.name), loc.location, Some(names)));
                }
            }
        }
    }
    out
}

pub fn events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    autorun_keys(hive, ctx.kind)
        .into_iter()
        .map(|a| {
            let parts: Vec<String> = a.entries.iter().map(|(n, d)| format!("{n}: {d}")).collect();
            let entries: Vec<serde_json::Value> = a
                .entries
                .iter()
                .map(|(n, d)| json!({"name": n, "data": d}))
                .collect();
            ctx.event(
                "run",
                "windows:registry:run",
                desc::WRITTEN,
                a.last_written_ns,
                format!("[{}] {}", ctx.full_path(&a.key_rel_path), parts.join(" ")),
                &a.key_rel_path,
                a.key_offset,
            )
            .attr("location", a.location)
            .attr("entries", serde_json::Value::Array(entries))
        })
        .collect()
}
